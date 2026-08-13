#!/usr/bin/env bash
# Unified config renderer for d2-edge stack.
# Called by deploy-all.sh and update.sh. Supersedes the per-service
# render-config.sh scripts (which had template/placeholder drift and
# silently produced broken configs for syslog-ng + zabbix).
#
# All templates use ${VAR} shell-style placeholders and are rendered
# via envsubst. Each render is followed by a validation step that fails
# loud if any ${...} literals remain in the output.
set -euo pipefail

EDGE_DIR=/opt/d2-edge

# Load .env so envsubst sees every key
set -a
source "${EDGE_DIR}/.env"
set +a

validate_rendered() {
    local file="$1"
    if grep -q '${' "$file"; then
        echo "[ERROR] $file still contains unexpanded ${...} placeholders:"
        grep -n '${' "$file" | head -5
        return 1
    fi
}

# ─── syslog-ng ────────────────────────────────────────────────────────────
# Restrict envsubst to OUR variables so syslog-ng's own ${HOST}, ${MESSAGE},
# ${SOURCEIP}, ${PROGRAM}, ${R_UNIXTIME}, ${YEAR}/${MONTH}/${DAY} macros
# stay intact for syslog-ng to resolve at runtime.
SYSLOG_VARS='$TENANT_ID $TENANT_NAME $EDGE_SITE_ID $ENVIRONMENT $GRAYLOG_HOST'
envsubst "$SYSLOG_VARS"     < "${EDGE_DIR}/syslog-proxy/config/syslog-ng.conf.template"     > "${EDGE_DIR}/syslog-proxy/config/syslog-ng.conf"
# Validate: every ${TENANT_ID}-style placeholder we ship should be gone.
# syslog-ng's own macros like ${HOST} are fine; we check only for our keys.
for v in TENANT_ID TENANT_NAME EDGE_SITE_ID ENVIRONMENT GRAYLOG_HOST; do
    if grep -q "\${$v}" "${EDGE_DIR}/syslog-proxy/config/syslog-ng.conf"; then
        echo "[ERROR] syslog-ng.conf missing substitution for $v"; exit 1
    fi
done
echo "[syslog] rendered OK"

# ─── zabbix-proxy ─────────────────────────────────────────────────────────
envsubst < "${EDGE_DIR}/zabbix-proxy/config/zabbix_proxy.conf.template"     > "${EDGE_DIR}/zabbix-proxy/config/zabbix_proxy.conf"
validate_rendered "${EDGE_DIR}/zabbix-proxy/config/zabbix_proxy.conf" || exit 1
echo "[zabbix] rendered OK"

# ─── netflow-proxy ────────────────────────────────────────────────────────
# Only Pis that act as tenant flow exporters mount nginx.conf into the
# netflow-proxy container, but rendering is cheap and unconditional so the
# template is always kept in sync — the compose profile (DEPLOY_NETFLOW_PROXY)
# decides whether the container actually runs.
envsubst < "${EDGE_DIR}/netflow-proxy/nginx.conf.template"     > "${EDGE_DIR}/netflow-proxy/nginx.conf"
validate_rendered "${EDGE_DIR}/netflow-proxy/nginx.conf" || exit 1
echo "[netflow] rendered OK"

# Build per-subnet client blocks for FreeRADIUS.
# LOCAL_CLIENT_SUBNET can be a single CIDR ("10.0.0.0/8") OR a list
# separated by spaces or commas ("10.0.0.0/8 192.168.1.0/24").
# RadSec client secret is the literal "radsec" per RFC 6614 section 2.3 --
# real TLS clients (AOS-CX radius-server host ... tls) hardcode it and offer
# no way to configure anything else. Confirmed live 2026-07-15 on NCM-BEL-SW06:
# a per-Pi random secret drops every packet with "invalid Message-Authenticator".
# The actual gate for 2083 is TLS itself plus the subnet-scoped client blocks
# below. (RADSEC_CLIENT_SECRET in existing .env files is vestigial/unused.)
SUBNETS="${LOCAL_CLIENT_SUBNET//,/ }"
LOCAL_CLIENTS_UDP_BLOCKS=""
LOCAL_CLIENTS_RADSEC_BLOCKS=""
i=0
for subnet in $SUBNETS; do
    i=$((i+1))
    LOCAL_CLIENTS_UDP_BLOCKS="${LOCAL_CLIENTS_UDP_BLOCKS}
client local-network-${i} {
    ipaddr = ${subnet}
    secret = ${LOCAL_CLIENT_SECRET}
    require_message_authenticator = yes
}
"
    LOCAL_CLIENTS_RADSEC_BLOCKS="${LOCAL_CLIENTS_RADSEC_BLOCKS}
client radsec-local-${i} {
    ipaddr = ${subnet}
    proto = tcp
    secret = radsec
    require_message_authenticator = yes
    limit {
        max_connections = 16
        lifetime = 86400
        idle_timeout = 600
    }
}
"
done
export LOCAL_CLIENTS_UDP_BLOCKS LOCAL_CLIENTS_RADSEC_BLOCKS

# RadSec listener is optional — only include in rendered `default` site if
# all three cert files are present. Without them freeradius would fail
# to start, taking the whole RADIUS stack (incl. plain UDP) down with it.
RADSEC_CERTS_DIR="${EDGE_DIR}/freeradius-proxy/certs"
if [[ -f "$RADSEC_CERTS_DIR/radsec.key" \
   && -f "$RADSEC_CERTS_DIR/radsec.crt" \
   && -f "$RADSEC_CERTS_DIR/ca-bundle.pem" ]]; then
    RADSEC_LISTEN_BLOCK=$(cat "${EDGE_DIR}/freeradius-proxy/config/templates/radsec-listen.template")
    echo "[freeradius] RadSec enabled (certs present)"
else
    RADSEC_LISTEN_BLOCK="    # RadSec disabled (cert files not present in ${RADSEC_CERTS_DIR})"
    echo "[freeradius] RadSec disabled (certs not provisioned) — plain UDP only"
fi
export RADSEC_LISTEN_BLOCK

# ─── freeradius-proxy ─────────────────────────────────────────────────────
FR_TPL="${EDGE_DIR}/freeradius-proxy/config/templates"
FR_OUT="${EDGE_DIR}/freeradius-proxy/config/rendered"
mkdir -p "$FR_OUT"
for f in clients.conf proxy.conf default; do
    src="$FR_TPL/${f}.template"
    # Per-Pi opt-in: send the Pi->central AUTH hop over RadSec (TLS/2083) instead
    # of plain UDP/1812. Gated on a RadSec cert being present (else freeradius
    # fails to start). Acct stays UDP/1813. Set RADSEC_UPSTREAM=true in .env.
    if [[ "$f" == "proxy.conf" && "${RADSEC_UPSTREAM:-false}" == "true" && -f "$RADSEC_CERTS_DIR/radsec.crt" && -f "$RADSEC_CERTS_DIR/radsec.key" && -f "$RADSEC_CERTS_DIR/ca-bundle.pem" ]]; then
        src="$FR_TPL/proxy.conf.radsec.template"
        echo "[freeradius] proxy->central auth: RadSec (RADSEC_UPSTREAM=true)"
    fi
    envsubst < "$src" > "$FR_OUT/$f"
    validate_rendered "$FR_OUT/$f" || exit 1
done
echo "[freeradius] rendered OK"

echo "All configs rendered and validated"

# ─── oob-console (ser2net) ────────────────────────────────────────────────
# Only when the OOB toggle is on AND the operator has written ports.yaml.
# Renders ser2net.yaml (mounted into the container) + slots.rules (udev
# fragment installed by setup-oob.sh on the next update.sh run).
if [[ "${DEPLOY_OOB_CONSOLE:-disabled}" == "enabled" ]]; then
    if [[ -f "${EDGE_DIR}/oob-console/ports.yaml" ]]; then
        python3 "${EDGE_DIR}/oob-console/render-ser2net.py" \
            "${EDGE_DIR}/oob-console/ports.yaml" \
            "${EDGE_DIR}/oob-console/ser2net.yaml" \
            "${EDGE_DIR}/oob-console/slots.rules"
        echo "[oob] rendered OK ($(grep -c '^connection:' "${EDGE_DIR}/oob-console/ser2net.yaml") slots)"
    else
        echo "[ERROR] DEPLOY_OOB_CONSOLE=enabled but oob-console/ports.yaml missing" >&2
        exit 1
    fi
fi
