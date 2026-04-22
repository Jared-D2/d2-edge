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

# Build per-subnet client blocks for FreeRADIUS.
# LOCAL_CLIENT_SUBNET can be a single CIDR ("10.0.0.0/8") OR a list
# separated by spaces or commas ("10.0.0.0/8 192.168.1.0/24").
# RADSEC_CLIENT_SECRET: self-heal on first run. Every Pi previously
# inherited the hardcoded "radsec" literal; auto-generating and
# persisting into .env avoids forcing a manual fleet-wide edit while
# still giving each Pi a unique secret (same pattern bootstrap uses
# for DOCKER_GID). Safe because RadSec is cert-gated and not yet
# deployed anywhere, so rotating the secret doesn't break any
# currently-connected client.
if [[ -z "${RADSEC_CLIENT_SECRET:-}" ]]; then
    RADSEC_CLIENT_SECRET="$(openssl rand -hex 32)"
    export RADSEC_CLIENT_SECRET
    if ! grep -q '^RADSEC_CLIENT_SECRET=' "${EDGE_DIR}/.env"; then
        echo "RADSEC_CLIENT_SECRET=${RADSEC_CLIENT_SECRET}" >> "${EDGE_DIR}/.env"
        echo "[render-configs] Generated RADSEC_CLIENT_SECRET and appended to .env"
    fi
fi
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
    secret = ${RADSEC_CLIENT_SECRET}
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
    envsubst < "$FR_TPL/${f}.template" > "$FR_OUT/$f"
    validate_rendered "$FR_OUT/$f" || exit 1
done
echo "[freeradius] rendered OK"

echo "All configs rendered and validated"
