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
