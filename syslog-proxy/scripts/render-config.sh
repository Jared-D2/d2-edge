#!/usr/bin/env bash
set -euo pipefail

source /opt/d2-edge/.env

TAILSCALE_IP=$(docker exec tailscale tailscale ip -4 2>/dev/null | head -1)
if [[ -z "$TAILSCALE_IP" ]]; then
    echo "[syslog] ERROR: Could not get Tailscale IP"
    exit 1
fi
echo "[syslog] Tailscale IP: $TAILSCALE_IP"

PROXY_ID="syslog-proxy-${TENANT_ID}-${EDGE_SITE_ID}"

sed \
  -e "s|__TENANT_ID__|${TENANT_ID}|g" \
  -e "s|__TENANT_NAME__|${TENANT_NAME}|g" \
  -e "s|__SITE_ID__|${EDGE_SITE_ID}|g" \
  -e "s|__PROXY_ID__|${PROXY_ID}|g" \
  -e "s|__ENVIRONMENT__|${ENVIRONMENT}|g" \
  -e "s|__GRAYLOG_HOST__|${GRAYLOG_HOST}|g" \
  -e "s|__GRAYLOG_PORT__|${GRAYLOG_PORT}|g" \
  -e "s|__TAILSCALE_IP__|${TAILSCALE_IP}|g" \
  /opt/d2-edge/syslog-proxy/config/syslog-ng.conf.template \
  > /opt/d2-edge/syslog-proxy/config/syslog-ng.conf

echo "[syslog] Config rendered OK"
