#!/usr/bin/env bash
set -euo pipefail

source /opt/d2-edge/.env

ZABBIX_PROXY_NAME="zbx-${TENANT_ID}-${EDGE_SITE_ID}"
ZABBIX_PROXY_MODE=0

sed \
  -e "s|__ZABBIX_PROXY_MODE__|${ZABBIX_PROXY_MODE}|g" \
  -e "s|__ZABBIX_SERVER_HOST__|${ZABBIX_SERVER_HOST}|g" \
  -e "s|__ZABBIX_SERVER_PORT__|${ZABBIX_SERVER_PORT}|g" \
  -e "s|__ZABBIX_PROXY_NAME__|${ZABBIX_PROXY_NAME}|g" \
  /opt/d2-edge/zabbix-proxy/config/zabbix_proxy.conf.template \
  > /opt/d2-edge/zabbix-proxy/config/zabbix_proxy.conf

echo "[zabbix] Config rendered OK"
