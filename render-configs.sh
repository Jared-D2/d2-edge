#!/bin/bash
set -euo pipefail

# Source environment (set -a exports all vars so envsubst can see them)
set -a
source /opt/d2-edge/.env
set +a

# Only substitute the variables we control — leave syslog-ng internal macros alone
SYSLOG_VARS='$TENANT_ID $TENANT_NAME $EDGE_SITE_ID $ENVIRONMENT $GRAYLOG_HOST $GRAYLOG_PORT'

# Render syslog-ng config
envsubst "$SYSLOG_VARS" < /opt/d2-edge/syslog-proxy/config/syslog-ng.conf.template > /opt/d2-edge/syslog-proxy/config/syslog-ng.conf

# Render zabbix proxy config
envsubst < /opt/d2-edge/zabbix-proxy/config/zabbix_proxy.conf.template > /opt/d2-edge/zabbix-proxy/config/zabbix_proxy.conf

echo "Configs rendered from templates"
