#!/usr/bin/env bash
set -euo pipefail

set -a
source /opt/d2-edge/.env
set +a

TEMPLATE_DIR="/opt/d2-edge/freeradius-proxy/config/templates"
OUTPUT_DIR="/opt/d2-edge/freeradius-proxy/config/rendered"
mkdir -p "$OUTPUT_DIR"

envsubst < "$TEMPLATE_DIR/clients.conf.template"        > "$OUTPUT_DIR/clients.conf"
envsubst < "$TEMPLATE_DIR/proxy.conf.template"           > "$OUTPUT_DIR/proxy.conf"
envsubst < "$TEMPLATE_DIR/policy-operator-name.template" > "$OUTPUT_DIR/policy-operator-name"
envsubst < "$TEMPLATE_DIR/default.template"              > "$OUTPUT_DIR/default"

echo "[freeradius] Config rendered OK"
