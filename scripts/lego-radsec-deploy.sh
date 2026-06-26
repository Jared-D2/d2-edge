#!/bin/bash
# lego --run-hook/--renew-hook: deploy the issued/renewed RadSec cert, re-render
# (so the cert-gated :2083 listener appears on first issuance) and recreate.
set -euo pipefail
DST=/opt/d2-edge/freeradius-proxy/certs
install -m 0644 "$LEGO_CERT_PATH"     "$DST/radsec.crt"
install -m 0640 "$LEGO_CERT_KEY_PATH" "$DST/radsec.key"
bash /opt/d2-edge/render-configs.sh >/dev/null 2>&1 || true
docker compose -f /opt/d2-edge/docker-compose.yml up -d --force-recreate freeradius-proxy
logger -t lego-radsec-deploy "deployed $(basename "$LEGO_CERT_PATH"); re-rendered + recreated freeradius-proxy"
