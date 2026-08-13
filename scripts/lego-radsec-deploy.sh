#!/bin/bash
# lego --run-hook/--renew-hook: deploy the issued/renewed RadSec cert, re-render
# (so the cert-gated :2083 listener appears on first issuance) and recreate.
set -euo pipefail
DST=/opt/d2-edge/freeradius-proxy/certs
install -m 0644 "$LEGO_CERT_PATH"     "$DST/radsec.crt"
install -m 0640 "$LEGO_CERT_KEY_PATH" "$DST/radsec.key"
# CA bundle (intermediate + root) so RadSec can verify peers (central server
# cert + switch client certs). Without it the :2083 listener AND the RadSec
# home_server cannot load their ca_file and freeradius will not start.
ROOT=/opt/d2-edge/shared/files/d2tech-internal-root.crt
ISSUER="${LEGO_ISSUER_CERT_PATH:-${LEGO_CERT_PATH%.crt}.issuer.crt}"
if [ -f "$ISSUER" ] && [ -f "$ROOT" ]; then
  cat "$ISSUER" "$ROOT" > "$DST/ca-bundle.pem"
  chmod 0644 "$DST/ca-bundle.pem"
else
  echo "WARN: ca-bundle.pem NOT built (issuer=$ISSUER root=$ROOT)" >&2
fi
bash /opt/d2-edge/render-configs.sh >/dev/null 2>&1 || true
docker compose -f /opt/d2-edge/docker-compose.yml up -d --force-recreate freeradius-proxy
logger -t lego-radsec-deploy "deployed $(basename "$LEGO_CERT_PATH"); re-rendered + recreated freeradius-proxy"
