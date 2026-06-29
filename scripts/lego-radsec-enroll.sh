#!/bin/bash
# First issuance (lego run). Run by Ansible AFTER the Pi key is registered with
# acme-hook. Idempotent-ish: re-running re-issues; renewal thereafter is the timer.
set -euo pipefail
. /etc/lego/radsec.env
DST=/opt/d2-edge/freeradius-proxy/certs
if [ -f "/etc/lego/certificates/${CERT_NAME}.crt" ]; then
  if [ -f "$DST/ca-bundle.pem" ]; then
    echo "RadSec cert + ca-bundle present for ${CERT_NAME}; nothing to do."; exit 0
  fi
  echo "cert present but ca-bundle.pem missing -- rebuilding + re-rendering..."
  ISSUER="/etc/lego/certificates/${CERT_NAME}.issuer.crt"
  ROOT=/opt/d2-edge/shared/files/d2tech-internal-root.crt
  if [ -f "$ISSUER" ] && [ -f "$ROOT" ]; then
    cat "$ISSUER" "$ROOT" > "$DST/ca-bundle.pem"; chmod 0644 "$DST/ca-bundle.pem"
    bash /opt/d2-edge/render-configs.sh >/dev/null 2>&1 || true
    docker compose -f /opt/d2-edge/docker-compose.yml up -d --force-recreate freeradius-proxy
    echo "ca-bundle rebuilt; RadSec listener should now be up."; exit 0
  fi
  echo "ERROR: cannot rebuild ca-bundle (issuer=$ISSUER root=$ROOT)" >&2; exit 1
fi
export EXEC_PATH=/usr/local/sbin/lego-dns-exec.sh
exec /usr/bin/lego --server https://ca.internal.d2tech.com.au:9000/acme/acme/directory \
  --email acme@d2tech.com.au --accept-tos --dns exec --dns.disable-cp \
  -d "${CERT_NAME}" --path /etc/lego \
  run --run-hook /usr/local/sbin/lego-radsec-deploy.sh
