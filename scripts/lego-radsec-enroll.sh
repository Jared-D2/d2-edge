#!/bin/bash
# Make this Pi a full RadSec consumer: ensure cert + ca-bundle + RADSEC_UPSTREAM
# (Pi->central over RadSec), then render + recreate only if something changed.
# Idempotent. Runs as root via the svc_ansible sudo grant. Requires the Pi key
# already registered with acme-hook.
set -euo pipefail
if [ ! -f /etc/lego/radsec.env ]; then
  echo "ERROR: /etc/lego/radsec.env missing -- scaffolding has not run; run update.sh (install-lego-radsec) on this Pi first." >&2; exit 1
fi
. /etc/lego/radsec.env                     # CERT_NAME
EDGE=/opt/d2-edge
DST="$EDGE/freeradius-proxy/certs"
ENVF="$EDGE/.env"
CERTFILE="/etc/lego/certificates/${CERT_NAME}.crt"
ISSUER="/etc/lego/certificates/${CERT_NAME}.issuer.crt"
ROOT="$EDGE/shared/files/d2tech-internal-root.crt"
changed=0

# 1) ensure the upstream flag (this Pi runs Pi->central over RadSec)
if grep -q '^RADSEC_UPSTREAM=true' "$ENVF"; then :
elif grep -q '^RADSEC_UPSTREAM=' "$ENVF"; then sed -i 's/^RADSEC_UPSTREAM=.*/RADSEC_UPSTREAM=true/' "$ENVF"; changed=1; echo "set RADSEC_UPSTREAM=true"
else printf 'RADSEC_UPSTREAM=true\n' >> "$ENVF"; changed=1; echo "added RADSEC_UPSTREAM=true"; fi

# 2) first issuance if no cert -- the deploy hook renders+recreates with the flag set
if [ ! -f "$CERTFILE" ]; then
  export EXEC_PATH=/usr/local/sbin/lego-dns-exec.sh
  exec /usr/bin/lego --server https://ca.internal.d2tech.com.au:9000/acme/acme/directory \
    --email acme@d2tech.com.au --accept-tos --dns exec --dns.disable-cp \
    -d "${CERT_NAME}" --path /etc/lego run --run-hook /usr/local/sbin/lego-radsec-deploy.sh
fi

# 3) cert exists: ensure ca-bundle (intermediate + root)
if [ ! -f "$DST/ca-bundle.pem" ]; then
  if [ -f "$ISSUER" ] && [ -f "$ROOT" ]; then
    cat "$ISSUER" "$ROOT" > "$DST/ca-bundle.pem"; chmod 0644 "$DST/ca-bundle.pem"; changed=1; echo "rebuilt ca-bundle.pem"
  else echo "ERROR: cannot build ca-bundle (issuer=$ISSUER root=$ROOT)" >&2; exit 1; fi
fi

# 4) render + recreate only if something changed
if [ "$changed" = "1" ]; then
  echo "re-rendering + recreating freeradius-proxy..."
  bash "$EDGE/render-configs.sh" >/dev/null 2>&1 || true
  docker compose -f "$EDGE/docker-compose.yml" up -d --force-recreate freeradius-proxy
  echo "RadSec ensured (cert + ca-bundle + upstream)."
else
  echo "RadSec fully configured for ${CERT_NAME} (cert + ca-bundle + upstream); nothing to do."
fi
