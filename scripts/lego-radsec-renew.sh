#!/bin/bash
# Timer entrypoint: renew the RadSec cert if one exists. No-op (exit 0) on Pis
# not yet enrolled, so the daily timer is silent until the Pi has a cert.
set -uo pipefail
[ -f /etc/lego/radsec.env ] || exit 0
. /etc/lego/radsec.env
[ -n "${CERT_NAME:-}" ] || exit 0
[ -f "/etc/lego/certificates/${CERT_NAME}.crt" ] || exit 0
export EXEC_PATH=/usr/local/sbin/lego-dns-exec.sh
exec /usr/bin/lego --server https://ca.internal.d2tech.com.au:9000/acme/acme/directory \
  --email acme@d2tech.com.au --accept-tos --dns exec --dns.disable-cp \
  -d "${CERT_NAME}" --path /etc/lego \
  renew --days 15 --renew-hook /usr/local/sbin/lego-radsec-deploy.sh
