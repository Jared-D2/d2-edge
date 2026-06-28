#!/bin/bash
# First issuance (lego run). Run by Ansible AFTER the Pi key is registered with
# acme-hook. Idempotent-ish: re-running re-issues; renewal thereafter is the timer.
set -euo pipefail
. /etc/lego/radsec.env
if [ -f "/etc/lego/certificates/${CERT_NAME}.crt" ]; then
  echo "RadSec cert already issued for ${CERT_NAME}; nothing to do."; exit 0
fi
export EXEC_PATH=/usr/local/sbin/lego-dns-exec.sh
exec /usr/bin/lego --server https://ca.internal.d2tech.com.au:9000/acme/acme/directory \
  --email acme@d2tech.com.au --accept-tos --dns exec --dns.disable-cp \
  -d "${CERT_NAME}" --path /etc/lego \
  run --run-hook /usr/local/sbin/lego-radsec-deploy.sh
