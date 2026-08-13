#!/usr/bin/env bash
# Installs the RadSec cert-expiry monitor (script + daily timer). Idempotent.
# No-ops harmlessly on Pis without a RadSec cert (the script exits 0 then).
set -euo pipefail
SCRIPTS_DIR=/opt/d2-edge/scripts
UNIT_DIR=/etc/systemd/system
if [[ $EUID -ne 0 ]]; then echo "Run as root (sudo)" >&2; exit 1; fi
install -m 0755 "$SCRIPTS_DIR/radsec-cert-check" /usr/local/sbin/radsec-cert-check
for f in radsec-cert-check.service radsec-cert-check.timer; do
  install -m 0644 "$SCRIPTS_DIR/$f" "$UNIT_DIR/$f"
done
systemctl daemon-reload
systemctl enable --now radsec-cert-check.timer >/dev/null
echo "radsec-cert-check installed."
