#!/usr/bin/env bash
# Installs the D2 weekly full-upgrade systemd timer on this Pi. Idempotent.
set -euo pipefail

SCRIPTS_DIR=/opt/d2-edge/scripts
UNIT_DIR=/etc/systemd/system

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)" >&2
  exit 1
fi

for f in weekly-full-upgrade.service weekly-full-upgrade.timer; do
  install -m 0644 "$SCRIPTS_DIR/$f" "$UNIT_DIR/$f"
done

systemctl daemon-reload
systemctl enable --now weekly-full-upgrade.timer

echo "Installed. Current schedule:"
systemctl list-timers weekly-full-upgrade.timer --no-pager
