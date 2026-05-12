#!/usr/bin/env bash
# Installs the Auvik watchdog systemd timer on this Pi. Idempotent.
set -euo pipefail

SCRIPTS_DIR=/opt/d2-edge/scripts
UNIT_DIR=/etc/systemd/system

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)" >&2
  exit 1
fi

for f in auvik-watchdog.service auvik-watchdog.timer; do
  install -m 0644 "$SCRIPTS_DIR/$f" "$UNIT_DIR/$f"
done

chmod 0755 "$SCRIPTS_DIR/auvik-watchdog.sh" "$SCRIPTS_DIR/auvik-recover.sh"

systemctl daemon-reload
systemctl enable --now auvik-watchdog.timer

echo "Installed. Current schedule:"
systemctl list-timers auvik-watchdog.timer --no-pager
