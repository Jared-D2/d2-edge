#!/usr/bin/env bash
# Installs the Tailscale wedge-watchdog systemd timer on this Pi. Idempotent.
set -euo pipefail

SCRIPTS_DIR=/opt/d2-edge/scripts
UNIT_DIR=/etc/systemd/system

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)" >&2
  exit 1
fi

for f in tailscale-watchdog.service tailscale-watchdog.timer; do
  install -m 0644 "$SCRIPTS_DIR/$f" "$UNIT_DIR/$f"
done

chmod 0755 "$SCRIPTS_DIR/tailscale-watchdog.sh"

systemctl daemon-reload
systemctl enable --now tailscale-watchdog.timer
