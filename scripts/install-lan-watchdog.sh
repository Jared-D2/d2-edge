#!/usr/bin/env bash
# Installs (or, with DEPLOY_LAN_WATCHDOG=disabled, removes) the LAN path
# watchdog systemd timer on this Pi. Idempotent. See scripts/lan-watchdog.sh
# for the trigger/backoff contract.
set -euo pipefail

EDGE_DIR=${EDGE_DIR:-/opt/d2-edge}
SCRIPTS_DIR="$EDGE_DIR/scripts"
UNIT_DIR=/etc/systemd/system
PERSIST_DIR=/var/lib/d2-lan-watchdog

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)" >&2
  exit 1
fi

# shellcheck source=../shared/scripts/lib/envfile.sh
source "$EDGE_DIR/shared/scripts/lib/envfile.sh"

if [[ "$(deploy_flag DEPLOY_LAN_WATCHDOG enabled)" != "enabled" ]]; then
  if systemctl is-enabled --quiet lan-watchdog.timer 2>/dev/null; then
    systemctl disable --now lan-watchdog.timer
    echo "  lan-watchdog disabled (DEPLOY_LAN_WATCHDOG)"
  fi
  exit 0
fi

changed=0
for f in lan-watchdog.service lan-watchdog.timer; do
  if [[ ! -f "$UNIT_DIR/$f" ]] || ! cmp -s "$SCRIPTS_DIR/$f" "$UNIT_DIR/$f"; then
    install -m 0644 "$SCRIPTS_DIR/$f" "$UNIT_DIR/$f"
    changed=1
  fi
done
chmod 0755 "$SCRIPTS_DIR/lan-watchdog.sh"

# Zabbix reads these through the agent's /rootfs mount; seed them so the
# items are supported (and at a known zero) before the watchdog ever acts.
mkdir -p "$PERSIST_DIR/snapshots"
for c in bounce_count reboot_count; do
  [[ -f "$PERSIST_DIR/$c" ]] || echo 0 > "$PERSIST_DIR/$c"
done
chmod 0755 "$PERSIST_DIR"; chmod 0644 "$PERSIST_DIR"/*_count

(( changed )) && systemctl daemon-reload
if ! systemctl is-enabled --quiet lan-watchdog.timer 2>/dev/null || (( changed )); then
  systemctl enable --now lan-watchdog.timer
  echo "  lan-watchdog timer installed/updated"
fi
