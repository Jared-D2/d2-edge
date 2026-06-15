#!/usr/bin/env bash
# Sanitize this Pi for golden-image capture: clear all per-instance state so
# clones are generic. DESTRUCTIVE -- requires --confirm. Without it, prints the
# plan and exits 0 (dry run).
set -euo pipefail

EDGE_DIR="${EDGE_DIR:-/opt/d2-edge}"
COMPOSE="$EDGE_DIR/docker-compose.yml"
RESET="$EDGE_DIR/scripts/auvik-state-reset.sh"
STAMP="$(date -u +%Y%m%d-%H%M%S)"

cat <<PLAN
prepare-image.sh will clear the following per-instance state:
  - docker stack: docker compose down
  - auvik/etc, auvik/config (backed up first), auvik/logs
  - Tailscale state: /var/lib/tailscale/*
  - SSH host keys: /etc/ssh/ssh_host_*   (regenerated first boot)
  - machine-id: /etc/machine-id, /var/lib/dbus/machine-id (regenerated first boot)
  - runtime data: zabbix-proxy/{data,logs}, syslog-proxy/{state,logs}, d2-agent/buffer
  - .env -> backed up to .env.preimage-$STAMP, reset to .env.template
PLAN

if [[ "${1:-}" != "--confirm" ]]; then
  echo; echo "DRY RUN. Re-run with --confirm to apply."; exit 0
fi

if [[ $EUID -ne 0 ]]; then echo "Run as root (sudo)" >&2; exit 1; fi

echo "[1/7] docker compose down"
docker compose -f "$COMPOSE" down || true

echo "[2/7] auvik state"
CONTAINER=auvik bash "$RESET" "prepare-image" || true
rm -rf "${EDGE_DIR:?}/auvik/logs/"* 2>/dev/null || true

echo "[3/7] Tailscale state"
rm -rf /var/lib/tailscale/* 2>/dev/null || true

echo "[4/7] SSH host keys + machine-id"
rm -f /etc/ssh/ssh_host_* 2>/dev/null || true
: > /etc/machine-id
rm -f /var/lib/dbus/machine-id 2>/dev/null || true

echo "[5/7] first-boot regen one-shot"
install -m 0644 "$EDGE_DIR/shared/files/d2-firstboot-regen.service" \
  /etc/systemd/system/d2-firstboot-regen.service
systemctl enable d2-firstboot-regen.service >/dev/null 2>&1 || true

echo "[6/7] runtime data dirs"
rm -rf "${EDGE_DIR:?}"/zabbix-proxy/data/* "${EDGE_DIR:?}"/zabbix-proxy/logs/* \
       "${EDGE_DIR:?}"/syslog-proxy/state/* "${EDGE_DIR:?}"/syslog-proxy/logs/* \
       "${EDGE_DIR:?}"/d2-agent/buffer/* 2>/dev/null || true

echo "[7/7] .env"
if [[ -f "$EDGE_DIR/.env" ]]; then
  cp -a "$EDGE_DIR/.env" "$EDGE_DIR/.env.preimage-$STAMP"
  cp -a "$EDGE_DIR/.env.template" "$EDGE_DIR/.env"
  chmod 600 "$EDGE_DIR/.env"
fi

echo "Done. Power off now and capture the image."
