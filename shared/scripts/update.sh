#!/usr/bin/env bash
set -euo pipefail

EDGE_DIR=/opt/d2-edge

# Docker group GID varies per host install — resolve at deploy time.
export DOCKER_GID=$(getent group docker | cut -d: -f3)
if [[ -z "$DOCKER_GID" ]]; then
    echo "ERROR: host 'docker' group not found." >&2
    exit 1
fi

echo "========================================"
echo " D2 Edge Appliance — Update"
echo "========================================"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash update.sh"
    exit 1
fi

echo
echo "[1/4] Pulling latest from Git..."
cd "$EDGE_DIR"
# Heal ownership on git-tracked paths so `sudo -u admin git pull` can
# unlink/write them. Runtime data dirs (zabbix-proxy/data|logs,
# syslog-proxy/logs|state, auvik/*, d2-agent/buffer) are gitignored and
# owned by container runtime UIDs — DO NOT chown them, or containers lose
# write access (e.g. zabbix UID 1997 can't write admin-owned data).
chown admin:admin "$EDGE_DIR"
chown -R admin:admin "$EDGE_DIR/.git" 2>/dev/null || true
# Only tracked files matter to `git pull`; list them via the index.
sudo -u admin git ls-files -z | xargs -0r -I{} chown admin:admin "$EDGE_DIR/{}"
sudo -u admin git pull
echo "  OK"

echo
echo "[2/4] Re-rendering configs..."
bash "$EDGE_DIR/render-configs.sh"
echo "  OK"

echo
echo "[3/4] Building d2-agent image..."
cd "$EDGE_DIR"
docker compose build d2-agent --pull
echo "  OK"

echo
echo "[4/4] Recreating containers..."
# Legacy .env files on pre-existing fleet Pis may lack COMPOSE_PROFILES.
# Without it, every profile-gated service (syslog/zabbix/freeradius/auvik/
# d2-agent/zabbix-agent2) is skipped by `docker compose up` — they stay on
# their old image/config instead of picking up render-configs.sh output.
export COMPOSE_PROFILES=enabled
docker compose up -d --force-recreate
echo "  OK"

echo
echo "========================================"
echo " Update complete"
echo "========================================"
