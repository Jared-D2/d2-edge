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
# Heal ownership: earlier deploys (or manual root-level edits) can leave
# files owned by root, which makes `sudo -u admin git pull` fail on
# unlink. Idempotent — running on an already-correct tree is a no-op.
chown -R admin:admin "$EDGE_DIR"
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
docker compose up -d --force-recreate
echo "  OK"

echo
echo "========================================"
echo " Update complete"
echo "========================================"
