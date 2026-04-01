#!/usr/bin/env bash
set -euo pipefail

EDGE_DIR="/opt/d2-edge"

echo "========================================"
echo " D2 Edge Appliance — Update"
echo "========================================"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash update.sh"
    exit 1
fi

echo ""
echo "[1/3] Pulling latest from Git..."
cd "$EDGE_DIR"
git pull
echo "  OK"

echo ""
echo "[2/3] Re-rendering configs..."
bash "$EDGE_DIR/syslog-proxy/scripts/render-config.sh"
bash "$EDGE_DIR/zabbix-proxy/scripts/render-config.sh"
bash "$EDGE_DIR/freeradius-proxy/scripts/render-config.sh"
echo "  OK"

echo ""
echo "[3/3] Restarting containers..."
cd "$EDGE_DIR"
docker compose down
docker compose up -d
echo "  OK"

echo ""
echo "========================================"
echo " Update complete"
echo "========================================"
