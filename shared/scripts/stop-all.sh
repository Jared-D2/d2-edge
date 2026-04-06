#!/usr/bin/env bash
set -euo pipefail

EDGE_DIR="/opt/d2-edge"

echo "Stopping all D2 Edge containers..."
cd "$EDGE_DIR"
docker compose down
echo "All containers stopped."
