#!/usr/bin/env bash
# Auvik collector recovery (invoked by auvik-watchdog.sh on the tenant-secret
# corruption signature). Resets persisted state via the shared helper, then
# restarts so the collector re-registers with the cloud.
#
# Env: AUVIK_DIR (default /opt/d2-edge/auvik), CONTAINER (default auvik),
#      RESET_SCRIPT (default /opt/d2-edge/scripts/auvik-state-reset.sh).
set -euo pipefail

AUVIK_DIR="${AUVIK_DIR:-/opt/d2-edge/auvik}"
CONTAINER="${CONTAINER:-auvik}"
RESET="${RESET_SCRIPT:-/opt/d2-edge/scripts/auvik-state-reset.sh}"
LOG_TAG=auvik-recover

log(){ logger -t "$LOG_TAG" -- "$*" 2>/dev/null || true; echo "[$(date -u +%FT%TZ)] $*"; }

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  log "auvik container not present; nothing to do"; exit 0
fi

AUVIK_DIR="$AUVIK_DIR" CONTAINER="$CONTAINER" LOG_TAG="$LOG_TAG" \
  bash "$RESET" "watchdog: tenant-secret corruption"

log "Starting $CONTAINER container"
docker start "$CONTAINER" >/dev/null

date -u +%s > "$AUVIK_DIR/.last-recovery"
log "Recovery complete; cloud re-registration in progress (~30s)"
