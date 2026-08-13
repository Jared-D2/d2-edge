#!/usr/bin/env bash
# Back up and clear the Auvik collector's persisted tenant state. Single
# source of truth for "safely reset auvik identity". Used by auvik-recover.sh
# (watchdog) and auvik-ensure-tenant.sh (deploy guard). Does NOT start the
# container -- the caller decides.
#
# Env: AUVIK_DIR (default /opt/d2-edge/auvik), CONTAINER (default auvik),
#      LOG_TAG (default auvik-state-reset). Arg 1: reason (logged).
set -euo pipefail

AUVIK_DIR="${AUVIK_DIR:-/opt/d2-edge/auvik}"
CONTAINER="${CONTAINER:-auvik}"
LOG_TAG="${LOG_TAG:-auvik-state-reset}"
REASON="${1:-unspecified}"

log(){ logger -t "$LOG_TAG" -- "$*" 2>/dev/null || true; echo "[$(date -u +%FT%TZ)] $*"; }

if [[ ! -d "$AUVIK_DIR" ]]; then log "No $AUVIK_DIR; nothing to reset"; exit 0; fi

if docker inspect "$CONTAINER" >/dev/null 2>&1; then
  if [[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" == "true" ]]; then
    log "Stopping $CONTAINER ($REASON)"; docker stop "$CONTAINER" >/dev/null
  fi
else
  log "Container $CONTAINER not present; skipping stop"
fi

STAMP="$(date -u +%Y%m%d-%H%M%S)"
BACKUP="$AUVIK_DIR/backup-$STAMP"
log "Backing up etc + config to $BACKUP ($REASON)"
mkdir -p "$BACKUP"
[[ -d "$AUVIK_DIR/etc" ]]    && cp -a "$AUVIK_DIR/etc" "$BACKUP/"    || true
[[ -d "$AUVIK_DIR/config" ]] && cp -a "$AUVIK_DIR/config" "$BACKUP/" || true

log "Clearing $AUVIK_DIR/etc and $AUVIK_DIR/config (keeping .gitkeep)"
for d in etc config; do
  if [[ -d "$AUVIK_DIR/$d" ]]; then
    find "$AUVIK_DIR/$d" -mindepth 1 -maxdepth 1 ! -name .gitkeep -exec rm -rf {} +
  fi
done
log "Reset complete"
