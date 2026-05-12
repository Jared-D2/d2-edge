#!/usr/bin/env bash
# Auvik collector recovery — backs up and clears the persistent tenant-secret
# state so the collector re-registers with the Auvik cloud on next start.
#
# Trigger condition (see auvik-watchdog.sh): StorageException: No value for
# com.auvik.npl.agent.tenantInfo.<prefix>.secret. The locally-stored secret
# has been wiped/corrupted; re-registration is the documented fix.
set -euo pipefail

AUVIK_DIR=/opt/d2-edge/auvik
LOG_TAG=auvik-recover
STAMP=$(date -u +%Y%m%d-%H%M%S)

log() { logger -t "$LOG_TAG" -- "$*"; echo "[$(date -u +%FT%TZ)] $*"; }

if ! docker inspect auvik >/dev/null 2>&1; then
  log "auvik container not present; nothing to do"
  exit 0
fi

if [[ ! -d "$AUVIK_DIR" ]]; then
  log "No $AUVIK_DIR; nothing to recover"
  exit 0
fi

BACKUP="$AUVIK_DIR/backup-$STAMP"
log "Stopping auvik container"
docker stop auvik >/dev/null

log "Backing up etc + config to $BACKUP"
mkdir -p "$BACKUP"
[[ -d "$AUVIK_DIR/etc" ]] && cp -a "$AUVIK_DIR/etc" "$BACKUP/" || true
[[ -d "$AUVIK_DIR/config" ]] && cp -a "$AUVIK_DIR/config" "$BACKUP/" || true

log "Clearing $AUVIK_DIR/etc and $AUVIK_DIR/config"
if [[ -d "$AUVIK_DIR/etc" ]]; then
  find "$AUVIK_DIR/etc" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
fi
if [[ -d "$AUVIK_DIR/config" ]]; then
  find "$AUVIK_DIR/config" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
fi

log "Starting auvik container"
docker start auvik >/dev/null

date -u +%s > "$AUVIK_DIR/.last-recovery"
log "Recovery complete; cloud re-registration in progress (~30s)"
