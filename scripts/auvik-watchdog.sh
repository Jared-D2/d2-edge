#!/usr/bin/env bash
# Auvik watchdog — detects the tenant-secret corruption signature and
# triggers auvik-recover.sh. Rate-limited so a recovery that doesn't
# actually fix the problem (e.g. cloud-side issue) doesn't loop.
#
# Detection is by log pattern only. The container's healthcheck
# (pgrep -f /usr/share/agent) only sees the parent process, which can
# stay "running healthy" while internal actors (ConnectionMonitor etc.)
# die with StorageException — so we cannot trust Docker's health state
# as a fast-path filter. The grep over a 10-min log window is cheap.
set -euo pipefail

AUVIK_DIR=/opt/d2-edge/auvik
MARKER="$AUVIK_DIR/.last-recovery"
RECOVER=/opt/d2-edge/scripts/auvik-recover.sh
LOG_TAG=auvik-watchdog
RATE_LIMIT_SECONDS=3600
ERROR_PATTERN='StorageException: No value for com\.auvik\.npl\.agent\.tenantInfo\..*\.secret'

log() { logger -t "$LOG_TAG" -- "$*"; }

if ! docker inspect auvik >/dev/null 2>&1; then
  exit 0
fi

if ! docker logs --since 10m auvik 2>&1 | grep -Eq "$ERROR_PATTERN"; then
  exit 0
fi

if [[ -f "$MARKER" ]]; then
  LAST=$(cat "$MARKER" 2>/dev/null || echo 0)
  NOW=$(date -u +%s)
  AGE=$((NOW - LAST))
  if (( AGE < RATE_LIMIT_SECONDS )); then
    log "Corruption signature seen, but last recovery was ${AGE}s ago (< ${RATE_LIMIT_SECONDS}s); skipping"
    exit 0
  fi
fi

STATUS=$(docker inspect auvik --format '{{.State.Status}}' 2>/dev/null || echo unknown)
HEALTH=$(docker inspect auvik --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' 2>/dev/null || echo unknown)
RESTART_COUNT=$(docker inspect auvik --format '{{.RestartCount}}' 2>/dev/null || echo 0)

log "Detected Auvik tenant-secret corruption (status=$STATUS health=$HEALTH restarts=$RESTART_COUNT); triggering recovery"
exec "$RECOVER"
