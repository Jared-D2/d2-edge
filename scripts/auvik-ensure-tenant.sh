#!/usr/bin/env bash
# Tenant-mismatch guard. Run before the auvik container is (re)created. If the
# persisted collector identity belongs to a different tenant than
# AUVIK_DOMAIN_PREFIX, back up + clear it (via the shared helper) so the
# collector registers cleanly into the correct tenant. Strict no-op when
# already correct, empty, or auvik disabled.
#
# Config: AUVIK_DOMAIN_PREFIX / DEPLOY_AUVIK from env, else parsed from
# $ENV_FILE (default /opt/d2-edge/.env). AUVIK_DIR default /opt/d2-edge/auvik.
set -euo pipefail

ENV_FILE="${ENV_FILE:-/opt/d2-edge/.env}"
AUVIK_DIR="${AUVIK_DIR:-/opt/d2-edge/auvik}"
CONTAINER="${CONTAINER:-auvik}"
RESET="${RESET_SCRIPT:-/opt/d2-edge/scripts/auvik-state-reset.sh}"
LOG_TAG=auvik-ensure-tenant

log(){ logger -t "$LOG_TAG" -- "$*" 2>/dev/null || true; echo "[$(date -u +%FT%TZ)] $*"; }

# Read KEY=VALUE from .env WITHOUT sourcing (never execute .env content).
env_get(){
  local key="$1"
  [[ -f "$ENV_FILE" ]] || return 0
  sed -n -E "s/^${key}=([^#]*)\$/\1/p" "$ENV_FILE" | tail -n1 \
    | sed -E "s/[[:space:]]+\$//; s/^\"(.*)\"\$/\1/; s/^'(.*)'\$/\1/"
}

PREFIX="${AUVIK_DOMAIN_PREFIX:-$(env_get AUVIK_DOMAIN_PREFIX)}"
DEPLOY="${DEPLOY_AUVIK:-$(env_get DEPLOY_AUVIK)}"; DEPLOY="${DEPLOY:-enabled}"

if [[ "$DEPLOY" != "enabled" ]]; then log "DEPLOY_AUVIK=$DEPLOY; skipping tenant check"; exit 0; fi
if [[ -z "$PREFIX" ]]; then log "AUVIK_DOMAIN_PREFIX empty; skipping (cannot determine tenant)"; exit 0; fi

ETC="$AUVIK_DIR/etc"
if [[ ! -d "$ETC" ]]; then log "No $ETC; nothing to check (fresh)"; exit 0; fi

shopt -s nullglob
mismatch=0; have=""
for f in "$ETC"/agentId-*; do
  p="$(basename "$f")"; p="${p#agentId-}"
  have="$have $p"
  if [[ "$p" != "$PREFIX" ]]; then mismatch=1; fi
done
shopt -u nullglob

if [[ -z "${have// }" ]]; then log "No persisted agentId; nothing to check (fresh)"; exit 0; fi

if [[ "$mismatch" -eq 1 ]]; then
  log "Tenant prefix mismatch (have:${have}, want: $PREFIX); resetting auvik state"
  AUVIK_DIR="$AUVIK_DIR" CONTAINER="$CONTAINER" LOG_TAG="$LOG_TAG" \
    bash "$RESET" "tenant prefix mismatch (have:${have}, want: $PREFIX)"
  log "Reset done; collector will register into $PREFIX on next start"
else
  log "Persisted tenant matches $PREFIX; no action"
fi
