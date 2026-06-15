#!/usr/bin/env bash
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$HERE/auvik-ensure-tenant.sh"
RESET="$HERE/auvik-state-reset.sh"
fails=0
check(){ if [[ "$1" == "$2" ]]; then echo "ok: $3"; else echo "FAIL: $3"; fails=$((fails+1)); fi; }
nbackups(){ ls -d "$TMP"/backup-* 2>/dev/null | wc -l | tr -d " "; }

guard(){ # $1=prefix $2=deploy
  AUVIK_DOMAIN_PREFIX="$1" DEPLOY_AUVIK="$2" AUVIK_DIR="$TMP" \
  CONTAINER="nope-$$-x" RESET_SCRIPT="$RESET" ENV_FILE=/nonexistent LOG_TAG=test \
  bash "$SCRIPT" >/dev/null 2>&1
}

# case 1: mismatch -> cleared + backup
TMP="$(mktemp -d)"; mkdir -p "$TMP/etc" "$TMP/config"
echo u > "$TMP/etc/agentId-d2techhq"; echo c > "$TMP/config/agent.conf"
guard ncm001 enabled
[[ -e "$TMP/etc/agentId-d2techhq" ]]; check "$?" "1" "mismatch: stale identity cleared"
[[ "$(nbackups)" -ge 1 ]];           check "$?" "0" "mismatch: backup made"
rm -rf "$TMP"

# case 2: match -> no-op
TMP="$(mktemp -d)"; mkdir -p "$TMP/etc" "$TMP/config"
echo u > "$TMP/etc/agentId-ncm001"; echo c > "$TMP/config/agent.conf"
guard ncm001 enabled
[[ -e "$TMP/etc/agentId-ncm001" ]]; check "$?" "0" "match: identity kept"
[[ "$(nbackups)" -eq 0 ]];          check "$?" "0" "match: no backup"
rm -rf "$TMP"

# case 3: empty -> no-op
TMP="$(mktemp -d)"; mkdir -p "$TMP/etc" "$TMP/config"
guard ncm001 enabled
[[ "$(nbackups)" -eq 0 ]]; check "$?" "0" "empty: no backup"
rm -rf "$TMP"

# case 4: disabled -> no-op even on mismatch
TMP="$(mktemp -d)"; mkdir -p "$TMP/etc" "$TMP/config"
echo u > "$TMP/etc/agentId-d2techhq"
guard ncm001 disabled
[[ -e "$TMP/etc/agentId-d2techhq" ]]; check "$?" "0" "disabled: no action"
[[ "$(nbackups)" -eq 0 ]];            check "$?" "0" "disabled: no backup"
rm -rf "$TMP"

# case 5: prefix read FROM .env (exercises the parser)
TMP="$(mktemp -d)"; mkdir -p "$TMP/etc" "$TMP/config"
echo u > "$TMP/etc/agentId-d2techhq"
printf "DEPLOY_AUVIK=enabled\nAUVIK_DOMAIN_PREFIX=ncm001\n" > "$TMP/cfg.env"
AUVIK_DIR="$TMP" CONTAINER="nope-$$-x" RESET_SCRIPT="$RESET" ENV_FILE="$TMP/cfg.env" LOG_TAG=test \
  bash "$SCRIPT" >/dev/null 2>&1
[[ -e "$TMP/etc/agentId-d2techhq" ]]; check "$?" "1" "env-parse: mismatch cleared via .env prefix"
[[ "$(nbackups)" -ge 1 ]];            check "$?" "0" "env-parse: backup made"
rm -rf "$TMP"

[[ "$fails" -eq 0 ]] && { echo "ALL PASS"; exit 0; } || { echo "$fails FAILED"; exit 1; }
