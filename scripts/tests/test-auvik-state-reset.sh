#!/usr/bin/env bash
# Tests auvik-state-reset.sh against a temp AUVIK_DIR with a nonexistent
# container (docker stop is skipped). No docker images required.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"   # -> scripts/
SCRIPT="$HERE/auvik-state-reset.sh"
fails=0
check(){ if [[ "$1" == "$2" ]]; then echo "ok: $3"; else echo "FAIL: $3 (got '$1' want '$2')"; fails=$((fails+1)); fi; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/etc" "$TMP/config"
echo uuid-old > "$TMP/etc/agentId-oldtenant"
echo cfg      > "$TMP/config/agent.conf"
: > "$TMP/config/.gitkeep"
mkdir -p "$TMP/backup-prior"; echo keep > "$TMP/backup-prior/marker"

AUVIK_DIR="$TMP" CONTAINER="nope-$$-doesnotexist" LOG_TAG=test \
  bash "$SCRIPT" "unit test" >/dev/null

[[ -e "$TMP/etc/agentId-oldtenant" ]]; check "$?" "1" "etc cleared"
[[ -e "$TMP/config/agent.conf" ]];    check "$?" "1" "config cleared"
[[ -e "$TMP/config/.gitkeep" ]];      check "$?" "0" ".gitkeep preserved"
found="$(ls -d "$TMP"/backup-* 2>/dev/null | grep -v backup-prior | head -1)"
[[ -n "$found" && -f "$found/etc/agentId-oldtenant" ]]; check "$?" "0" "backup captured old identity"
[[ -f "$TMP/backup-prior/marker" ]];  check "$?" "0" "prior backup preserved"

[[ "$fails" -eq 0 ]] && { echo "ALL PASS"; exit 0; } || { echo "$fails FAILED"; exit 1; }
