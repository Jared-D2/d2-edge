#!/usr/bin/env bash
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$HERE/auvik-recover.sh"
RESET="$HERE/auvik-state-reset.sh"
fails=0
check(){ if [[ "$1" == "$2" ]]; then echo "ok: $3"; else echo "FAIL: $3"; fails=$((fails+1)); fi; }

C="auvik-recover-test-$$"
TMP="$(mktemp -d)"; mkdir -p "$TMP/etc" "$TMP/config"
echo u > "$TMP/etc/agentId-x"; echo c > "$TMP/config/agent.conf"
docker pull -q busybox >/dev/null 2>&1
docker rm -f "$C" >/dev/null 2>&1 || true
docker run -d --name "$C" busybox sleep 3600 >/dev/null
trap 'docker rm -f "$C" >/dev/null 2>&1; rm -rf "$TMP"' EXIT

AUVIK_DIR="$TMP" CONTAINER="$C" RESET_SCRIPT="$RESET" bash "$SCRIPT" >/dev/null 2>&1

[[ -e "$TMP/etc/agentId-x" ]]; check "$?" "1" "recover: identity cleared"
ls -d "$TMP"/backup-* >/dev/null 2>&1; check "$?" "0" "recover: backup made"
[[ -f "$TMP/.last-recovery" ]]; check "$?" "0" "recover: marker written"
[[ "$(docker inspect -f '{{.State.Running}}' "$C" 2>/dev/null)" == "true" ]]; check "$?" "0" "recover: container restarted"

[[ "$fails" -eq 0 ]] && { echo "ALL PASS"; exit 0; } || { echo "$fails FAILED"; exit 1; }
