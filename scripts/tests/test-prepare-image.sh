#!/usr/bin/env bash
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$HERE/prepare-image.sh"
fails=0
check(){ if [[ "$1" == "$2" ]]; then echo "ok: $3"; else echo "FAIL: $3"; fails=$((fails+1)); fi; }

out="$(EDGE_DIR=/nonexistent bash "$SCRIPT" 2>&1)"; rc=$?
echo "$out" | grep -q "DRY RUN";   check "$?" "0" "no flag -> dry run banner"
echo "$out" | grep -qi "will clear"; check "$?" "0" "prints plan"
check "$rc" "0" "dry run exits 0 without --confirm"

[[ "$fails" -eq 0 ]] && { echo "ALL PASS"; exit 0; } || { echo "$fails FAILED"; exit 1; }
