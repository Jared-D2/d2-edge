#!/usr/bin/env bash
# oob-hotplug.sh — fired by oob-hotplug.path when /dev/d2-console changes.
# ser2net silently skips slots whose serial device is absent at startup and
# never retries (pilot-verified), so a freshly plugged adapter needs an
# oob-console restart to serve. State-guarded: spurious path-unit fires
# with no actual slot change are no-ops.
#
# Trade-off (documented in the runbook): a restart drops any live console
# session on OTHER slots. Plugging/unplugging adapters during an active
# break-glass session is rare; adapters should be cabled at install time.
set -u
STATE=/run/d2-oob/slots.state
mkdir -p /run/d2-oob
cur=$(ls /dev/d2-console 2>/dev/null | sort | tr '\n' ' ')
last=$(cat "$STATE" 2>/dev/null || echo "__unset__")
[[ "$cur" == "$last" ]] && exit 0
echo "$cur" > "$STATE"
docker ps --format '{{.Names}}' 2>/dev/null | grep -qx oob-console || exit 0
logger -t oob-hotplug "console slot set changed: '${last}' -> '${cur}' — restarting oob-console"
docker restart oob-console >/dev/null 2>&1 || true
