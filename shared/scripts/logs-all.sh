#!/usr/bin/env bash
# Show recent logs from all D2 Edge containers
CONTAINERS=(tailscale syslog-proxy zabbix-proxy freeradius-proxy auvik d2-agent)
LINES=${1:-20}

for c in "${CONTAINERS[@]}"; do
    echo "════════════════════════════════════════"
    echo " $c"
    echo "════════════════════════════════════════"
    docker logs "$c" --tail "$LINES" 2>&1
    echo ""
done
