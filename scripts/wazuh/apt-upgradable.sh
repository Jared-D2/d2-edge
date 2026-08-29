#!/bin/bash
# Emit structured key=value for Wazuh decoder
count=$(apt list --upgradable 2>/dev/null | tail -n +2 | grep -c .)
security=$(apt list --upgradable 2>/dev/null | grep -c -- '-security')
[ -z "$count" ] && count=0
[ -z "$security" ] && security=0
echo "wazuh_updates pending=${count} security=${security}"
