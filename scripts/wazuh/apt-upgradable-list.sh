#!/bin/bash
# Emit one event per upgradable package for drill-down
apt list --upgradable 2>/dev/null | tail -n +2 | while read line; do
  # Format: package_name/repo version arch [upgradable from: old_version]
  if [ -n "$line" ]; then
    pkg=$(echo "$line" | awk -F/ '{print $1}')
    ver=$(echo "$line" | awk '{print $2}')
    is_sec=$(echo "$line" | grep -q -- '-security' && echo "yes" || echo "no")
    echo "wazuh_package_upgrade name=${pkg} new_version=${ver} security=${is_sec}"
  fi
done
