#!/bin/bash
# Emit reboot-required status for Wazuh
if [ -f /var/run/reboot-required ]; then
  status="yes"
  # pkgs file lists what triggered it
  if [ -f /var/run/reboot-required.pkgs ]; then
    pkgs=$(tr '\n' ',' < /var/run/reboot-required.pkgs | sed 's/,$//')
  else
    pkgs="unknown"
  fi
else
  status="no"
  pkgs="none"
fi
# Uptime in days for context
uptime_days=$(awk '{print int($1/86400)}' /proc/uptime)
echo "wazuh_reboot_required status=${status} uptime_days=${uptime_days} packages=${pkgs}"
