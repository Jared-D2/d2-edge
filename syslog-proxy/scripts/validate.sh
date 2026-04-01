#!/usr/bin/env bash
set -euo pipefail

docker exec syslog-proxy syslog-ng --syntax-only --cfgfile /config/syslog-ng.conf
echo "syslog-ng config syntax OK"
