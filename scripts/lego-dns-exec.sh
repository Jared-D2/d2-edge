#!/bin/bash
# lego --dns exec wrapper: places ACME DNS-01 TXT via the acme-hook on ca-dns.
set -euo pipefail
exec ssh -i /etc/lego/ssh_id -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=accept-new acme-hook@10.255.255.244 "$@"
