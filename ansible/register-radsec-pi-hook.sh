#!/bin/bash
# Forced-command for the radsec-enroll user on ca-dns. The SSH command line is
# the pubkey to register; hand it to register-radsec-pi.sh (which validates it).
# Deploy to /usr/local/sbin on ca-dns; authorized_keys forces `sudo` to this.
set -euo pipefail
exec /usr/local/sbin/register-radsec-pi.sh "${SSH_ORIGINAL_COMMAND:-}"
