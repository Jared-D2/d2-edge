#!/bin/bash
# Register an edge Pi's lego DNS-01 pubkey with acme-hook so it can request RadSec
# certs from step-ca. THE GATED TRUST STEP -- run on ca-dns by a CA admin, NOT from
# the fleet control node (a Pi/.3 must not be able to authorize itself to the CA).
# Idempotent. Usage: register-radsec-pi.sh '<ssh-ed25519 AAAA... lego-dns-hook@host>'
set -euo pipefail
AK=/home/acme-hook/.ssh/authorized_keys
PREFIX='command="sudo /usr/local/sbin/lego-dns-hook.sh",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty'
PUBKEY="${1:?usage: register-radsec-pi.sh \"<pubkey line>\"}"
echo "$PUBKEY" | grep -qE '^ssh-ed25519 [A-Za-z0-9+/]+=* lego-dns-hook@[a-z0-9._-]+$' \
  || { echo "ERROR: not a valid lego-dns-hook ed25519 pubkey" >&2; exit 2; }
BLOB=$(echo "$PUBKEY" | awk '{print $2}')
if sudo grep -qF "$BLOB" "$AK" 2>/dev/null; then echo "already registered: $(echo "$PUBKEY" | awk '{print $3}')"; exit 0; fi
sudo cp "$AK" "$AK.bak-$(date +%Y%m%d-%H%M%S)"
printf '%s %s\n' "$PREFIX" "$PUBKEY" | sudo tee -a "$AK" >/dev/null
sudo chown acme-hook:acme-hook "$AK"; sudo chmod 0600 "$AK"
echo "registered: $(echo "$PUBKEY" | awk '{print $3}')"
