# Oxidized SSH Proxy

Restricted SSH jump host user for Oxidized config backups.

## What it does

Creates an oxidized-proxy user that can ONLY forward TCP connections
to internal device SSH ports. No shell, no commands, no lateral movement.

## Setup

1. Place the Oxidized server public key at oxidized-proxy/authorized_keys.pub
2. Run: sudo bash oxidized-proxy/setup.sh

To use a key from a different path:
   sudo bash oxidized-proxy/setup.sh /path/to/key.pub

## Re-running

The script is idempotent. Re-run it to update the key or after modifying
the allowed subnet list in the script.

## Allowed networks

Edit the ALLOWED_NETS array in setup.sh to match your device subnets.
Default: all RFC1918 ranges on port 22.
