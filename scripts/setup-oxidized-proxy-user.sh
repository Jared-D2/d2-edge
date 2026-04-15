#!/bin/bash
# Idempotent. Creates the oxidized-proxy bastion user on this Pi and
# installs the Oxidized SSH public key. Used by Oxidized backup system
# to jump to customer devices on the Pi's LAN.
set -e

USER_NAME=oxidized-proxy
PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL1m+QZVi53JtZLUNRQpIYqpiGuZyv4m42hG2d6M2Z5k oxidized-proxy@oxidized'
# Optional: restrict connections to Oxidized's tailnet source once known
# Currently permissive — tailnet ACL is the outer perimeter.

if ! id "$USER_NAME" >/dev/null 2>&1; then
  useradd -m -s /bin/bash -c 'Oxidized SSH jump user' "$USER_NAME"
  echo "[setup] created user $USER_NAME"
else
  echo "[setup] user $USER_NAME already exists"
fi

install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "/home/$USER_NAME/.ssh"
AUTH=/home/$USER_NAME/.ssh/authorized_keys
if ! grep -qF "$PUBKEY" "$AUTH" 2>/dev/null; then
  echo "$PUBKEY" >> "$AUTH"
  chown "$USER_NAME:$USER_NAME" "$AUTH"
  chmod 600 "$AUTH"
  echo "[setup] installed oxidized pubkey"
else
  echo "[setup] pubkey already installed"
fi
