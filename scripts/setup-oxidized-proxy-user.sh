#!/bin/bash
# Idempotent. Creates the oxidized-proxy bastion user on this Pi and
# installs the Oxidized SSH public key with hardened restrictions:
# - restrict: deny everything by default
# - port-forwarding: allow TCP forwarding only
# - permitopen="*:22": only allow forwarding to port 22 of other hosts
# - from="10.255.255.68": only accept connections from the Oxidized VM
set -e

USER_NAME=oxidized-proxy
OXIDIZED_IP=10.255.255.68
PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL1m+QZVi53JtZLUNRQpIYqpiGuZyv4m42hG2d6M2Z5k oxidized-proxy@oxidized'
RESTRICTIONS='restrict,port-forwarding,permitopen="*:22",from="'$OXIDIZED_IP'"'

if ! id "$USER_NAME" >/dev/null 2>&1; then
  useradd -m -s /bin/bash -c 'Oxidized SSH jump user' "$USER_NAME"
  echo "[setup] created user $USER_NAME"
fi

install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "/home/$USER_NAME/.ssh"
AUTH=/home/$USER_NAME/.ssh/authorized_keys
LINE="$RESTRICTIONS $PUBKEY"

# Rewrite authorized_keys idempotently with the single hardened line
echo "$LINE" > /tmp/ak.$$
chown "$USER_NAME:$USER_NAME" /tmp/ak.$$
chmod 600 /tmp/ak.$$
mv /tmp/ak.$$ "$AUTH"
echo "[setup] authorized_keys updated with hardened restrictions"
