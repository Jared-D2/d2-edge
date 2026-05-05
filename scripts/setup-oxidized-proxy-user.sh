#!/bin/bash
# Idempotent. Ensures the svc_oxidized_proxy bastion user exists on this Pi
# (renamed 2026-04-20 from `oxidized-proxy`) with hardened SSH restrictions:
# - restrict: deny everything by default
# - port-forwarding: allow TCP forwarding only
# - permitopen="*:22": only allow forwarding to port 22 of other hosts
# - from="10.255.255.68": only accept connections from the Oxidized VM
# - shell: /usr/sbin/nologin (no interactive login, only -W tunneling)
#
# Migration logic: if the legacy `oxidized-proxy` user exists and the new
# user does not, rename in-place (preserves UID/GID, fixes shell). If both
# exist, the legacy is removed (its authorized_keys are wiped). If only
# the new user exists, just heal shell + authorized_keys.
set -e

USER_NAME=svc_oxidized_proxy
LEGACY_NAME=oxidized-proxy
OXIDIZED_IP=10.255.255.68
PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL1m+QZVi53JtZLUNRQpIYqpiGuZyv4m42hG2d6M2Z5k oxidized-proxy@oxidized'
RESTRICTIONS='restrict,port-forwarding,permitopen="*:22",from="'$OXIDIZED_IP'"'
SHELL_PATH=/usr/sbin/nologin

have_user() { id "$1" >/dev/null 2>&1; }

# Migrate legacy → new if needed.
if have_user "$LEGACY_NAME" && ! have_user "$USER_NAME"; then
    # Drop any active sessions before renaming. Bastion is nologin shell,
    # so processes here are only -W tcp-forward children of sshd. Killing
    # them at most aborts an in-flight Oxidized backup; it will retry on
    # the next scheduled run.
    pkill -u "$LEGACY_NAME" 2>/dev/null || true
    sleep 1
    usermod -l "$USER_NAME" "$LEGACY_NAME"
    usermod -d "/home/$USER_NAME" -m "$USER_NAME"
    if getent group "$LEGACY_NAME" >/dev/null 2>&1; then
        groupmod -n "$USER_NAME" "$LEGACY_NAME" 2>/dev/null || true
    fi
    echo "[setup] migrated legacy '$LEGACY_NAME' → '$USER_NAME' (UID preserved)"
elif have_user "$LEGACY_NAME" && have_user "$USER_NAME"; then
    pkill -u "$LEGACY_NAME" 2>/dev/null || true
    sleep 1
    userdel -r "$LEGACY_NAME" 2>/dev/null || userdel "$LEGACY_NAME" 2>/dev/null || true
    echo "[setup] removed redundant legacy user '$LEGACY_NAME' (kept '$USER_NAME')"
fi

if ! have_user "$USER_NAME"; then
    useradd -m -s "$SHELL_PATH" -c 'Oxidized SSH jump user' "$USER_NAME"
    echo "[setup] created user $USER_NAME"
fi

# Force shell to nologin (idempotent — handles legacy /bin/bash state).
current_shell=$(getent passwd "$USER_NAME" | cut -d: -f7)
if [[ "$current_shell" != "$SHELL_PATH" ]]; then
    usermod -s "$SHELL_PATH" "$USER_NAME"
    echo "[setup] forced shell to $SHELL_PATH (was $current_shell)"
fi

install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "/home/$USER_NAME/.ssh"
AUTH=/home/$USER_NAME/.ssh/authorized_keys
LINE="$RESTRICTIONS $PUBKEY"

# Rewrite authorized_keys idempotently with the single hardened line.
TMP=$(mktemp)
echo "$LINE" > "$TMP"
chown "$USER_NAME:$USER_NAME" "$TMP"
chmod 600 "$TMP"
mv "$TMP" "$AUTH"
echo "[setup] authorized_keys hardened (1 line, restrict+from+permitopen)"
