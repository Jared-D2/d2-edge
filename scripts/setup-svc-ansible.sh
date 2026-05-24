#!/usr/bin/env bash
# Provision the least-privilege "svc_ansible" service account used by the
# central Ansible control node (192.168.166.3, Tailscale tag:ansible) to
# manage this Pi. Idempotent -- safe to run on every update.sh.
#
# Grants svc_ansible ONLY:
#   - membership of the docker group (read-only `docker ps` for status)
#   - an authorized_keys entry locked (from=) to the control node's IPs
#   - sudo for EXACTLY one command: this repo's update.sh
#   - git safe.directory for the repo (so it can read HEAD)
set -euo pipefail

EDGE_DIR="${EDGE_DIR:-/opt/d2-edge}"
SVC_USER=svc_ansible
UPDATE_SCRIPT="$EDGE_DIR/shared/scripts/update.sh"
SVC_KEY='from="100.101.84.10,192.168.166.3" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFHl6rEy+GYlEomoOs/lR4D9FskLwrU/MQCP7kOliAFX svc_ansible@control-166.3'

if [[ $EUID -ne 0 ]]; then echo "[svc_ansible] must run as root" >&2; exit 1; fi

# 1. user
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$SVC_USER"
    echo "[svc_ansible] created user"
fi

# 2. docker group (read-only status)
if getent group docker >/dev/null 2>&1 && ! id -nG "$SVC_USER" | tr ' ' '\n' | grep -qx docker; then
    usermod -aG docker "$SVC_USER"
    echo "[svc_ansible] added to docker group"
fi

# 3. from=-locked authorized_keys
SVC_HOME="$(getent passwd "$SVC_USER" | cut -d: -f6)"
install -d -m 700 -o "$SVC_USER" -g "$SVC_USER" "$SVC_HOME/.ssh"
AK="$SVC_HOME/.ssh/authorized_keys"
if [[ ! -f "$AK" ]] || ! grep -qF 'svc_ansible@control-166.3' "$AK"; then
    printf '%s\n' "$SVC_KEY" > "$AK"
    chown "$SVC_USER:$SVC_USER" "$AK"
    chmod 600 "$AK"
    echo "[svc_ansible] authorized_keys set"
fi

# 4. sudo restricted to ONLY update.sh (staged + validated before install)
SUDOERS=/etc/sudoers.d/svc_ansible
WANT="$SVC_USER ALL=(root) NOPASSWD: $UPDATE_SCRIPT"
if [[ ! -f "$SUDOERS" ]] || ! grep -qxF "$WANT" "$SUDOERS"; then
    TMP=/etc/sudoers.d/.svc_ansible.tmp
    printf '%s\n' "$WANT" > "$TMP"
    if visudo -cf "$TMP"; then
        install -m 0440 -o root -g root "$TMP" "$SUDOERS"; rm -f "$TMP"
        echo "[svc_ansible] sudoers installed"
    else
        rm -f "$TMP"; echo "[svc_ansible] ERROR: sudoers validation failed" >&2; exit 1
    fi
fi

# 5. git safe.directory (repo is admin-owned; --system covers svc_ansible)
if ! git config --system --get-all safe.directory 2>/dev/null | grep -qx "$EDGE_DIR"; then
    git config --system --add safe.directory "$EDGE_DIR"
    echo "[svc_ansible] git safe.directory set"
fi

echo "[svc_ansible] OK"
