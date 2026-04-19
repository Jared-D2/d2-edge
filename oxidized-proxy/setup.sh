#!/usr/bin/env bash
# oxidized-proxy/setup.sh
# Creates a restricted SSH proxy user for Oxidized config backup.
# Idempotent — safe to re-run.
#
# Usage: sudo bash oxidized-proxy/setup.sh [public_key_file]
#   public_key_file: path to the Oxidized server ed25519 public key
#                    defaults to oxidized-proxy/authorized_keys.pub

set -euo pipefail

PROXY_USER="svc_oxidized_proxy"
PROXY_HOME="/home/${PROXY_USER}"
KEY_FILE="${1:-oxidized-proxy/authorized_keys.pub}"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must run as root (sudo)" >&2
    exit 1
fi

if [[ ! -f "$KEY_FILE" ]]; then
    echo "ERROR: Public key file not found: $KEY_FILE" >&2
    echo "Place the Oxidized server ed25519 public key at $KEY_FILE" >&2
    exit 1
fi

PUB_KEY=$(cat "$KEY_FILE")

# Create user if it doesn't exist
if ! id "$PROXY_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$PROXY_USER"
    echo "Created user: $PROXY_USER"
else
    echo "User already exists: $PROXY_USER"
fi

# Lock password (no password login ever)
passwd -l "$PROXY_USER" >/dev/null 2>&1

# Build authorized_keys with restrictions
# restrict  — disables shell, pty, agent/X11 forwarding
# port-forwarding — re-enables TCP forwarding (needed for ProxyJump)
# permitopen="*:22" — only allow forwarding to SSH port
SSH_DIR="${PROXY_HOME}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"

mkdir -p "$SSH_DIR"
echo "restrict,port-forwarding,permitopen=\"*:22\" ${PUB_KEY}" > "$AUTH_KEYS"

chmod 700 "$SSH_DIR"
chmod 600 "$AUTH_KEYS"
chown -R "${PROXY_USER}:${PROXY_USER}" "$SSH_DIR"

echo ""
echo "Setup complete."
echo "  User:            $PROXY_USER"
echo "  Shell:           /bin/bash (restricted by authorized_keys)"
echo "  Auth:            key-only (password locked)"
echo "  Port forwarding: any host, port 22 only"
echo "  authorized_keys: $AUTH_KEYS"
echo ""
echo "Test from the Oxidized server:"
echo "  ssh -o ProxyJump=svc_oxidized_proxy@<pi-tailscale-ip> user@<device-ip>"
