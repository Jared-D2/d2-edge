#!/usr/bin/env bash
# Point this Pi's /opt/d2-edge checkout at the PRIVATE GitHub repo using the
# fleet READ-ONLY deploy key. Idempotent -- runs on every update.sh (host-
# heal [3/6]) and at the end of bootstrap.sh.
#
# Why: the d2-edge repo is private; anonymous https:// pulls 404. Every Pi
# needs (a) the deploy key and (b) an SSH origin. The key is fleet-shared
# (one read-only deploy key on the repo -- same pattern as TS_AUTHKEY and
# AGENT_TOKEN) and arrives as GIT_DEPLOY_KEY_B64 in .env (root-only 0600),
# or as the same name in the ENVIRONMENT, which is how bootstrap supplies it
# before .env exists. Environment wins over .env.
#
# Never touches the operator's legacy ~admin/.ssh/id_ed25519 (the full-
# account key from imaging) -- it only REPORTS its fingerprint so the key
# can be revoked on GitHub once the fleet has converted.
#
# Env overrides (test harness only): EDGE_DIR, ENV_FILE, ADMIN_USER, ADMIN_HOME.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EDGE_DIR="${EDGE_DIR:-/opt/d2-edge}"
ENV_FILE="${ENV_FILE:-$EDGE_DIR/.env}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_HOME="${ADMIN_HOME:-/home/$ADMIN_USER}"
SSH_DIR="$ADMIN_HOME/.ssh"
KEY_FILE="$SSH_DIR/id_d2edge_deploy"
KNOWN_HOSTS="$SSH_DIR/known_hosts_github"
SSH_ORIGIN="git@github.com:Jared-D2/d2-edge.git"
SSH_CMD="ssh -i $KEY_FILE -o IdentitiesOnly=yes -o UserKnownHostsFile=$KNOWN_HOSTS -o StrictHostKeyChecking=yes"

# GitHub's published host keys (gh api meta --jq '.ssh_keys[]', 2026-09-14).
# Pinned, NOT ssh-keyscan'd: trust-on-first-use over a customer WAN is not
# acceptable for the key that pulls code onto every appliance.
GITHUB_HOST_KEYS='github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk='

# shellcheck source=../shared/scripts/lib/envfile.sh
. "$SCRIPT_DIR/../shared/scripts/lib/envfile.sh"

log() { echo "[git-deploy-key] $*"; }

# Run git as the user who owns the checkout (update.sh runs as root).
as_admin() {
    if [[ $EUID -eq 0 && "$ADMIN_USER" != "$(id -un)" ]]; then
        sudo -u "$ADMIN_USER" "$@"
    else
        "$@"
    fi
}

# install_file MODE SRC DST -- write only when absent or content differs.
# Returns 0 if it wrote, 1 if already current.
install_file() {
    local mode="$1" src="$2" dst="$3"
    if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then return 1; fi
    install -m "$mode" -o "$ADMIN_USER" -g "$ADMIN_USER" "$src" "$dst"
    return 0
}

tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT

# 1. Key material: environment wins (bootstrap, pre-.env), then .env.
key_b64="${GIT_DEPLOY_KEY_B64:-$(env_get GIT_DEPLOY_KEY_B64 "$ENV_FILE")}"
if [[ -n "$key_b64" ]]; then
    if ! printf '%s' "$key_b64" | base64 -d > "$tmp" 2>/dev/null \
       || ! grep -q -- '-----BEGIN OPENSSH PRIVATE KEY-----' "$tmp"; then
        echo "[git-deploy-key] ERROR: GIT_DEPLOY_KEY_B64 is not a base64 OpenSSH private key" >&2
        exit 1
    fi
    install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$SSH_DIR"
    if install_file 600 "$tmp" "$KEY_FILE"; then log "installed $KEY_FILE"; fi
fi

# 2. Without a key there is nothing to wire -- but shout if the pull will break.
if [[ ! -f "$KEY_FILE" ]]; then
    if [[ -d "$EDGE_DIR/.git" ]] \
       && as_admin git -C "$EDGE_DIR" remote get-url origin 2>/dev/null | grep -q '^https://'; then
        log "WARNING: origin is https:// and no deploy key is configured -- git pull fails once the repo is private. Add GIT_DEPLOY_KEY_B64 to $ENV_FILE."
    fi
    exit 0
fi

# 3. Pinned GitHub host keys.
printf '%s\n' "$GITHUB_HOST_KEYS" > "$tmp"
if install_file 644 "$tmp" "$KNOWN_HOSTS"; then log "pinned GitHub host keys in $KNOWN_HOSTS"; fi

# 4. Repo wiring (only once a checkout exists).
if [[ -d "$EDGE_DIR/.git" ]]; then
    if [[ "$(as_admin git -C "$EDGE_DIR" config --get core.sshCommand || true)" != "$SSH_CMD" ]]; then
        as_admin git -C "$EDGE_DIR" config core.sshCommand "$SSH_CMD"
        log "set core.sshCommand -> $KEY_FILE"
    fi
    origin="$(as_admin git -C "$EDGE_DIR" remote get-url origin 2>/dev/null || true)"
    if [[ "$origin" != "$SSH_ORIGIN" ]]; then
        as_admin git -C "$EDGE_DIR" remote set-url origin "$SSH_ORIGIN"
        log "origin: ${origin:-<none>} -> $SSH_ORIGIN"
    fi
fi

# 5. Legacy full-account key: report, never delete.
if [[ -f "$SSH_DIR/id_ed25519.pub" ]]; then
    log "NOTICE: legacy key still present: $(ssh-keygen -lf "$SSH_DIR/id_ed25519.pub" 2>/dev/null || echo "$SSH_DIR/id_ed25519.pub") -- revoke on GitHub once the fleet is converted, then delete it"
fi
