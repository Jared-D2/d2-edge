#!/usr/bin/env bash
# Point this Pi's /opt/d2-edge checkout at the PRIVATE GitHub repo using the
# fleet READ-ONLY deploy key. Idempotent -- runs from update.sh [1/6] (before
# the pull) and twice in bootstrap.sh: before the admin pull in the
# repo-exists branch, and again after the fresh clone.
#
# Why: the d2-edge repo is private; anonymous https:// pulls 404. Every Pi
# needs (a) the deploy key and (b) an SSH origin -- on port 443
# (ssh.github.com), because customer firewalls block outbound 22. The key is
# fleet-shared (one read-only deploy key on the repo -- same pattern as
# TS_AUTHKEY and AGENT_TOKEN) and arrives as GIT_DEPLOY_KEY_B64 in .env
# (root-only 0600), or as the same name in the ENVIRONMENT, which is how
# bootstrap supplies it before .env exists. Environment wins over .env.
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
ADMIN_HOME="${ADMIN_HOME:-$(getent passwd "$ADMIN_USER" 2>/dev/null | cut -d: -f6)}"
ADMIN_HOME="${ADMIN_HOME:-/home/$ADMIN_USER}"
SSH_DIR="$ADMIN_HOME/.ssh"
KEY_FILE="$SSH_DIR/id_d2edge_deploy"
KNOWN_HOSTS="$SSH_DIR/known_hosts_github"
# SSH over 443 at ssh.github.com: customer firewalls block outbound 22 (lmc001 hung 16 min on 2026-09-18); 443 works wherever https does. Same host keys as github.com.
SSH_ORIGIN="ssh://git@ssh.github.com:443/Jared-D2/d2-edge.git"
# Keep identical to the clone -c core.sshCommand in shared/scripts/bootstrap.sh and the portal's edge_bootstrap.py; drift just makes this heal re-log once, but keep them in step.
SSH_CMD="ssh -i '$KEY_FILE' -o IdentitiesOnly=yes -o UserKnownHostsFile='$KNOWN_HOSTS' -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=20"

# GitHub's published host keys (gh api meta --jq '.ssh_keys[]', 2026-09-14),
# under the bracketed [host]:port form known_hosts requires for a non-22 port.
# ssh.github.com serves the SAME keys as github.com, so the key material is
# byte-identical to the published values -- only the host field differs.
# Pinned, NOT ssh-keyscan'd: trust-on-first-use over a customer WAN is not
# acceptable for the key that pulls code onto every appliance.
GITHUB_HOST_KEYS='[ssh.github.com]:443 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
[ssh.github.com]:443 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
[ssh.github.com]:443 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk='

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

# install_file MODE SRC DST -- write only when absent or content differs, but
# ALWAYS converge mode/owner (the portal's bootstrap block writes the key 0644).
# Returns 0 if it wrote content, 1 if the content was already current.
install_file() {
    local mode="$1" src="$2" dst="$3"
    if [[ -f "$dst" ]] && cmp -s "$src" "$dst"; then
        if [[ "$(stat -c '%a %U %G' "$dst")" != "$mode $ADMIN_USER $ADMIN_USER" ]]; then
            chmod "$mode" "$dst"
            chown "$ADMIN_USER:$ADMIN_USER" "$dst"
        fi
        return 1
    fi
    install -m "$mode" -o "$ADMIN_USER" -g "$ADMIN_USER" "$src" "$dst"
    return 0
}

# 0. ~admin/.ssh: converge on every run, not just when a key arrives. A Pi
# without the admin home is misprovisioned -- do not invent one.
if [[ ! -d "$ADMIN_HOME" ]]; then
    echo "[git-deploy-key] ERROR: admin home $ADMIN_HOME does not exist -- this Pi is misprovisioned" >&2
    exit 1
fi
if [[ -d "$SSH_DIR" ]]; then
    # install -d does NOT re-mode an existing directory.
    chmod 700 "$SSH_DIR"
    chown "$ADMIN_USER:$ADMIN_USER" "$SSH_DIR"
else
    install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "$SSH_DIR"
fi

# Stage inside $SSH_DIR (0700, same filesystem as the destinations). Sweep
# temps a killed earlier run left behind -- but only ones older than an hour,
# so a concurrent run's live temp is never pulled out from under it.
find "$SSH_DIR" -maxdepth 1 -name '.setup-git-deploy-key.*' -mmin +60 -delete 2>/dev/null || true
tmp=$(mktemp "$SSH_DIR/.setup-git-deploy-key.XXXXXX"); trap 'rm -f "$tmp"' EXIT

if [[ -e "$ENV_FILE" && ! -r "$ENV_FILE" ]]; then
    log "NOTE: $ENV_FILE exists but is not readable as $(id -un); run as root"
fi

# 1. Key material: environment wins (bootstrap, pre-.env), then .env. The
# `|| true` keeps an unreadable .env (running as a non-root operator) on the
# NOTE + WARNING path above instead of aborting on sed's "Permission denied".
key_material=
key_b64="${GIT_DEPLOY_KEY_B64:-$(env_get GIT_DEPLOY_KEY_B64 "$ENV_FILE" || true)}"
if [[ -n "$key_b64" ]]; then
    # ssh-keygen -y proves it parses AND is unencrypted (and catches truncation);
    # a BEGIN-line grep passes on a half-written key. $tmp is mktemp'd 0600.
    if ! printf '%s' "$key_b64" | base64 -d > "$tmp" 2>/dev/null \
       || ! ssh-keygen -y -P '' -f "$tmp" >/dev/null 2>&1; then
        # A fat-fingered .env must not strand a Pi that already holds a good
        # key: keep it and carry on as if no new material arrived this run
        # ($tmp holds the garbage, so nothing gets installed from it). Only a
        # bad value with no usable key to fall back on is fatal.
        if [[ -f "$KEY_FILE" ]] && ssh-keygen -y -P '' -f "$KEY_FILE" >/dev/null 2>&1; then
            log "WARNING: GIT_DEPLOY_KEY_B64 is not a base64 OpenSSH private key (or it is passphrase-protected/truncated) -- keeping the existing valid $KEY_FILE"
        else
            echo "[git-deploy-key] ERROR: GIT_DEPLOY_KEY_B64 is not a base64 OpenSSH private key (or it is passphrase-protected/truncated)" >&2
            exit 1
        fi
    else
        if install_file 600 "$tmp" "$KEY_FILE"; then log "installed $KEY_FILE"; fi
        key_material=1
    fi
fi

# 2. Without a key there is nothing to wire -- but shout if the pull will break.
if [[ ! -f "$KEY_FILE" ]]; then
    if [[ -d "$EDGE_DIR/.git" ]] \
       && as_admin git -C "$EDGE_DIR" remote get-url origin 2>/dev/null | grep -q '^https://'; then
        log "WARNING: origin is https:// and no deploy key is configured -- git pull fails once the repo is private. Add GIT_DEPLOY_KEY_B64 to $ENV_FILE."
    fi
    exit 0
fi

# 2b. Key file on disk but no validated material this run (nothing in the
# environment or .env): prove what is already there is usable, or the failure
# only shows up as an unexplained pull error. Warning, not fatal -- the fix is
# an operator putting GIT_DEPLOY_KEY_B64 back in .env.
if [[ -z "$key_material" ]] && ! ssh-keygen -y -P '' -f "$KEY_FILE" >/dev/null 2>&1; then
    log "WARNING: $KEY_FILE does not parse as an unencrypted OpenSSH private key -- the next pull will fail"
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
        # A checkout with no origin at all (hand-built, or `git init`) must be
        # wired up, not aborted on -- `remote set-url` fails when it is absent.
        if [[ -z "$origin" ]]; then
            as_admin git -C "$EDGE_DIR" remote add origin "$SSH_ORIGIN"
        else
            as_admin git -C "$EDGE_DIR" remote set-url origin "$SSH_ORIGIN"
        fi
        log "origin: ${origin:-<none>} -> $SSH_ORIGIN"
    fi
    # Prove the wiring end-to-end so a dead key shows up in THIS run's output,
    # not one update later. BatchMode=yes prevents prompts and timeout 20
    # bounds a dead WAN, so it cannot stall the update. Skippable for the
    # offline test harness only.
    if [[ -z "${GIT_DEPLOY_KEY_NO_REMOTE_CHECK:-}" ]] \
       && ! as_admin timeout 20 env GIT_TERMINAL_PROMPT=0 git -C "$EDGE_DIR" ls-remote --exit-code origin HEAD >/dev/null 2>&1; then
        log "WARNING: origin is wired to the deploy key but 'git ls-remote origin' failed -- check WAN, the key on GitHub, and the pinned host keys"
    fi
fi

# 5. Legacy full-account key: report, never delete. Either half is evidence --
# an imaged Pi whose .pub was tidied away still has the private key on disk,
# and `ssh-keygen -lf` fingerprints a private key too.
legacy_key=""
for f in "$SSH_DIR/id_ed25519.pub" "$SSH_DIR/id_ed25519"; do
    if [[ -f "$f" ]]; then legacy_key="$f"; break; fi
done
if [[ -n "$legacy_key" ]]; then
    # </dev/null: ssh-keygen prompts for a passphrase on an encrypted private
    # key, which would swallow the caller's stdin mid-update.
    log "NOTICE: legacy key still present: $(ssh-keygen -lf "$legacy_key" </dev/null 2>/dev/null || echo "$legacy_key") -- revoke on GitHub once the fleet is converted, then delete it"
fi
