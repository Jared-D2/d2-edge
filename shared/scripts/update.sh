#!/usr/bin/env bash
set -euo pipefail

EDGE_DIR=/opt/d2-edge

# Docker group GID varies per host install — resolve at deploy time.
export DOCKER_GID=$(getent group docker | cut -d: -f3)
if [[ -z "$DOCKER_GID" ]]; then
    echo "ERROR: host 'docker' group not found." >&2
    exit 1
fi

echo "========================================"
echo " D2 Edge Appliance — Update"
echo "========================================"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash update.sh"
    exit 1
fi

# Heal .env if DOCKER_GID is missing — older bootstraps didn't persist it,
# and `docker compose` interpolates ${DOCKER_GID} from .env at graph-parse
# time. A missing key leaves zabbix-agent2's group_add unresolved and
# stops the start phase mid-recreate (containers stuck in 'Created').
# This must run BEFORE preflight at [2/6] so the new required-key check
# doesn't reject a legacy .env that we're about to fix.
if [[ -f "$EDGE_DIR/.env" ]] && ! grep -q "^DOCKER_GID=" "$EDGE_DIR/.env"; then
    echo "DOCKER_GID=${DOCKER_GID}" >> "$EDGE_DIR/.env"
    echo "Healed .env: appended DOCKER_GID=${DOCKER_GID} (legacy bootstrap)"
fi

# Heal .env duplicate KEY= lines. preflight.sh fails loud on conflicting
# duplicates; here we silently dedup same-value duplicates (paste
# accidents during onboarding) so update.sh stays self-healing on legacy
# state. Different-value duplicates are left for preflight to flag —
# silent collapse there could lose operator intent.
if [[ -f "$EDGE_DIR/.env" ]]; then
    awk -F= '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { print; next }
        /^[A-Za-z_][A-Za-z0-9_]*=/ {
            k=$1
            v=substr($0, length(k)+2)
            if (k in seen) {
                if (seen[k] == v) next
                else { print; next }
            }
            seen[k]=v
        }
        { print }
    ' "$EDGE_DIR/.env" > "$EDGE_DIR/.env.dedup.$$"
    if ! cmp -s "$EDGE_DIR/.env" "$EDGE_DIR/.env.dedup.$$"; then
        chown --reference="$EDGE_DIR/.env" "$EDGE_DIR/.env.dedup.$$"
        chmod --reference="$EDGE_DIR/.env" "$EDGE_DIR/.env.dedup.$$"
        mv "$EDGE_DIR/.env.dedup.$$" "$EDGE_DIR/.env"
        echo "Healed .env: dedup'd same-value duplicate keys"
    else
        rm -f "$EDGE_DIR/.env.dedup.$$"
    fi
fi

echo
echo "[1/6] Pulling latest from Git..."
cd "$EDGE_DIR"
# Heal ownership on git-tracked paths so `sudo -u admin git pull` can
# unlink/write them. Runtime data dirs (zabbix-proxy/data|logs,
# syslog-proxy/logs|state, auvik/*, d2-agent/buffer) are gitignored and
# owned by container runtime UIDs — DO NOT chown them, or containers lose
# write access (e.g. zabbix UID 1997 can't write admin-owned data).
chown admin:admin "$EDGE_DIR"
chown -R admin:admin "$EDGE_DIR/.git" 2>/dev/null || true
# Only tracked files matter to `git pull`; list them via the index.
sudo -u admin git ls-files -z | xargs -0r -I{} chown admin:admin "$EDGE_DIR/{}"
sudo -u admin git pull
# Stamp current commit into .env so d2-agent reports the running version.
SHA=$(sudo -u admin git -C "$EDGE_DIR" rev-parse HEAD)
if grep -q '^GIT_SHA=' "$EDGE_DIR/.env" 2>/dev/null; then
    sed -i "s|^GIT_SHA=.*|GIT_SHA=${SHA}|" "$EDGE_DIR/.env"
else
    echo "GIT_SHA=${SHA}" >> "$EDGE_DIR/.env"
fi
echo "  OK ($SHA)"

echo
echo "[2/6] Validating .env and host state..."
bash "$EDGE_DIR/shared/scripts/preflight.sh"
echo "  OK"

echo
echo "[3/6] Applying host heals (auto-reboot policy, oxidized bastion)..."
# Auto-reboot drop-in: needed for kernel-CVE remediation. Source of truth
# is shared/files/52-d2-auto-reboot.conf — copy if absent or content drift.
# Drop-in number 52 is intentionally higher than the stock 50unattended-
# upgrades so its values win regardless of distro defaults.
DROPIN_SRC="$EDGE_DIR/shared/files/52-d2-auto-reboot.conf"
DROPIN_DST=/etc/apt/apt.conf.d/52-d2-auto-reboot
if [[ -f "$DROPIN_SRC" ]]; then
    if [[ ! -f "$DROPIN_DST" ]] || ! cmp -s "$DROPIN_SRC" "$DROPIN_DST"; then
        install -m 0644 -o root -g root "$DROPIN_SRC" "$DROPIN_DST"
        echo "  installed/updated $DROPIN_DST"
    fi
fi
# Oxidized bastion user: idempotent. Migrates legacy oxidized-proxy →
# svc_oxidized_proxy if needed; ensures nologin shell + hardened keys.
# Safe on Pis that don't proxy any device today — the user just sits
# unused until Oxidized adds it as a jump_host.
if [[ -x "$EDGE_DIR/scripts/setup-oxidized-proxy-user.sh" ]]; then
    bash "$EDGE_DIR/scripts/setup-oxidized-proxy-user.sh"
fi
echo "  OK"

echo
echo "[4/6] Re-rendering configs..."
bash "$EDGE_DIR/render-configs.sh"
echo "  OK"

echo
echo "[5/6] Building d2-agent image..."
cd "$EDGE_DIR"
docker compose build d2-agent --pull
echo "  OK"

echo
echo "[6/6] Recreating containers..."
# Zabbix runtime data must be owned by the zabbix container user (UID 1997
# / GID 1995 in the zabbix/zabbix-proxy-sqlite3:alpine image). Historic
# broad `chown -R admin` runs left zabbix_proxy.db owned by admin 0644,
# which silently breaks SQLite writes on the next container recreate
# ("attempt to write a readonly database" → proxy down, agent2 active
# checks time out). Idempotent no-op on correctly-owned trees.
if [[ -d "$EDGE_DIR/zabbix-proxy/data" ]]; then
    chown -R 1997:1995 "$EDGE_DIR/zabbix-proxy/data" "$EDGE_DIR/zabbix-proxy/logs" 2>/dev/null || true
fi
# Legacy .env files on pre-existing fleet Pis may lack COMPOSE_PROFILES.
# Without it, every profile-gated service (syslog/zabbix/freeradius/auvik/
# d2-agent/zabbix-agent2) is skipped by `docker compose up` — they stay on
# their old image/config instead of picking up render-configs.sh output.
export COMPOSE_PROFILES=enabled
# Force-recreate only services whose config is actually re-rendered by
# render-configs.sh OR whose image we just rebuilt. Tailscale is excluded
# on purpose: its compose block has no volume-mounted config, and forcing
# a recreate reruns `tailscale up --authkey=${TS_AUTHKEY}`. If that
# authkey has expired or been consumed, the node is logged out of the
# tailnet — which has locked us out of fleet Pis remotely in the past.
# Plain `up -d` on tailscale still recreates it if docker-compose.yml
# itself changed, which is the only case where a restart is warranted.
docker compose up -d --force-recreate \
    auvik cert-server d2-agent freeradius-proxy \
    syslog-proxy zabbix-agent2 zabbix-proxy
docker compose up -d tailscale
echo "  OK"

echo
echo "========================================"
echo " Update complete"
echo "========================================"
