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
# `|| true` + 2>/dev/null: tolerate tracked files that are missing on disk
# (a stray rm) — the pull two lines down will restore them. Without this,
# xargs' non-zero exit trips `set -euo pipefail` and aborts before pull.
sudo -u admin git ls-files -z | xargs -0r -I{} chown admin:admin "$EDGE_DIR/{}" 2>/dev/null || true
sudo -u admin git pull
# Stamp current commit into .env so d2-agent reports the running version.
SHA=$(sudo -u admin git -C "$EDGE_DIR" rev-parse HEAD)
if grep -q '^GIT_SHA=' "$EDGE_DIR/.env" 2>/dev/null; then
    sed -i "s|^GIT_SHA=.*|GIT_SHA=${SHA}|" "$EDGE_DIR/.env"
else
    echo "GIT_SHA=${SHA}" >> "$EDGE_DIR/.env"
fi
echo "  OK ($SHA)"

# Migrate legacy IP-based CONTROLLER_URL to the hostname form. The controller
# cert is hostname-based (uxi.internal.d2tech.com.au); the IP SAN is being
# retired. extra_hosts on the d2-agent service maps the name -> 10.255.255.36
# so resolution works without fleet DNS. Idempotent: only rewrites the exact
# legacy IP URL, leaves anything else (already-migrated, lab overrides) alone.
if [[ -f "$EDGE_DIR/.env" ]] && grep -q '^CONTROLLER_URL=wss://10\.255\.255\.36:9000/ws/agent' "$EDGE_DIR/.env"; then
    sed -i 's|^CONTROLLER_URL=wss://10\.255\.255\.36:9000/ws/agent|CONTROLLER_URL=wss://uxi.internal.d2tech.com.au:9000/ws/agent|' "$EDGE_DIR/.env"
    echo "  migrated CONTROLLER_URL to hostname (uxi.internal.d2tech.com.au)"
fi

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
# Auvik watchdog: idempotent install of the systemd timer that watches
# for tenant-secret corruption (StorageException: No value for
# com.auvik.npl.agent.tenantInfo.<prefix>.secret) and triggers
# auvik-recover.sh. The watchdog scripts have shipped in the repo since
# 2026-05-12 but the systemd unit was a separate manual install; folding
# the installer in here means every update.sh self-arms the timer.
# Confirmed gap on nib001-mb-pi01 2026-05-15: repo at latest commit but
# timer never enabled, leaving the collector silently offline for ~24h.
if [[ -x "$EDGE_DIR/scripts/install-auvik-watchdog.sh" ]]; then
    bash "$EDGE_DIR/scripts/install-auvik-watchdog.sh"
fi

# Ansible service account: idempotent provision of svc_ansible (sudo limited
# to THIS update.sh, key locked to the Ansible control node 192.168.166.3).
# Self-arms on every update so new Pis are Ansible-manageable with no manual
# setup -- mirrors the auvik-watchdog / oxidized-proxy heals above.
if [[ -x "$EDGE_DIR/scripts/setup-svc-ansible.sh" ]]; then
    bash "$EDGE_DIR/scripts/setup-svc-ansible.sh"
fi
# Wazuh agent: idempotent, FAIL-SOFT install + enrolment of the native Wazuh
# agent for host security monitoring (package/CVE inventory, FIM, auditd).
# Gated by DEPLOY_WAZUH in .env (default enabled). Self-arms like the heals
# above; exits 0 cleanly if already connected or if the manager
# (10.255.255.28) isn't reachable yet -- the `|| true` is belt-and-suspenders
# so Wazuh can never abort a fleet deploy. See spec
# docs/superpowers/specs/2026-07-08-wazuh-agent-pi-fleet-rollout-design.md.
if [[ -x "$EDGE_DIR/scripts/install-wazuh-agent.sh" ]]; then
    bash "$EDGE_DIR/scripts/install-wazuh-agent.sh" || true
fi
# Weekly full-upgrade timer: idempotent install of the systemd timer that
# runs `apt full-upgrade` (all repos incl third-party Docker/Tailscale)
# every Saturday 01:00 Australia/Sydney and schedules a 02:00 reboot if one
# is required. Daily unattended-upgrades stays security-only (52 drop-in);
# this is the weekly catch-up for non-security + third-party packages that
# the security-only daily policy never touches. Added 2026-05-24, see
# project_auto_patch_reboot.md.
if [[ -x "$EDGE_DIR/scripts/install-weekly-upgrade.sh" ]]; then
    bash "$EDGE_DIR/scripts/install-weekly-upgrade.sh"
fi
# Wi-Fi sensing radio: idempotent passive enable for RF-capable sensor Pis.
# d2-agent scans wlan0 but never brings the radio up; the enablement was a
# manual imaging step never captured here, so sites shipped soft-blocked
# (ENETDOWN every ap_scan -> standing sensor_health incident). No-op on
# wired-only Pis; NEVER associates. See nib001-mu-pi01 / ncm001-bc-pi01.
if [[ -x "$EDGE_DIR/scripts/enable-rf-radio.sh" ]]; then
    bash "$EDGE_DIR/scripts/enable-rf-radio.sh"
fi

# Internal CA/DNS hosts pin: lego RadSec renewal resolves step-ca by name but
# edge Pis can't reach CoreDNS on :53; without the /etc/hosts pin (cloud-init
# wipes it on reboot) renewal fails silently and the cert expires (cost a
# ~3-week silent expiry on d2001 2026-06-26).
if [[ -x "$EDGE_DIR/scripts/ensure-internal-hosts.sh" ]]; then
    bash "$EDGE_DIR/scripts/ensure-internal-hosts.sh"
fi
# RadSec cert-expiry monitor: daily check + 2 escalating Zabbix alerts so a
# silent renewal failure can't expire unnoticed. No-op on Pis without a cert.
if [[ -x "$EDGE_DIR/scripts/install-radsec-cert-check.sh" ]]; then
    bash "$EDGE_DIR/scripts/install-radsec-cert-check.sh"
fi
# RadSec cert scaffolding (lego): installs lego + per-Pi key + renew timer.
# Self-arms everywhere but stays a no-op until the Pi key is registered with
# acme-hook (gated enrollment via Ansible). See scripts/install-lego-radsec.sh.
if [[ -x "$EDGE_DIR/scripts/install-lego-radsec.sh" ]]; then
    bash "$EDGE_DIR/scripts/install-lego-radsec.sh"
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
# Tenant-mismatch guard: reset stale auvik identity before (re)creating the
# collector so a cloned/re-tenanted Pi registers into the correct tenant.
if [[ -x "$EDGE_DIR/scripts/auvik-ensure-tenant.sh" ]]; then
    bash "$EDGE_DIR/scripts/auvik-ensure-tenant.sh" || true
fi
docker compose up -d --force-recreate \
    auvik cert-server d2-agent freeradius-proxy netflow-proxy \
    syslog-proxy zabbix-agent2 zabbix-proxy
docker compose up -d tailscale
echo "  OK"

echo
echo "========================================"
echo " Update complete"
echo "========================================"
