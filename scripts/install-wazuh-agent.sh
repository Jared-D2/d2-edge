#!/usr/bin/env bash
# Install + enrol the native Wazuh agent on this Pi -- host-level security
# monitoring (package/CVE inventory, FIM on /opt/d2-edge + /etc/tailscale,
# auditd, reboot-required). Wazuh runs as a host apt package, NOT a container:
# a containerised agent would inventory the container's packages, not the Pi's
# OS, defeating the CVE-tracking purpose.
#
# Idempotent AND fail-soft: this is called from update.sh step [3/6], which
# runs `set -euo pipefail`, so it must NEVER exit non-zero (an unreachable
# manager or apt hiccup must not abort a fleet deploy). Every failure path
# logs a warning and `exit 0`; the next update.sh retries.
#
# Enrols via authd (no password) into agent groups raspberry-pi,docker-host
# -- the shared group configs already tune Pi FIM + the docker-listener wodle.
# Gated by DEPLOY_WAZUH in .env (default 'enabled'; absent key == enabled).
# Mirrors the auvik-watchdog / svc_ansible self-arm heals in update.sh.
#
# 2026-08-23 "host profile" heal (runs on EVERY update.sh, even when the agent
# is already connected): lays down the apt/reboot wodle scripts the shared
# `raspberry-pi` group config calls, and installs auditd + the D2 audit rules
# (file-watch + privilege-escalation keys; deliberately NO execve rules -- per-
# command events from 30s container healthchecks are volume without signal).
# Manager side (group `default` + wodle/audit entries in `raspberry-pi`
# agent.conf) was applied 2026-08-23; until this heal has fired on a Pi the
# agent only logs local "command not found"/"file not available" warnings.
set -uo pipefail   # deliberately NOT -e: soft-fail on network/apt hiccups

EDGE_DIR="${EDGE_DIR:-/opt/d2-edge}"
ENV_FILE="$EDGE_DIR/.env"
WAZUH_MANAGER_DEFAULT="10.255.255.28"
WAZUH_GROUPS="raspberry-pi,docker-host"
WAZUH_APT="4.x"
STATE=/var/ossec/var/run/wazuh-agentd.state
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_SRC="$SCRIPT_DIR/wazuh"            # scripts/wazuh/{*.sh,audit.rules} in this repo
WODLE_DIR=/var/ossec/wodle-scripts
AUDIT_RULES=/etc/audit/rules.d/wazuh.rules
log() { echo "[wazuh] $*"; }

if [[ $EUID -ne 0 ]]; then log "must run as root -- skipping" >&2; exit 0; fi

# env_get from the shared lib (compose-dotenv semantics; reads $ENV_FILE).
. "$(cd "$SCRIPT_DIR/.." && pwd)/shared/scripts/lib/envfile.sh"

# --- gate ------------------------------------------------------------------
DEPLOY_WAZUH="$(env_get DEPLOY_WAZUH)"; DEPLOY_WAZUH="${DEPLOY_WAZUH:-enabled}"
if [[ "$DEPLOY_WAZUH" != "enabled" ]]; then
    log "DEPLOY_WAZUH='$DEPLOY_WAZUH' (not 'enabled') -- skipping"; exit 0
fi

WAZUH_MANAGER="$(env_get WAZUH_MANAGER)"; WAZUH_MANAGER="${WAZUH_MANAGER:-$WAZUH_MANAGER_DEFAULT}"
AGENT_NAME="$(env_get EDGE_HOSTNAME)"
if [[ -z "$AGENT_NAME" || "$AGENT_NAME" == "REPLACE_ME" ]]; then AGENT_NAME="$(hostname)"; fi

# --- host profile heal (idempotent; needs the wazuh-agent package present) --
# Returns 0 always. Only touches files owned by this profile.
ensure_host_profile() {
    dpkg -s wazuh-agent >/dev/null 2>&1 || return 0
    getent group wazuh >/dev/null 2>&1 || return 0
    [[ -d "$PROFILE_SRC" ]] || { log "WARN $PROFILE_SRC missing in repo -- profile skipped"; return 0; }
    local changed=0 f
    # 1) wodle scripts called by the shared raspberry-pi group config
    install -d -m 755 -o root -g root "$WODLE_DIR"
    for f in apt-check.sh apt-upgradable.sh apt-upgradable-list.sh reboot-required.sh; do
        [[ -f "$PROFILE_SRC/$f" ]] || continue
        if ! cmp -s "$PROFILE_SRC/$f" "$WODLE_DIR/$f" 2>/dev/null; then
            install -m 750 -o root -g wazuh "$PROFILE_SRC/$f" "$WODLE_DIR/$f" && changed=1
        fi
    done
    # 2) auditd + D2 rules (no execve)
    if ! dpkg -s auditd >/dev/null 2>&1; then
        if DEBIAN_FRONTEND=noninteractive apt-get install -y -q auditd >/dev/null 2>&1; then
            log "auditd installed"; changed=1
        else
            log "WARN auditd install failed -- next update.sh retries"
        fi
    fi
    if dpkg -s auditd >/dev/null 2>&1 && [[ -f "$PROFILE_SRC/audit.rules" ]]; then
        if ! cmp -s "$PROFILE_SRC/audit.rules" "$AUDIT_RULES" 2>/dev/null; then
            install -m 640 -o root -g root "$PROFILE_SRC/audit.rules" "$AUDIT_RULES" \
                && augenrules --load >/dev/null 2>&1 && changed=1
        fi
        systemctl enable --now auditd >/dev/null 2>&1 || true
    fi
    [[ $changed -eq 1 ]] && log "host profile applied (wodle scripts + auditd rules=$(auditctl -l 2>/dev/null | grep -c audit-wazuh))"
    return 0
}

# --- idempotency: already enrolled + connected? ----------------------------
if [[ -s /var/ossec/etc/client.keys && -x /var/ossec/bin/wazuh-control ]]; then
    ensure_host_profile
    if [[ -f "$STATE" ]] && grep -q "status='connected'" "$STATE" 2>/dev/null; then
        log "already installed + connected as '$AGENT_NAME' -> $WAZUH_MANAGER -- nothing to do"
        exit 0
    fi
    log "installed but not connected -- will re-ensure config + service"
fi

# --- reachability preflight (fail-soft) ------------------------------------
if ! timeout 6 bash -c "echo > /dev/tcp/${WAZUH_MANAGER}/1514" 2>/dev/null; then
    log "WARN manager ${WAZUH_MANAGER}:1514 unreachable -- Tailscale ACL/NSG not ready? Skipping this run; next update.sh retries."
    exit 0
fi

# --- install repo + package (first time only) ------------------------------
if ! dpkg -s wazuh-agent >/dev/null 2>&1; then
    KEYRING=/usr/share/keyrings/wazuh.gpg
    if [[ ! -s "$KEYRING" ]]; then
        if ! curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
             | gpg --no-default-keyring --keyring "gnupg-ring:$KEYRING" --import 2>/dev/null; then
            log "WARN could not import Wazuh GPG key -- skipping this run"; exit 0
        fi
        chmod 644 "$KEYRING"
    fi
    echo "deb [signed-by=$KEYRING] https://packages.wazuh.com/${WAZUH_APT}/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list
    apt-get update >/dev/null 2>&1 || true
    if ! WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" \
         WAZUH_AGENT_GROUP="$WAZUH_GROUPS" \
         apt-get install -y wazuh-agent >/dev/null 2>&1; then
        log "WARN wazuh-agent install failed -- next update.sh retries"; exit 0
    fi
    # Pin the agent: the weekly full-upgrade timer must not bump it past the
    # manager (agent newer than manager is unsupported). Bump deliberately
    # WITH the manager (apt-mark unhold; apt install; apt-mark hold).
    apt-mark hold wazuh-agent >/dev/null 2>&1 || true
    log "installed wazuh-agent (manager=$WAZUH_MANAGER name=$AGENT_NAME groups=$WAZUH_GROUPS, held)"
fi

# --- host integration: docker group + remote commands ----------------------
# docker-host group runs a docker-listener wodle; the wazuh user needs docker
# group membership to read the socket. remote_commands=1 is required for the
# apt-update wodles the raspberry-pi/default groups push.
if getent group docker >/dev/null 2>&1 && ! id -nG wazuh 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    usermod -aG docker wazuh 2>/dev/null && log "added wazuh user to docker group"
fi
LIO=/var/ossec/etc/local_internal_options.conf
if [[ -f "$LIO" ]] && ! grep -q '^wazuh_command.remote_commands=1' "$LIO" 2>/dev/null; then
    echo 'wazuh_command.remote_commands=1' >> "$LIO"
    log "enabled wazuh_command.remote_commands"
fi
ensure_host_profile

# Repair path: if the agent was installed earlier but never enrolled (no
# client.keys), make sure the manager address is set before (re)starting so
# authd enrolment can proceed.
if [[ ! -s /var/ossec/etc/client.keys && -f /var/ossec/etc/ossec.conf ]]; then
    if ! grep -q "<address>${WAZUH_MANAGER}</address>" /var/ossec/etc/ossec.conf 2>/dev/null; then
        sed -i -E "0,/<address>[^<]*<\/address>/s//<address>${WAZUH_MANAGER}<\/address>/" \
            /var/ossec/etc/ossec.conf 2>/dev/null \
            && log "set manager address to ${WAZUH_MANAGER} in ossec.conf"
    fi
fi

# --- enable + start + verify -----------------------------------------------
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable wazuh-agent >/dev/null 2>&1 || true
systemctl restart wazuh-agent >/dev/null 2>&1 || true

for _ in $(seq 1 15); do
    if grep -q "status='connected'" "$STATE" 2>/dev/null; then
        log "OK agent '$AGENT_NAME' connected to $WAZUH_MANAGER"; exit 0
    fi
    sleep 2
done
log "WARN agent '$AGENT_NAME' not 'connected' 30s after start -- check manager enrolment / NSG. Non-fatal; retries next run."
exit 0
