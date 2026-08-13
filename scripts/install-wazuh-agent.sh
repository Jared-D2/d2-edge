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
set -uo pipefail   # deliberately NOT -e: soft-fail on network/apt hiccups

EDGE_DIR="${EDGE_DIR:-/opt/d2-edge}"
ENV_FILE="$EDGE_DIR/.env"
WAZUH_MANAGER_DEFAULT="10.255.255.28"
WAZUH_GROUPS="raspberry-pi,docker-host"
WAZUH_APT="4.x"
STATE=/var/ossec/var/run/wazuh-agentd.state
log() { echo "[wazuh] $*"; }

if [[ $EUID -ne 0 ]]; then log "must run as root -- skipping" >&2; exit 0; fi

# env_get from the shared lib (compose-dotenv semantics; reads $ENV_FILE).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/shared/scripts/lib/envfile.sh"

# --- gate ------------------------------------------------------------------
DEPLOY_WAZUH="$(env_get DEPLOY_WAZUH)"; DEPLOY_WAZUH="${DEPLOY_WAZUH:-enabled}"
if [[ "$DEPLOY_WAZUH" != "enabled" ]]; then
    log "DEPLOY_WAZUH='$DEPLOY_WAZUH' (not 'enabled') -- skipping"; exit 0
fi

WAZUH_MANAGER="$(env_get WAZUH_MANAGER)"; WAZUH_MANAGER="${WAZUH_MANAGER:-$WAZUH_MANAGER_DEFAULT}"
AGENT_NAME="$(env_get EDGE_HOSTNAME)"
if [[ -z "$AGENT_NAME" || "$AGENT_NAME" == "REPLACE_ME" ]]; then AGENT_NAME="$(hostname)"; fi

# --- idempotency: already enrolled + connected? ----------------------------
if [[ -s /var/ossec/etc/client.keys && -x /var/ossec/bin/wazuh-control ]]; then
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
