#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/opt/d2-edge/.env"
EDGE_DIR="/opt/d2-edge"

# Docker group GID varies per host install — resolve at deploy time
# so zabbix-agent2's group_add matches this Pi's actual docker group.
export DOCKER_GID=$(getent group docker | cut -d: -f3)
if [[ -z "$DOCKER_GID" ]]; then
    echo "ERROR: host 'docker' group not found. Is Docker installed?" >&2
    exit 1
fi

echo "========================================"
echo " D2 Edge Appliance � Deploy"
echo "========================================"

# --- Load and validate .env -----------------------------------------------
echo ""
echo "[1/6] Validating .env..."
# Stamp current git SHA into .env so d2-agent reports the running code version
if [[ -d "$EDGE_DIR/.git" ]]; then
    SHA=$(git -C "$EDGE_DIR" rev-parse HEAD 2>/dev/null || echo "unknown")
    if grep -q '^GIT_SHA=' "$ENV_FILE" 2>/dev/null; then
        sed -i "s|^GIT_SHA=.*|GIT_SHA=${SHA}|" "$ENV_FILE"
    else
        echo "GIT_SHA=${SHA}" >> "$ENV_FILE"
    fi
fi
source "$ENV_FILE"

bash "$EDGE_DIR/shared/scripts/preflight.sh"
echo "  OK"

# --- NTP sync check -------------------------------------------------------
echo ""
echo "[2/6] Checking time sync..."
if chronyc tracking &>/dev/null; then
    OFFSET=$(chronyc tracking | grep "System time" | awk '{print $4}')
    echo "  OK � offset: ${OFFSET}s"
else
    echo "  WARNING: chrony not running � time may be unreliable"
fi

# --- Start Tailscale first ------------------------------------------------
echo ""
echo "[3/6] Starting Tailscale..."
cd "$EDGE_DIR"
docker compose up -d tailscale

echo "  Waiting for Tailscale to authenticate..."
for i in $(seq 1 24); do
    sleep 5
    TSIP=$(docker exec tailscale tailscale ip -4 2>/dev/null | head -1 || true)
    if [[ -n "$TSIP" ]]; then
        echo "  OK � Tailscale IP: $TSIP"
        break
    fi
    echo "  Waiting... ($((i*5))s)"
    if [[ $i -eq 24 ]]; then
        echo "  ERROR: Tailscale did not authenticate after 120s"
        exit 1
    fi
done

# --- Render configs -------------------------------------------------------
echo ""
echo "[4/6] Rendering configs..."
bash "$EDGE_DIR/render-configs.sh"
echo "  OK"

# --- Ensure directories exist with correct permissions --------------------
echo ""
echo "[5/6] Starting remaining containers..."
mkdir -p "$EDGE_DIR"/{syslog-proxy/{config,logs,state},zabbix-proxy/{config,data,logs},freeradius-proxy/config/{templates,rendered},auvik/{config,etc,logs}}
chown -R 1997:1997 "$EDGE_DIR/zabbix-proxy/data" 2>/dev/null || true
chown -R 1997:1997 "$EDGE_DIR/zabbix-proxy/logs" 2>/dev/null || true
docker compose up -d
echo "  OK"

# --- Validate connectivity ------------------------------------------------
echo ""
echo "[6/6] Validating connectivity..."
sleep 10

# Actual service ports, not ICMP — ICMP is often blocked even when the
# real TCP/UDP ports work (misleading FAIL was the #1 confusion in the
# NIB dummy deploy).
check_tcp() {
    local host="$1" port="$2" name="$3"
    if timeout 3 bash -c "</dev/tcp/$host/$port" 2>/dev/null; then
        echo "  $name ($host:$port/tcp): OK"
    else
        echo "  $name ($host:$port/tcp): FAIL"
    fi
}
check_tcp "$GRAYLOG_HOST"       12203 "Graylog GELF relay"
check_tcp "$ZABBIX_SERVER_HOST" "$ZABBIX_SERVER_PORT" "Zabbix server"
# RADIUS is UDP — TCP check would always fail. Use netcat if available,
# else fall back to a Tailscale peer ping as the only sensible signal.
if command -v nc >/dev/null 2>&1; then
    if timeout 3 nc -uzw2 "$RADIUS_HOME_SERVER" 1812 2>/dev/null; then
        echo "  RADIUS ($RADIUS_HOME_SERVER:1812/udp): probed"
    else
        echo "  RADIUS ($RADIUS_HOME_SERVER:1812/udp): probed (UDP is connectionless, may show fail even when working)"
    fi
else
    if docker exec tailscale tailscale ping -c1 "$RADIUS_HOME_SERVER" &>/dev/null; then
        echo "  RADIUS ($RADIUS_HOME_SERVER): Tailscale-reachable"
    else
        echo "  RADIUS ($RADIUS_HOME_SERVER): Tailscale NOT reachable"
    fi
fi

echo ""
echo "[Perms] Tightening secrets written at runtime..."
# Auvik config files are written on first container run; tighten after.
for f in "$EDGE_DIR/auvik/config/agent.conf" "$EDGE_DIR/auvik/config/extra.conf"; do
    [[ -f "$f" ]] && chmod 600 "$f"
done
# RadSec private key (if provisioned out-of-band into the certs dir)
[[ -f "$EDGE_DIR/freeradius-proxy/certs/radsec.key" ]] && \
    chmod 600 "$EDGE_DIR/freeradius-proxy/certs/radsec.key"
echo "  OK"

echo ""
echo "========================================"
echo " Deploy complete"
echo " Hostname : $EDGE_HOSTNAME"
echo " Tenant   : $TENANT_ID ($TENANT_NAME)"
echo " Site     : $EDGE_SITE_ID"
echo " Tailscale: $TSIP"
echo "========================================"