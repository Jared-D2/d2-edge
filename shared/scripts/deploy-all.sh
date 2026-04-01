#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/opt/d2-edge/.env"
EDGE_DIR="/opt/d2-edge"

echo "========================================"
echo " D2 Edge Appliance — Deploy"
echo "========================================"

# ─── Load and validate .env ───────────────────────────────────────────────
echo ""
echo "[1/6] Validating .env..."
source "$ENV_FILE"

REQUIRED=(
    EDGE_HOSTNAME EDGE_SITE_ID TZ
    TENANT_ID TENANT_NAME ENVIRONMENT
    TS_AUTHKEY
    GRAYLOG_HOST GRAYLOG_PORT
    ZABBIX_SERVER_HOST ZABBIX_SERVER_PORT
    RADIUS_HOME_SERVER
    RADIUS_SHARED_SECRET LOCAL_CLIENT_SECRET LOCAL_CLIENT_SUBNET AUVIK_USERNAME AUVIK_API_KEY AUVIK_DOMAIN_PREFIX
)

MISSING=0
for VAR in "${REQUIRED[@]}"; do
    VAL="${!VAR:-}"
    if [[ -z "$VAL" || "$VAL" == "REPLACE_ME" ]]; then
        echo "  ERROR: $VAR is not set"
        MISSING=1
    fi
done
[[ $MISSING -eq 1 ]] && { echo "Fix .env and re-run."; exit 1; }
echo "  OK"

# ─── NTP sync check ───────────────────────────────────────────────────────
echo ""
echo "[2/6] Checking time sync..."
if chronyc tracking &>/dev/null; then
    OFFSET=$(chronyc tracking | grep "System time" | awk '{print $4}')
    echo "  OK — offset: ${OFFSET}s"
else
    echo "  WARNING: chrony not running — time may be unreliable"
fi

# ─── Start Tailscale first ────────────────────────────────────────────────
echo ""
echo "[3/6] Starting Tailscale..."
cd "$EDGE_DIR"
docker compose up -d tailscale

echo "  Waiting for Tailscale to authenticate..."
for i in $(seq 1 24); do
    sleep 5
    TSIP=$(docker exec tailscale tailscale ip -4 2>/dev/null | head -1 || true)
    if [[ -n "$TSIP" ]]; then
        echo "  OK — Tailscale IP: $TSIP"
        break
    fi
    echo "  Waiting... ($((i*5))s)"
    if [[ $i -eq 24 ]]; then
        echo "  ERROR: Tailscale did not authenticate after 120s"
        exit 1
    fi
done

# ─── Render configs ───────────────────────────────────────────────────────
echo ""
echo "[4/6] Rendering configs..."
bash "$EDGE_DIR/syslog-proxy/scripts/render-config.sh"
bash "$EDGE_DIR/zabbix-proxy/scripts/render-config.sh"
bash "$EDGE_DIR/freeradius-proxy/scripts/render-config.sh"
echo "  OK"

# ─── Bring up remaining containers ────────────────────────────────────────
echo ""
echo "[5/6] Starting remaining containers..."
docker compose up -d
echo "  OK"

# ─── Validate connectivity ────────────────────────────────────────────────
echo ""
echo "[6/6] Validating connectivity..."
sleep 10

ping -c1 -W3 "$GRAYLOG_HOST"      &>/dev/null && echo "  Graylog (${GRAYLOG_HOST}): OK"      || echo "  Graylog (${GRAYLOG_HOST}): FAIL"
ping -c1 -W3 "$ZABBIX_SERVER_HOST" &>/dev/null && echo "  Zabbix (${ZABBIX_SERVER_HOST}): OK" || echo "  Zabbix (${ZABBIX_SERVER_HOST}): FAIL"
ping -c1 -W3 "$RADIUS_HOME_SERVER" &>/dev/null && echo "  RADIUS (${RADIUS_HOME_SERVER}): OK" || echo "  RADIUS (${RADIUS_HOME_SERVER}): FAIL"

echo ""
echo "========================================"
echo " Deploy complete"
echo " Hostname : $EDGE_HOSTNAME"
echo " Tenant   : $TENANT_ID ($TENANT_NAME)"
echo " Site     : $EDGE_SITE_ID"
echo " Tailscale: $TSIP"
echo "========================================"
