#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://raw.githubusercontent.com/Jared-D2/d2-edge"
REPO_GIT="https://github.com/Jared-D2/d2-edge.git"
EDGE_DIR="/opt/d2-edge"

echo "========================================"
echo " D2 Edge Appliance — Bootstrap"
echo "========================================"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash bootstrap.sh"
    exit 1
fi

# ─── Hostname ─────────────────────────────────────────────────────────────
echo ""
echo "[1/7] Hostname setup..."
read -rp "  Enter hostname for this Pi (e.g. d2-customer-site01): " NEW_HOSTNAME
hostnamectl set-hostname "${NEW_HOSTNAME}"
echo "  Set to: ${NEW_HOSTNAME}"

# ─── System update ────────────────────────────────────────────────────────
echo ""
echo "[2/7] Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq
echo "  OK"

# ─── Install dependencies ─────────────────────────────────────────────────
echo ""
echo "[3/7] Installing dependencies..."
apt-get install -y -qq \
    curl git nano chrony logrotate ca-certificates \
    gnupg lsb-release apt-transport-https
echo "  OK"

# ─── Install Docker ───────────────────────────────────────────────────────
echo ""
echo "[4/7] Installing Docker..."
if command -v docker &>/dev/null; then
    echo "  Already installed: $(docker --version)"
else
    curl -fsSL https://get.docker.com | sh
    usermod -aG docker admin 2>/dev/null || true
    systemctl enable docker
    systemctl start docker
    echo "  OK: $(docker --version)"
fi

# ─── Configure NTP ────────────────────────────────────────────────────────
echo ""
echo "[5/7] Configuring NTP..."
cat > /etc/chrony/chrony.conf << 'CHRONY'
pool time.cloudflare.com iburst
pool pool.ntp.org iburst
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
CHRONY
systemctl enable chrony
systemctl restart chrony
sleep 3
echo "  OK — $(chronyc tracking | grep 'Reference ID')"

# ─── Clone repo ───────────────────────────────────────────────────────────
echo ""
echo "[6/7] Cloning d2-edge repo..."
if [[ -d "${EDGE_DIR}/.git" ]]; then
    echo "  Repo already exists, pulling latest..."
    cd "${EDGE_DIR}" && git pull
else
    git clone "${REPO_GIT}" "${EDGE_DIR}"
fi

# ─── Log rotation ─────────────────────────────────────────────────────────
cat > /etc/logrotate.d/d2-edge-syslog << 'LOGROTATE'
/opt/d2-edge/syslog-proxy/logs/*/*/*.log {
    daily
    rotate 2
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        docker kill --signal="SIGHUP" syslog-proxy 2>/dev/null || true
    endscript
}
LOGROTATE

# ─── Create required directories ──────────────────────────────────────────
mkdir -p "${EDGE_DIR}"/{syslog-proxy/{config,logs,state},zabbix-proxy/{config,data,logs},freeradius-proxy/config/{templates,rendered},auvik/{config,etc,logs},shared/scripts}

# ─── Create .env from template ────────────────────────────────────────────
echo ""
echo "[7/7] Setting up .env..."
if [[ -f "${EDGE_DIR}/.env" ]]; then
    echo "  .env already exists — skipping"
else
    cp "${EDGE_DIR}/.env.template" "${EDGE_DIR}/.env"
    sed -i "s/^EDGE_HOSTNAME=REPLACE_ME$/EDGE_HOSTNAME=${NEW_HOSTNAME}/" "${EDGE_DIR}/.env"
    echo "  Created from template"
fi

echo ""
echo "========================================"
echo " Bootstrap complete!"
echo ""
echo " Next steps:"
echo "   1. Edit .env with customer details:"
echo "      nano ${EDGE_DIR}/.env"
echo ""
echo "   2. Run the deploy script:"
echo "      sudo bash ${EDGE_DIR}/shared/scripts/deploy-all.sh"
echo "========================================"
