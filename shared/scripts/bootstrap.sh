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
echo "[1/8] Hostname setup..."
read -rp "  Enter hostname for this Pi (e.g. d2-customer-site01): " NEW_HOSTNAME
hostnamectl set-hostname "${NEW_HOSTNAME}"
echo "  Set to: ${NEW_HOSTNAME}"

# ─── System update ────────────────────────────────────────────────────────
echo ""
echo "[2/8] Updating system packages..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
echo "  OK"

# ─── Install dependencies ─────────────────────────────────────────────────
echo ""
echo "[3/8] Installing dependencies..."
apt-get install -y -qq     curl git nano chrony logrotate ca-certificates     gnupg lsb-release apt-transport-https     ufw fail2ban unattended-upgrades
echo "  OK"

# ─── Install Docker ───────────────────────────────────────────────────────
echo ""
echo "[4/8] Installing Docker..."
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
echo "[5/8] Configuring NTP..."
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

# ─── Security hardening ──────────────────────────────────────────────────
echo ""
echo "[6/8] Applying security hardening..."

# SSH hardening
cat > /etc/ssh/sshd_config.d/hardening.conf << 'SSHCONF'
X11Forwarding no
MaxAuthTries 3
SSHCONF
systemctl reload ssh
echo "  SSH: X11 disabled, MaxAuthTries=3"

# Firewall
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp comment 'SSH' >/dev/null
ufw allow 514 comment 'Syslog' >/dev/null
ufw allow 10051/tcp comment 'Zabbix proxy' >/dev/null
ufw allow 8080/tcp comment 'D2 agent' >/dev/null
ufw allow 10021/tcp comment 'Auvik' >/dev/null
ufw allow 1812/udp comment 'RADIUS auth' >/dev/null
ufw allow 1813/udp comment 'RADIUS acct' >/dev/null
ufw allow 5201/tcp comment 'iperf3 P2P' >/dev/null
ufw allow 9995/udp comment 'Auvik NetFlow' >/dev/null
ufw allow 9996/udp comment 'Auvik sFlow' >/dev/null
echo "y" | ufw enable >/dev/null
echo "  UFW: enabled with service rules"

# fail2ban
cat > /etc/fail2ban/jail.local << 'F2B'
[sshd]
enabled = true
port = ssh
backend = systemd
maxretry = 5
bantime = 3600
findtime = 600
F2B
systemctl enable --now fail2ban >/dev/null 2>&1
echo "  fail2ban: enabled for SSH"

# Disable unnecessary services
for svc in rpcbind.service rpcbind.socket nfs-blkmap.service            cups.service cups-browsed.service cups.socket cups.path            ModemManager.service avahi-daemon.service avahi-daemon.socket            lightdm.service; do
    systemctl disable --now "$svc" 2>/dev/null || true
done
echo "  Disabled: rpcbind, NFS, CUPS, ModemManager, avahi, lightdm"

# Unattended upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1
echo "  Unattended upgrades: enabled"

# ─── Clone repo ───────────────────────────────────────────────────────────
echo ""
echo "[7/8] Cloning d2-edge repo..."
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
mkdir -p "${EDGE_DIR}"/{syslog-proxy/{config,logs,state},zabbix-proxy/{config,data,logs},freeradius-proxy/config/{templates,rendered},auvik/{config,etc,logs},d2-agent,shared/scripts}

# ─── Create .env from template ────────────────────────────────────────────
echo ""
echo "[8/8] Setting up .env..."
if [[ -f "${EDGE_DIR}/.env" ]]; then
    echo "  .env already exists — skipping"
    chmod 600 "${EDGE_DIR}/.env"
else
    cp "${EDGE_DIR}/.env.template" "${EDGE_DIR}/.env"
    chmod 600 "${EDGE_DIR}/.env"
    sed -i "s/^EDGE_HOSTNAME=REPLACE_ME$/EDGE_HOSTNAME=${NEW_HOSTNAME}/" "${EDGE_DIR}/.env"
    echo "  Created from template (chmod 600)"
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
