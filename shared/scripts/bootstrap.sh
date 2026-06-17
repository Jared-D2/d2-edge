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
# Validate: lowercase letters / digits / hyphens, must start+end alnum, <=63 chars.
# Rejects empty input and accidental paste of command syntax.
HOSTNAME_RE='^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$'
while true; do
    read -rp "  Enter hostname for this Pi (e.g. d2-customer-site01): " NEW_HOSTNAME </dev/tty
    if [[ "$NEW_HOSTNAME" =~ $HOSTNAME_RE ]]; then
        break
    fi
    echo "  Invalid. Must be lowercase letters/digits/hyphens, <=63 chars (e.g. d2001-nw-pi01)."
done
OLD_HOSTNAME=$(hostname)
hostnamectl set-hostname "${NEW_HOSTNAME}"
# /etc/hosts: replace the 127.0.1.1 line so sudo does not log
# 'unable to resolve host' on every call.
if grep -q "^127\.0\.1\.1" /etc/hosts; then
    sed -i "s|^127\.0\.1\.1.*|127.0.1.1 ${NEW_HOSTNAME}|" /etc/hosts
else
    echo "127.0.1.1 ${NEW_HOSTNAME}" >> /etc/hosts
fi
echo "  Hostname: ${OLD_HOSTNAME} -> ${NEW_HOSTNAME} (also in /etc/hosts)"

# ─── System update ────────────────────────────────────────────────────────
echo ""
echo "[2/8] Updating system packages + removing desktop bloat..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
# Remove desktop browsers — not needed on a headless edge appliance.
# Keeps the SD card lean and shrinks the attack surface.
DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq     chromium chromium-common chromium-l10n chromium-sandbox     firefox firefox-esr 2>/dev/null || true
DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq --purge 2>/dev/null || true
echo "  OK"

# ─── Install dependencies ─────────────────────────────────────────────────
echo ""
echo "[3/8] Installing dependencies..."
apt-get install -y -qq     curl git nano chrony logrotate ca-certificates     gnupg lsb-release apt-transport-https     ufw fail2ban unattended-upgrades     snmp lldpd
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

# ── Source-scoped ingress ────────────────────────────────────────────────
# Nothing is exposed to "Anywhere". Every service is pinned to a trusted
# source zone so a hostile upstream (the customer WAN side, a misrouted
# public range) can't reach SSH or the device-facing collectors. Two zones:
#   TAILNET  — the Tailscale overlay (CGNAT 100.64.0.0/10). Admin + Pi<->Pi.
#   RFC1918  — the local customer LAN this appliance sits on. Device-facing.
# Most ports are both admin- and device-facing, so they take both zones.
# Carve-outs:
#   5201/iperf3 — TAILNET ONLY (Pi-to-Pi throughput tests over the overlay;
#                 never needs to answer a customer-LAN device).
#   10021/Auvik — RFC1918 ONLY (FTP/21 remapped to 10021; device-facing
#                 config/firmware backup push, no admin/tailnet need).
# scripts/heal-firewall.sh mirrors these EXACT rules additively onto
# already-deployed Pis (Phase A) — keep the two in sync. IPv4 CIDRs mean no
# "(v6)" rule twins, which dovetails with scripts/disable-ipv6.sh.
TAILNET=(100.64.0.0/10)
RFC1918=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)
DEVICE_FACING=("${TAILNET[@]}" "${RFC1918[@]}")

# allow_scoped <port> <proto|any> <comment> <src>...
# Emits one `ufw allow from <src> to any port <port> [proto <proto>]` per src.
allow_scoped() {
    local port="$1" proto="$2" comment="$3"; shift 3
    local src
    for src in "$@"; do
        if [[ "$proto" == "any" ]]; then
            ufw allow from "$src" to any port "$port" \
                comment "$comment" >/dev/null
        else
            ufw allow from "$src" to any port "$port" proto "$proto" \
                comment "$comment" >/dev/null
        fi
    done
}

# Admin + device-facing services: tailnet + local LAN.
allow_scoped 22   tcp 'SSH'                          "${DEVICE_FACING[@]}"
allow_scoped 514  any 'Syslog'                       "${DEVICE_FACING[@]}"
allow_scoped 1812 udp 'RADIUS auth'                  "${DEVICE_FACING[@]}"
allow_scoped 1813 udp 'RADIUS acct'                  "${DEVICE_FACING[@]}"
# cert-server onboarding + RadSec. Supersedes the old hardcoded
# 192.168.0.0/16-only rules (REVIEW.md C6) — tailnet+RFC1918 also covers
# 10.x / 172.16.x sites that the /16 rule firewalled out.
allow_scoped 80   tcp 'cert-server (LAN onboarding)' "${DEVICE_FACING[@]}"
allow_scoped 2083 tcp 'RadSec from customer devices' "${DEVICE_FACING[@]}"
# Flow telemetry ingress. 2055/6343/4739 -> netflow-proxy relay (nginx stream,
# host network) -> central goflow2 (NETFLOW_COLLECTOR_HOST); all three MUST be
# open or non-NetFlow exporters are dropped before reaching the relay.
# 9995/9996 are Auvik TrafficInsights' own ports. .env isn't populated yet at
# this point, so these open unconditionally; the netflow-proxy profile gate is
# applied by the update.sh heal.
allow_scoped 2055 udp 'Flow: NetFlow -> netflow-proxy relay'  "${DEVICE_FACING[@]}"
allow_scoped 6343 udp 'Flow: sFlow -> netflow-proxy relay'    "${DEVICE_FACING[@]}"
allow_scoped 4739 udp 'Flow: IPFIX -> netflow-proxy relay'    "${DEVICE_FACING[@]}"
allow_scoped 9995 udp 'Flow: Auvik TrafficInsights (NetFlow)' "${DEVICE_FACING[@]}"
allow_scoped 9996 udp 'Flow: Auvik TrafficInsights (sFlow)'   "${DEVICE_FACING[@]}"
# iperf3 — CARVE-OUT: TAILNET ONLY.
allow_scoped 5201 tcp 'iperf3 P2P (tailnet only)'    "${TAILNET[@]}"
# Auvik FTP-backup ingress (FTP/21 -> 10021) — CARVE-OUT: RFC1918 ONLY.
allow_scoped 10021 tcp 'Auvik FTP-backup (RFC1918)'  "${RFC1918[@]}"

echo "y" | ufw enable >/dev/null
echo "  UFW: enabled, source-scoped (tailnet + RFC1918; iperf=tailnet, Auvik=RFC1918)"

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
for svc in rpcbind.service rpcbind.socket nfs-blkmap.service            cups.service cups-browsed.service cups.socket cups.path            ModemManager.service avahi-daemon.service avahi-daemon.socket            lightdm.service bluetooth.service hciuart.service; do
    systemctl disable --now "$svc" 2>/dev/null || true
done
echo "  Disabled: rpcbind, NFS, CUPS, ModemManager, avahi, lightdm"

# Unattended upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1
# Auto-reboot drop-in placeholder — repo isn't cloned yet, so the real
# install happens after [7/8]. We just record intent here; the post-clone
# block below copies shared/files/52-d2-auto-reboot.conf in place.
echo "  Unattended upgrades: enabled (auto-reboot installed post-clone)"

# Mark /opt/d2-edge safe for the admin user's git — without this,
# update.sh (runs `sudo -u admin git pull`) fails with 'dubious ownership'
# because the repo may have mixed root/admin file ownership.
sudo -u admin git config --global --add safe.directory /opt/d2-edge 2>/dev/null || true

# ─── Clone repo ───────────────────────────────────────────────────────────
echo ""
echo "[7/8] Cloning d2-edge repo..."
if [[ -d "${EDGE_DIR}/.git" ]]; then
    echo "  Repo already exists, pulling latest..."
    cd "${EDGE_DIR}" && git pull
else
    git clone "${REPO_GIT}" "${EDGE_DIR}"
fi

# Repo cloned as root; chown everything to admin so update.sh (git pull
# runs as admin) can write .git state. Keep .env at root:root 600 — secrets.
chown -R admin:admin "${EDGE_DIR}"
[[ -f "${EDGE_DIR}/.env" ]] && chown root:root "${EDGE_DIR}/.env" && chmod 600 "${EDGE_DIR}/.env"

# Install auto-reboot drop-in now that the repo content is available.
# Higher-numbered drop-in (52 vs stock 50) wins over distro defaults.
DROPIN_SRC="${EDGE_DIR}/shared/files/52-d2-auto-reboot.conf"
if [[ -f "$DROPIN_SRC" ]]; then
    install -m 0644 -o root -g root "$DROPIN_SRC" /etc/apt/apt.conf.d/52-d2-auto-reboot
    echo "  Auto-reboot policy: 02:00 nightly when reboot-required (52-d2-auto-reboot)"
fi

# Scope LLDP to the physical uplink only. Default lldpd advertises on every
# interface (wlan0, docker bridges, tailscale0) — none of which connect to a
# managed switch, so the noise is wasted and confuses topology mappers.
LLDPD_CONF_SRC="${EDGE_DIR}/shared/files/lldpd-eth0-only.conf"
if [[ -f "$LLDPD_CONF_SRC" ]]; then
    mkdir -p /etc/lldpd.d
    install -m 0644 -o root -g root "$LLDPD_CONF_SRC" /etc/lldpd.d/eth0-only.conf
    systemctl enable lldpd >/dev/null 2>&1 || true
    systemctl restart lldpd
    echo "  LLDP: scoped to eth0 (lldpd-eth0-only.conf)"
fi

# Provision the Oxidized bastion user (svc_oxidized_proxy, nologin shell,
# locked authorized_keys). Idempotent — safe to run on every bootstrap.
if [[ -x "${EDGE_DIR}/scripts/setup-oxidized-proxy-user.sh" ]]; then
    bash "${EDGE_DIR}/scripts/setup-oxidized-proxy-user.sh"
fi


# ─── Log rotation ─────────────────────────────────────────────────────────
cat > /etc/logrotate.d/d2-edge-syslog << 'LOGROTATE'
/opt/d2-edge/syslog-proxy/logs/*/*/*.log {
    daily
    rotate 7
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

# Persist this host's docker group GID into .env so `docker compose` reads
# it natively. Without this, compose would fall back to the pinned default
# and zabbix-agent2's Docker plugin would silently fail on any Pi whose
# docker group GID differs.
DOCKER_GID_ACTUAL=$(getent group docker | cut -d: -f3)
if [[ -n "$DOCKER_GID_ACTUAL" ]]; then
    if grep -q "^DOCKER_GID=" "${EDGE_DIR}/.env"; then
        sed -i "s|^DOCKER_GID=.*|DOCKER_GID=${DOCKER_GID_ACTUAL}|" "${EDGE_DIR}/.env"
    else
        echo "DOCKER_GID=${DOCKER_GID_ACTUAL}" >> "${EDGE_DIR}/.env"
    fi
    echo "  DOCKER_GID=${DOCKER_GID_ACTUAL} persisted to .env"
fi

# Seed current git SHA so d2-agent can report the running code version.
SHA=$(git -C "${EDGE_DIR}" rev-parse HEAD 2>/dev/null || echo "unknown")
if grep -q '^GIT_SHA=' "${EDGE_DIR}/.env" 2>/dev/null; then
    sed -i "s|^GIT_SHA=.*|GIT_SHA=${SHA}|" "${EDGE_DIR}/.env"
else
    echo "GIT_SHA=${SHA}" >> "${EDGE_DIR}/.env"
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
