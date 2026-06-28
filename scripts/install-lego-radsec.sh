#!/usr/bin/env bash
# Self-arms the lego RadSec cert scaffolding on this Pi. Idempotent + fleet-safe.
# The Pi gets NO cert until its key is registered with acme-hook (gated Ansible
# enrollment); until then the renew timer is a clean no-op. CERT_NAME defaults to
# <EDGE_HOSTNAME>.internal.d2tech.com.au, overridable via LEGO_RADSEC_CERT_NAME in .env.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)" >&2; exit 1; }
EDGE=/opt/d2-edge; S="$EDGE/scripts"; F="$EDGE/shared/files"; SBIN=/usr/local/sbin
[ -f "$EDGE/.env" ] && { set -a; . "$EDGE/.env"; set +a; }

command -v lego >/dev/null 2>&1 || { apt-get update -qq; apt-get install -y -qq lego; }

if [[ -f "$F/d2tech-internal-root.crt" ]] && \
   ! cmp -s "$F/d2tech-internal-root.crt" /usr/local/share/ca-certificates/d2tech-internal-root.crt 2>/dev/null; then
  install -m 0644 "$F/d2tech-internal-root.crt" /usr/local/share/ca-certificates/d2tech-internal-root.crt
  update-ca-certificates >/dev/null
fi

install -d -m 0700 /etc/lego
[[ -f /etc/lego/ssh_id ]] || ssh-keygen -t ed25519 -N '' -C "lego-dns-hook@$(hostname)" -f /etc/lego/ssh_id >/dev/null

for f in lego-dns-exec.sh lego-radsec-deploy.sh lego-radsec-renew.sh lego-radsec-enroll.sh; do
  install -m 0755 "$S/$f" "$SBIN/$f"
done

CERT_NAME="${LEGO_RADSEC_CERT_NAME:-${EDGE_HOSTNAME:-$(hostname)}.internal.d2tech.com.au}"
printf 'CERT_NAME=%s\n' "$CERT_NAME" > /etc/lego/radsec.env
chmod 0644 /etc/lego/radsec.env

for f in lego-radsec.service lego-radsec.timer; do
  install -m 0644 "$S/$f" /etc/systemd/system/"$f"
done
systemctl daemon-reload
systemctl enable --now lego-radsec.timer >/dev/null

# UFW: let the on-site switch fetch the root CA (:80) and open RadSec (:2083).
# bootstrap.sh sets these on fresh Pis; re-assert here so already-deployed Pis
# pick them up via update.sh (idempotent; LAN-scoped). See feedback_pi_radsec_cert_lego_hygiene.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow from 192.168.0.0/16 to any port 80 proto tcp comment 'cert-server (LAN onboarding)' >/dev/null
  ufw allow from 192.168.0.0/16 to any port 2083 proto tcp comment 'RadSec from customer devices' >/dev/null
fi
echo "lego-radsec scaffolding installed (CERT_NAME=$CERT_NAME)."
