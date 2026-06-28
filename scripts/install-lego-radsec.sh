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
echo "lego-radsec scaffolding installed (CERT_NAME=$CERT_NAME)."
