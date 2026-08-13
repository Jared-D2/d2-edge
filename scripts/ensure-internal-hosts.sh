#!/usr/bin/env bash
# Idempotently pins the internal CA/DNS name in /etc/hosts so lego can resolve
# step-ca (edge Pis can't reach CoreDNS on :53). cloud-init manage_etc_hosts=true
# regenerates /etc/hosts from a template on boot, so we also add it there.
# Missing pin => lego RadSec renewal fails silently and the cert expires.
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run as root (sudo)" >&2; exit 1; fi
PIN='10.255.255.244 ca.internal.d2tech.com.au dns.internal.d2tech.com.au'
NAME='ca.internal.d2tech.com.au'
TMPL=/etc/cloud/templates/hosts.debian.tmpl
grep -qF "$NAME" /etc/hosts || printf '%s\n' "$PIN" >> /etc/hosts
if [[ -f "$TMPL" ]] && ! grep -qF "$NAME" "$TMPL"; then
  printf '\n# D2 internal CA/DNS pin (lego needs this; CoreDNS unreachable on :53)\n%s\n' "$PIN" >> "$TMPL"
fi
