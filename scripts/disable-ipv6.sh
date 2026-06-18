#!/usr/bin/env bash
# Idempotent IPv6 disable for the D2 edge appliance.
#
# Installs the sysctl drop-in, applies it live (no reboot), confirms IPv6 is
# actually down on the LAN uplink, and ONLY THEN sets IPV6=no in
# /etc/default/ufw + reloads UFW so it stops emitting "(v6)" rule twins.
#
# WHY: the stack is IPv4-only — every internal/platform endpoint is IPv4
# (10.255.255.x, 192.168.166.8) and the appliance is outbound-only. With IPv6
# up, UFW emits an "Anywhere (v6)" twin for every "Anywhere" allow rule (SSH
# 22, syslog 514, RADIUS 1812/1813, iperf3 5201, Auvik 10021, flow
# 2055/6343/4739/9995/9996), so those services also listen on / are reachable
# over IPv6. See shared/files/99-disable-ipv6.conf.
#
# SAFETY: additive + ordered. We NEVER `ufw reset`/`disable` (SSH-lockout
# risk — has locked us out of fleet Pis before). UFW's IPV6=no is flipped ONLY
# after the kernel confirms IPv6 is disabled on eth0, so we never leave an
# unfiltered v6 listener behind. Re-running on an already-disabled Pi is a
# no-op. Tolerates per-interface sysctl keys whose interface is absent.
set -euo pipefail

EDGE_DIR="${EDGE_DIR:-/opt/d2-edge}"
DROPIN_SRC="$EDGE_DIR/shared/files/99-disable-ipv6.conf"
DROPIN_DST=/etc/sysctl.d/99-disable-ipv6.conf
UFW_DEFAULTS=/etc/default/ufw

if [[ $EUID -ne 0 ]]; then echo "[disable-ipv6] must run as root" >&2; exit 1; fi
[[ -f "$DROPIN_SRC" ]] || { echo "[disable-ipv6] $DROPIN_SRC missing; skip"; exit 0; }

# 1. Install/refresh the persistent drop-in (survives reboot).
if [[ ! -f "$DROPIN_DST" ]] || ! cmp -s "$DROPIN_SRC" "$DROPIN_DST"; then
    install -m 0644 -o root -g root "$DROPIN_SRC" "$DROPIN_DST"
    echo "[disable-ipv6] installed/updated $DROPIN_DST"
fi

# 2. Apply live (no reboot). Writing disable_ipv6=1 flushes v6 addresses
#    immediately. Apply each key from the drop-in with `|| true` so a missing
#    interface (e.g. a Pi with no wlan0) can't abort under `set -e`.
grep -E '^[[:space:]]*net\.ipv6\.' "$DROPIN_DST" | sed -E 's/[[:space:]]+//g' \
  | while read -r kv; do
        [[ -n "$kv" ]] && sysctl -w "$kv" >/dev/null 2>&1 || true
    done || true
# Reload the full sysctl.d tree too so state is consistent; tolerate warnings.
sysctl --system >/dev/null 2>&1 || true

# 3. Confirm IPv6 is actually down on the primary LAN uplink BEFORE touching
#    UFW. eth0 is the Pi 5 built-in ethernet and is always present. Ground
#    truth = no inet6 address on eth0 (disable_ipv6=1 strips even link-local),
#    which holds for BOTH the global and per-interface drop-in variants.
ipv6_down_eth0() {
    [[ ! -e /sys/class/net/eth0 ]] && return 0   # no eth0 -> nothing to guard
    ! ip -6 addr show dev eth0 2>/dev/null | grep -q 'inet6'
}
if ! ipv6_down_eth0; then
    echo "[disable-ipv6] WARN: IPv6 still up on eth0 after apply — leaving UFW IPV6 setting untouched (no unfiltered v6 listener risk)" >&2
    exit 0
fi
echo "[disable-ipv6] IPv6 confirmed disabled on eth0"

# 4. Stop UFW emitting v6 rule twins. Idempotent sed + SAFE reload (not reset).
if grep -qE '^[[:space:]]*IPV6=yes' "$UFW_DEFAULTS"; then
    sed -i 's/^[[:space:]]*IPV6=yes/IPV6=no/' "$UFW_DEFAULTS"
    echo "[disable-ipv6] set IPV6=no in $UFW_DEFAULTS"
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw reload >/dev/null 2>&1 || true
        echo "[disable-ipv6] reloaded UFW (v6 twins removed)"
    fi
elif ! grep -qE '^[[:space:]]*IPV6=' "$UFW_DEFAULTS"; then
    echo "IPV6=no" >> "$UFW_DEFAULTS"
    echo "[disable-ipv6] appended IPV6=no to $UFW_DEFAULTS"
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw reload >/dev/null 2>&1 || true
        echo "[disable-ipv6] reloaded UFW (v6 twins removed)"
    fi
else
    echo "[disable-ipv6] $UFW_DEFAULTS already IPV6=no"
fi

echo "[disable-ipv6] OK"
