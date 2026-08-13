#!/usr/bin/env bash
# enable-rf-radio.sh — host-heal: ensure the Wi-Fi sensing radio is admin-UP.
#
# d2-agent does passive RF sensing (ap_scan over wlan0) but deliberately does
# NOT bring the radio up itself — wlan0 must already be unblocked + admin-UP on
# the host. That enablement was a manual per-Pi step at imaging and was never
# captured in this repo, so individual sites ship with the radio soft-rfkill-
# blocked: wlan0 stays admin-DOWN, every ap_scan returns ENETDOWN ("Network is
# down (-100)"), the cycle fails, and a standing sensor_health/major incident
# opens on the controller. Seen on nib001-mu-pi01 (2026-06-04) and
# ncm001-bc-pi01 (2026-06-15).
#
# Idempotent and PASSIVE-only: enables the radio and brings wlan0 admin-UP. It
# NEVER associates to an SSID — association is the active-mode hazard that can
# seize a production wlan0 (see SENSOR_MODE in .env.template). No-op on wired-
# only Pis (no wireless interface), so it is safe to run fleet-wide on every
# update. It cannot clear a HARD rfkill block or revive absent/dead hardware —
# those need hands on the device.
set -euo pipefail
LOG_TAG=enable-rf-radio
log() { logger -t "$LOG_TAG" -- "$*" 2>/dev/null || true; echo "  rf-radio: $*"; }

# Gate: act only on Pis that actually have a wireless interface.
iface=""
for w in /sys/class/net/*/wireless; do
    [[ -e "$w" ]] || continue
    iface="$(basename "$(dirname "$w")")"
    break
done
[[ -z "$iface" ]] && exit 0   # wired-only Pi — nothing to do

# 1. Clear a soft rfkill block if the rfkill tool is present (NM also clears
#    this via step 2; best-effort for hosts without NM-managed wifi).
if command -v rfkill >/dev/null 2>&1 && rfkill list 2>/dev/null | grep -qiE 'Soft blocked: yes'; then
    rfkill unblock wifi >/dev/null 2>&1 && log "cleared wifi soft-block (rfkill)" || true
fi

# 2. Ensure NetworkManager has wireless enabled (persists across reboot; brings
#    wlan0 managed + admin-UP without associating to any SSID).
if command -v nmcli >/dev/null 2>&1 && [[ "$(nmcli radio wifi 2>/dev/null)" != "enabled" ]]; then
    nmcli radio wifi on >/dev/null 2>&1 && log "enabled radio (nmcli radio wifi on)" || true
fi

# 3. Fallback: bring the link admin-UP directly if it still isn't (covers the
#    NM-unmanaged case). ENETDOWN on ap_scan comes from a missing IFF_UP flag.
if ! ip link show "$iface" 2>/dev/null | grep -qw UP; then
    ip link set "$iface" up 2>/dev/null && log "brought $iface admin-UP (ip link)" || true
fi

exit 0
