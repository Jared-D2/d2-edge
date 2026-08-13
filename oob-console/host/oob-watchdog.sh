#!/usr/bin/env bash
# oob-watchdog.sh — runs every 5 min via oob-watchdog.timer.
#
# Non-destructive by design (review 2026-08-13 finding #1): a modem that is
# visible on USB is NEVER PWRKEY'd — a 3 s PWRKEY hold on a running SIM7600
# is power-OFF, permanently, with nothing to turn it back on. PWRKEY is used
# ONLY to power ON a modem that is absent from the USB bus, at most once per
# hour. "Not registered" is a carrier/SIM condition, not a modem wedge, and
# gets no intervention (the old gate keyed on wwan0-has-IP, which the RNDIS
# internal DHCP satisfies even with no SIM).
#
# Ladder: absent from USB → PWRKEY power-on pulse (1/h max)
#         on USB, AT dead  → USB re-authorize reset
#         registered, no data ×3 → AT+CFUN=1,1 ×2 → USB re-authorize reset
set -u
STATE_DIR=/run/d2-oob; mkdir -p "$STATE_DIR"
AT=/usr/local/sbin/oob-at.py
log() { logger -t oob-watchdog "$*"; }

count() { cat "$STATE_DIR/$1" 2>/dev/null || echo 0; }
setc()  { echo "$2" > "$STATE_DIR/$1"; }

modem_usb_dirs() {
    local d
    for d in /sys/bus/usb/devices/*; do
        [[ "$(cat "$d/idVendor" 2>/dev/null)" == "1e0e" ]] && echo "$d"
    done
}

usb_reset() {
    local d
    log "USB re-authorize reset of modem"
    for d in $(modem_usb_dirs); do
        echo 0 > "$d/authorized" 2>/dev/null
        sleep 2
        echo 1 > "$d/authorized" 2>/dev/null
    done
}

# --- 1. modem absent from USB: power-ON pulse, rate-limited --------------
if [[ -z "$(modem_usb_dirs)" ]]; then
    now=$(date +%s)
    if (( now - $(count pwrkey_last) > 3600 )); then
        setc pwrkey_last "$now"
        gpio="${OOB_PWRKEY_GPIO:-6}"
        log "modem absent from USB — PWRKEY power-on pulse (GPIO $gpio)"
        pinctrl set "$gpio" op dh; sleep 3; pinctrl set "$gpio" dl
    fi
    exit 0
fi

# --- 2. on USB but AT dead: USB-level reset (never PWRKEY) ---------------
if [[ ! -e /dev/d2-modem ]] || ! "$AT" AT 2>/dev/null | grep -q OK; then
    setc at_fails "$(( $(count at_fails) + 1 ))"
    (( $(count at_fails) < 2 )) && exit 0   # tolerate a single blip
    setc at_fails 0
    log "modem on USB but AT unresponsive"
    usb_reset
    exit 0
fi
setc at_fails 0

# --- 3. not registered: carrier/SIM side — no intervention ---------------
if ! "$AT" 'AT+CEREG?' 2>/dev/null | grep -qE '\+CEREG: [0-9],[15]'; then
    setc ping_fails 0
    exit 0
fi

# --- 4. registered but no data path: CFUN ×2, then USB reset -------------
if ping -I wwan0 -c 2 -W 5 1.1.1.1 >/dev/null 2>&1; then
    setc ping_fails 0; setc cfun_resets 0
    exit 0
fi
setc ping_fails "$(( $(count ping_fails) + 1 ))"
log "registered but wwan0 ping failure $(count ping_fails)/3"
(( $(count ping_fails) < 3 )) && exit 0
setc ping_fails 0

if (( $(count cfun_resets) < 2 )); then
    setc cfun_resets "$(( $(count cfun_resets) + 1 ))"
    log "soft-resetting modem (AT+CFUN=1,1), attempt $(count cfun_resets)/2"
    "$AT" 'AT+CFUN=1,1' >/dev/null 2>&1
else
    setc cfun_resets 0
    usb_reset
fi
