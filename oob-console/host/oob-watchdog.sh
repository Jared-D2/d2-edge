#!/usr/bin/env bash
# oob-watchdog.sh — runs every 5 min via oob-watchdog.timer.
# Two jobs: (1) PROBE the OOB path and record /run/d2-oob/status for the
# zabbix-agent2 UserParameter (oob.status[*]); (2) HEAL, non-destructively.
#
# Non-destructive by design (review 2026-08-13 finding #1): a modem that is
# visible on USB is NEVER PWRKEY'd — a 3 s PWRKEY hold on a running SIM7600
# is power-OFF, permanently. PWRKEY is used ONLY to power ON a modem that
# is absent from the USB bus, at most once per hour. "Not registered" is a
# carrier/SIM condition, not a modem wedge, and gets no intervention.
#
# Heal ladder: absent from USB → PWRKEY power-on pulse (1/h max)
#              on USB, AT dead ×2 → USB recovery ladder (usb_recover)
#              registered, no data ×3 → AT+CFUN=1,1 ×2 → USB recovery ladder
#
# Manual use: `oob-watchdog.sh --usb-recover [--skip-reauth]` runs the same
# USB recovery ladder on demand (operator break-glass; see runbook).
set -u
STATE_DIR=/run/d2-oob; mkdir -p "$STATE_DIR"
AT=/usr/local/sbin/oob-at.py
EDGE_DIR=/opt/d2-edge
log() { logger -t oob-watchdog "$*"; }

count() { cat "$STATE_DIR/$1" 2>/dev/null || echo 0; }
setc()  { echo "$2" > "$STATE_DIR/$1"; }

modem_usb_dirs() {
    local d
    for d in /sys/bus/usb/devices/*; do
        [[ "$(cat "$d/idVendor" 2>/dev/null)" == "1e0e" ]] && echo "$d"
    done
}

# ─── USB recovery ladder ─────────────────────────────────────────────────
# Pilot incident 2026-08-23 (d2-lab-pi01, cold power-on): the modem
# enumerated on USB but its function side was dead — no AT reply, RNDIS
# carrier up with no DHCP. The old heal (re-authorize toggle alone) made it
# WORSE: SET_CONFIGURATION(0) succeeded, SET_CONFIGURATION(1) failed with
# EPROTO (-71) on the hung modem, and the device sat UNCONFIGURED
# (bConfigurationValue empty, no ttyUSB*, no wwan0) — nothing left for the
# kernel to rebind, OOB dark until a manual port reset + driver rebind.
# Ladder now (each step pilot-verified to return ttyUSB*/wwan0 in ~2 s on a
# healthy modem):
#   1. re-authorize toggle — cheap, recovers driver-side wedges.
#   2. if ports are not back within 15 s: USBDEVFS_RESET port reset (what a
#      replug does at the protocol level — un-wedges the control pipe; the
#      kernel re-applies the config and rebinds drivers if the device was
#      still configured).
#   3. if ports are still not back within 10 s (device left unconfigured —
#      a port reset on an unconfigured device rebinds nothing): driver
#      unbind/bind of the modem's USB device path (e.g. "3-2") re-issues
#      SET_CONFIGURATION(1). Wait up to 30 s.
# The modem stays powered throughout; PWRKEY is never touched here.
modem_ports_back() { [[ -e /dev/d2-modem ]] && ip link show wwan0 >/dev/null 2>&1; }
wait_ports() {  # wait_ports <seconds>
    local deadline=$(( SECONDS + $1 ))
    until modem_ports_back; do
        (( SECONDS >= deadline )) && return 1
        sleep 1
    done
}
usb_port_reset() {  # usb_port_reset <sysfs device dir>
    local node
    node=$(printf '/dev/bus/usb/%03d/%03d' "$(cat "$1/busnum")" "$(cat "$1/devnum")") || return 1
    python3 - "$node" <<'PY'
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_WRONLY)
try:
    fcntl.ioctl(fd, 0x5514)   # USBDEVFS_RESET = _IO('U', 20)
finally:
    os.close(fd)
PY
}
usb_recover() {  # usb_recover [--skip-reauth]
    local d id cfg
    for d in $(modem_usb_dirs); do
        id=$(basename "$d")
        if [[ "${1:-}" != "--skip-reauth" ]]; then
            log "USB recovery of modem $id: step 1 re-authorize toggle"
            echo 0 > "$d/authorized" 2>/dev/null
            sleep 2
            echo 1 > "$d/authorized" 2>/dev/null
            if wait_ports 15; then log "modem $id recovered after re-authorize"; continue; fi
        fi
        cfg=$(cat "$d/bConfigurationValue" 2>/dev/null)
        log "USB recovery of modem $id: step 2 port reset (cfg=[$cfg])"
        usb_port_reset "$d" 2>/dev/null || log "modem $id: USBDEVFS_RESET ioctl failed — continuing"
        if wait_ports 10; then log "modem $id recovered after port reset"; continue; fi
        cfg=$(cat "$d/bConfigurationValue" 2>/dev/null)
        log "USB recovery of modem $id: step 3 driver unbind/bind (cfg=[$cfg])"
        echo "$id" > /sys/bus/usb/drivers/usb/unbind 2>/dev/null
        sleep 3
        echo "$id" > /sys/bus/usb/drivers/usb/bind 2>/dev/null
        if wait_ports 30; then
            log "modem $id recovered after port reset + driver rebind"
        else
            cfg=$(cat "$d/bConfigurationValue" 2>/dev/null)
            log "modem $id STILL dead after port reset + driver rebind (cfg=[$cfg]) — needs a power cycle (Pi 5V feeds the HAT)"
        fi
    done
}

if [[ "${1:-}" == "--usb-recover" ]]; then
    (( EUID == 0 )) || { echo "oob-watchdog: --usb-recover must run as root" >&2; exit 1; }
    [[ -n "$(modem_usb_dirs)" ]] || { echo "oob-watchdog: no SIM7600 (vendor 1e0e) on the USB bus" >&2; exit 1; }
    log "manual USB recovery requested${2:+ ($2)}"
    usb_recover "${2:-}"
    modem_ports_back && echo "modem ports back: $(readlink -f /dev/d2-modem), wwan0 present" || { echo "modem ports NOT back — see journalctl -t oob-watchdog" >&2; exit 1; }
    exit 0
fi

# ─── Probe ────────────────────────────────────────────────────────────────
modem_present=0; at_ok=0; registered=0; csq=-1; ping_ok=0; tailnet_online=0
[[ -n "$(modem_usb_dirs)" ]] && modem_present=1

if (( modem_present )) && [[ -e /dev/d2-modem ]]; then
    if "$AT" AT 2>/dev/null | grep -q OK; then
        at_ok=1
        "$AT" 'AT+CEREG?' 2>/dev/null | grep -qE '\+CEREG: [0-9],[15]' && registered=1
        csq=$("$AT" 'AT+CSQ' 2>/dev/null | grep -oE '\+CSQ: [0-9]+' | grep -oE '[0-9]+$' || echo -1)
    fi
fi
if (( registered )); then
    ping -I wwan0 -c 2 -W 5 1.1.1.1 >/dev/null 2>&1 && ping_ok=1
fi
docker exec oob-tailscale tailscale status --json 2>/dev/null \
    | grep -q '"Online": *true' && tailnet_online=1

# Data budget: vnstat month-to-date on wwan0 vs OOB_DATA_CAP_MB (.env,
# default 1000). vnstat may have no month row yet on a fresh install.
data_cap_mb=1000
if [[ -r "$EDGE_DIR/shared/scripts/lib/envfile.sh" ]]; then
    . "$EDGE_DIR/shared/scripts/lib/envfile.sh"
    cap=$(env_get OOB_DATA_CAP_MB "$EDGE_DIR/.env")
    [[ "$cap" =~ ^[0-9]+$ ]] && data_cap_mb=$cap
fi
data_used_mb=$(vnstat -i wwan0 --json m 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    m = d['interfaces'][0]['traffic']['month']
    t = m[-1] if m else None
    print(0 if t is None else (t['rx'] + t['tx']) // (1024 * 1024))
except Exception:
    print(0)
" 2>/dev/null || echo 0)
data_used_pct=$(( data_cap_mb > 0 ? data_used_mb * 100 / data_cap_mb : 0 ))

cat > "$STATE_DIR/status.new" <<EOF
modem_present=$modem_present
at_ok=$at_ok
registered=$registered
csq=$csq
ping_ok=$ping_ok
tailnet_online=$tailnet_online
data_used_mb=$data_used_mb
data_cap_mb=$data_cap_mb
data_used_pct=$data_used_pct
updated=$(date +%s)
EOF
mv "$STATE_DIR/status.new" "$STATE_DIR/status"
chmod 644 "$STATE_DIR/status"

# ─── Heal ─────────────────────────────────────────────────────────────────
# 1. modem absent from USB: power-ON pulse, rate-limited
if (( ! modem_present )); then
    now=$(date +%s)
    if (( now - $(count pwrkey_last) > 3600 )); then
        setc pwrkey_last "$now"
        gpio="${OOB_PWRKEY_GPIO:-6}"
        log "modem absent from USB — PWRKEY power-on pulse (GPIO $gpio)"
        pinctrl set "$gpio" op dh; sleep 3; pinctrl set "$gpio" dl
    fi
    exit 0
fi

# 2. on USB but AT dead (no reply, or /dev/d2-modem gone while the device is
#    still on the bus): USB recovery ladder (never PWRKEY)
if (( ! at_ok )); then
    setc at_fails "$(( $(count at_fails) + 1 ))"
    (( $(count at_fails) < 2 )) && exit 0   # tolerate a single blip
    setc at_fails 0
    if [[ -e /dev/d2-modem ]]; then
        log "modem on USB but AT unresponsive"
    else
        log "modem on USB but /dev/d2-modem missing (unconfigured or ttys gone)"
    fi
    usb_recover
    exit 0
fi
setc at_fails 0

# 3. not registered: carrier/SIM side — no intervention
if (( ! registered )); then
    setc ping_fails 0
    exit 0
fi

# 4. registered but no data path: CFUN ×2, then USB recovery ladder
if (( ping_ok )); then
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
    usb_recover
fi
