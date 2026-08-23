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
#              registered, no data ×3 → USB recovery ladder, then AT+CFUN=1,1
#                                        (alternating, + pair restart)
#              data OK, -oob node offline ×2 → restart oob pair (1/30 min)
#
# Manual use: `oob-watchdog.sh --usb-recover` runs the same USB recovery
# ladder on demand (operator break-glass; see runbook).
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
# carrier up with no DHCP lease for 10+ min. The old heal (an `authorized`
# 0→1 toggle) made it WORSE: SET_CONFIGURATION(0) succeeded but
# SET_CONFIGURATION(1) got EPROTO (-71) from the hung modem, leaving the
# device UNCONFIGURED (bConfigurationValue empty, no ttyUSB*, no wwan0)
# with nothing for the kernel to rebind — OOB dark until a manual port
# reset + driver rebind. The toggle was dropped: it only ever succeeds on
# a modem that needs no recovery (pilot-verified: EPROTO on a modem whose
# function side is down, a no-op on an unconfigured device).
#
# Ladder (each step pilot-verified 2026-08-23):
#   1. USBDEVFS_RESET port reset — a replug at the protocol level; un-wedges
#      the modem's control pipe. If the device was still configured the
#      kernel re-applies the config and rebinds drivers itself (~2 s).
#   2. If ttyUSB*/wwan0 are not back (device unconfigured — a port reset
#      rebinds nothing on an unconfigured device): driver unbind/bind of
#      the modem's USB device path ("3-2", derived from the 1e0e sysfs
#      match) re-issues SET_CONFIGURATION(1). Wait up to 30 s.
#   3. Ports back → bounce oob-tailscale + oob-console: tailscaled sits on
#      a dead control connection after a modem bounce (new flows fine, node
#      Offline 15+ min; restart → Online in 5 s).
# The modem stays powered throughout; PWRKEY is never touched here.
modem_ports_back() { [[ -e /dev/d2-modem ]] && ip link show wwan0 >/dev/null 2>&1; }
wait_ports() {  # wait_ports <seconds>
    local deadline=$(( SECONDS + $1 ))
    until modem_ports_back; do
        (( SECONDS >= deadline )) && return 1
        sleep 1
    done
}
# Ports back ≠ modem back: after a reset the SIM7600 answers AT a few
# seconds later (up to ~20 s after re-enumeration on a full reboot). Each
# probe costs 2.5 s; poll until OK or the deadline.
wait_at() {  # wait_at <seconds>
    local deadline=$(( SECONDS + $1 ))
    while true; do
        [[ -e /dev/d2-modem ]] && "$AT" AT 2>/dev/null | grep -q OK && return 0
        (( SECONDS >= deadline )) && return 1
        sleep 2
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
restart_oob_pair() {  # restart_oob_pair <reason>
    # -a: a STOPPED pair (e.g. an interrupted `compose up`, incident 08-14)
    # must be started, not skipped — `docker restart` starts a stopped one.
    docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx oob-tailscale || return 0
    log "restarting oob-tailscale + oob-console ($1)"
    docker restart oob-tailscale >/dev/null 2>&1 || true
    docker restart oob-console >/dev/null 2>&1 || true
    setc pair_restart_last "$(date +%s)"
}
usb_recover() {
    local d id cfg recovered=0
    for d in $(modem_usb_dirs); do
        id=$(basename "$d")
        cfg=$(cat "$d/bConfigurationValue" 2>/dev/null)
        log "USB recovery of modem $id: step 1 port reset (cfg=[$cfg])"
        usb_port_reset "$d" 2>/dev/null || log "modem $id: USBDEVFS_RESET ioctl failed — continuing"
        sleep 2
        cfg=$(cat "$d/bConfigurationValue" 2>/dev/null)
        if [[ -n "$cfg" ]] && wait_ports 8 && wait_at 45; then
            log "modem $id recovered after port reset (AT OK)"
            recovered=1
            continue
        fi
        cfg=$(cat "$d/bConfigurationValue" 2>/dev/null)
        log "USB recovery of modem $id: step 2 driver unbind/bind (cfg=[$cfg], ports $(modem_ports_back && echo present || echo absent))"
        echo "$id" > /sys/bus/usb/drivers/usb/unbind 2>/dev/null
        sleep 3
        echo "$id" > /sys/bus/usb/drivers/usb/bind 2>/dev/null
        if wait_ports 30 && wait_at 45; then
            log "modem $id recovered after port reset + driver rebind (AT OK)"
            recovered=1
        else
            cfg=$(cat "$d/bConfigurationValue" 2>/dev/null)
            log "modem $id STILL dead after port reset + driver rebind (cfg=[$cfg], ports $(modem_ports_back && echo present || echo absent), AT $(wait_at 0 && echo OK || echo dead)) — will retry next cycle; if it persists, power-cycle (Pi 5V feeds the HAT)"
        fi
    done
    # Counters surface in /run/d2-oob/status → Zabbix oob.status[usb_recoveries]
    # (a modem that needs this daily is a hardware ticket, not a watchdog job).
    if (( recovered )); then
        setc usb_recoveries "$(( $(count usb_recoveries) + 1 ))"
        setc last_usb_recovery "$(date +%s)"
        # Only bounce the pair on SUCCESS: on a permanently dead modem the
        # ladder retries every 2 probes, and an unconditional restart would
        # kill in-band `telnet localhost 300N` console sessions every 10 min.
        restart_oob_pair "after USB recovery"
    else
        setc usb_recovery_failures "$(( $(count usb_recovery_failures) + 1 ))"
    fi
    return $(( ! recovered ))
}

# One run at a time: a timer run mid-ladder and a manual --usb-recover (or
# a second `systemctl start`) must not reset the modem under each other.
# A ladder run is ≤ ~2.5 min worst case; a caller that can't get the lock
# inside 4 min walks away rather than piling on.
exec 9>"$STATE_DIR/run.lock"
if ! flock -w 240 9; then
    log "another oob-watchdog run has held the lock for >240 s — skipping this run"
    exit 0
fi

if [[ "${1:-}" == "--usb-recover" ]]; then
    (( EUID == 0 )) || { echo "oob-watchdog: --usb-recover must run as root" >&2; exit 1; }
    [[ -n "$(modem_usb_dirs)" ]] || { echo "oob-watchdog: no SIM7600 (vendor 1e0e) on the USB bus" >&2; exit 1; }
    log "manual USB recovery requested"
    if usb_recover; then
        echo "modem back: $(readlink -f /dev/d2-modem) answers AT, wwan0 present"
    else
        echo "modem NOT back — see journalctl -t oob-watchdog" >&2; exit 1
    fi
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
# Self.Online only — the JSON also carries an "Online" flag per PEER, so a
# bare grep read "online" whenever any other tailnet node was up (fault test
# 2026-08-23: `tailscale down` inside the container went unnoticed).
tailnet_online=$(docker exec oob-tailscale tailscale status --json 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(1 if d.get("BackendState") == "Running" and d.get("Self", {}).get("Online") else 0)
except Exception:
    print(0)
' 2>/dev/null || echo 0)
[[ "$tailnet_online" == 1 ]] || tailnet_online=0

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
usb_recoveries=$(count usb_recoveries)
usb_recovery_failures=$(count usb_recovery_failures)
last_usb_recovery=$(count last_usb_recovery)
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
#    still on the bus): USB recovery ladder (never PWRKEY). Two consecutive
#    probes (timer = 5 min apart) — a modem rebooting after AT+CFUN=1,1
#    answers AT again well within that window.
if (( ! at_ok )); then
    setc at_fails "$(( $(count at_fails) + 1 ))"
    # Tolerate a single blip — except in the first 10 min after boot: the
    # first probe runs at 3 min, long past the modem's own boot, and a dead
    # AT port there is the cold-boot wedge (pilot: 2 of 2 boots on 08-23).
    # Acting on probe 1 cuts OOB dark time after a power-on from ~8 to ~3.5 min.
    uptime_s=$(cut -d. -f1 /proc/uptime)
    (( $(count at_fails) < 2 && uptime_s > 600 )) && exit 0
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

# 4. registered but no data path ×3: USB recovery ladder, then AT+CFUN=1,1,
#    alternating
if (( ping_ok )); then
    setc ping_fails 0; setc data_heals 0
    # 5. data path fine but the -oob node is offline: tailscaled stuck on a
    #    dead control connection (see restart_oob_pair). Two consecutive
    #    probes, then bounce the pair, at most once per 30 min — a carrier
    #    or Tailscale-side outage must not turn into a restart loop.
    if (( ! tailnet_online )); then
        setc tailnet_fails "$(( $(count tailnet_fails) + 1 ))"
        if (( $(count tailnet_fails) >= 2 )) \
           && (( $(date +%s) - $(count pair_restart_last) > 1800 )); then
            setc tailnet_fails 0
            restart_oob_pair "wwan0 data path OK but -oob node offline ×2"
        fi
    else
        setc tailnet_fails 0
    fi
    exit 0
fi
setc ping_fails "$(( $(count ping_fails) + 1 ))"
log "registered but wwan0 ping failure $(count ping_fails)/3"
(( $(count ping_fails) < 3 )) && exit 0
setc ping_fails 0

# Alternate: USB recovery ladder first (host-side port reset re-does RNDIS +
# DHCP in ~5 s and has never wedged the modem outside its boot window), then
# AT+CFUN=1,1 (modem-side reboot — re-attaches the PDP context, but on the
# pilot SIM7600 it came back wedged on 4 of 5 reboots, costing the ladder
# two more probes). data_heals resets to 0 whenever ping succeeds.
n=$(count data_heals); setc data_heals "$(( n + 1 ))"
if (( n % 2 == 0 )); then
    log "data path heal $(( n + 1 )): USB recovery ladder"
    usb_recover
else
    log "data path heal $(( n + 1 )): soft-resetting modem (AT+CFUN=1,1)"
    "$AT" 'AT+CFUN=1,1' >/dev/null 2>&1
    # The reboot re-enumerates USB and re-DHCPs wwan0; tailscaled then sits on
    # a dead control connection (fault test 2026-08-23) — wait for the modem
    # (re-enum ~20 s, AT ~40 s; this SIM7600 sometimes needs >90 s) and bounce
    # the pair. A modem that stays dead is the USB ladder's job 2 probes later.
    sleep 20
    if wait_at 120; then
        restart_oob_pair "after AT+CFUN=1,1 soft reset"
    else
        log "modem not answering AT 140 s after AT+CFUN=1,1 — USB recovery ladder takes over if it stays dead"
    fi
fi

exit 0
