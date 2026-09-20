#!/usr/bin/env bash
# lan-watchdog.sh — self-heal a dead wired LAN path (bounce NIC, then reboot).
#
# Failure mode (lmc001-hq-pi01, 2026-09-19): 7.5 h after boot eth0 stopped
# TRANSMITTING. The Pi stayed up, link stayed 1000/Full, the DHCP address and
# default route stayed in place and broadcast traffic kept arriving — but the
# tx counter froze, so nothing (ARP included) left the box. Every service
# timed out for 26 h until someone power-cycled it. The tailscale-watchdog
# cannot help: it correctly sees "control plane unreachable" and holds off.
#
# Health signal = the default gateway's NEIGHBOUR (ARP) state, never ICMP:
# several customer gateways drop ping from the Pi (lmc001 does), so a ping
# probe would reboot healthy Pis. A ping is still sent, but only to make the
# kernel (re)resolve the neighbour; its result is a shortcut, not a verdict.
#
# Ladder (the timer runs this once a minute, so strikes ~= minutes):
#   tx-stall  — tx_packets did not advance while we probed (the signature
#               above; a driver reset is known to be the cure):
#                 bounce at strike 3, reboot at strike 10
#   gw-dead   — tx advances but the gateway never answers ARP, or the wired
#               default route vanished (more likely upstream: gateway
#               reboot/upgrade, switch fault), so be patient:
#                 bounce at strike 5, reboot at strike 30
#   no-carrier— link already down when the episode began (cable/switch port).
#               A bounce is cheap and can clear a wedged PHY, but a reboot
#               cannot plug a cable in: never reboot.
# Bounces repeat every 15 strikes. Watchdog reboots are rate-limited to one
# per 6 h, doubling (cap 48 h) for each consecutive reboot that did not
# restore the LAN, so a site that is genuinely dark is not reboot-looped.
#
# Evidence: the first strike of every episode snapshots link/neigh/route/
# ethtool/dmesg into $PERSIST_DIR/snapshots (last 10 kept). bounce_count /
# reboot_count are monotonic and read by Zabbix (Template D2 Edge Pi
# Hardware) so a silent self-heal still raises a flag.
#
# Opt-out: DEPLOY_LAN_WATCHDOG=disabled in .env (timer removed on next
# update), or `touch /etc/d2-lan-watchdog.disabled` for an immediate pause —
# do that before deliberately unplugging/re-addressing eth0.
set -u

STATE_DIR=${LAN_WD_STATE_DIR:-/run/d2-lan-watchdog}
PERSIST_DIR=${LAN_WD_PERSIST_DIR:-/var/lib/d2-lan-watchdog}
NET_SYS=${LAN_WD_NET_SYS:-/sys/class/net}
DISABLE_F=${LAN_WD_DISABLE_FILE:-/etc/d2-lan-watchdog.disabled}
DRY_RUN=${LAN_WD_DRY_RUN:-0}
SETTLE_SECS=${LAN_WD_SETTLE_SECS:-10}   # NUD: 5 s DELAY + 3x1 s PROBE, +margin

STALL_BOUNCE=3;  STALL_REBOOT=10
GW_BOUNCE=5;     GW_REBOOT=30
REBOUNCE_EVERY=15
REBOOT_MIN_GAP=21600      # 6 h
REBOOT_MAX_GAP=172800     # 48 h

[[ -e "$DISABLE_F" ]] && exit 0
mkdir -p "$STATE_DIR" "$PERSIST_DIR/snapshots"

log() { logger -t lan-watchdog -- "$*" 2>/dev/null || true; }
rd()  { local v; v=$(cat "$1" 2>/dev/null) || v=""; [[ "$v" =~ ^[0-9]+$ ]] && echo "$v" || echo 0; }

# --- 1. which wired default route are we guarding? ---------------------------
# Wired only: tailscale0 / wwan (OOB) default routes are someone else's job.
# LAN_WD_ROUTE="<gw> <dev>" overrides discovery — validation only (point it at
# an unused address to exercise the dead-gateway path on a healthy Pi).
route=${LAN_WD_ROUTE:-}
[[ -z "$route" ]] && route=$(ip -4 route show default 2>/dev/null | awk '{
    gw=""; dev="";
    for (i = 1; i < NF; i++) { if ($i == "via") gw = $(i+1); if ($i == "dev") dev = $(i+1) }
    if (gw != "" && dev ~ /^(eth|en)/) { print gw, dev; exit }
}')
have_route=1
if [[ -n "$route" ]]; then
    echo "$route" > "$STATE_DIR/route"
else
    # Route gone (lease lost, NM gave up). Judge against the last one seen this
    # boot; if there never was one, there is nothing to guard.
    route=$(cat "$STATE_DIR/route" 2>/dev/null) || route=""
    [[ -z "$route" ]] && exit 0
    have_route=0
fi
read -r gw dev <<<"$route"

neigh_state() { ip -4 neigh show to "$gw" dev "$dev" 2>/dev/null | awk '{print $NF; exit}'; }
tx_count()    { rd "$NET_SYS/$dev/statistics/tx_packets"; }

# --- 2. probe ----------------------------------------------------------------
verdict=healthy
stalled=0
if (( have_route )); then
    # REACHABLE = confirmed within ~30 s by live traffic: the steady state on a
    # working Pi, and it costs zero packets to check.
    if [[ "$(neigh_state)" != "REACHABLE" ]]; then
        tx0=$(tx_count)
        if ! ping -c 2 -W 1 -I "$dev" "$gw" >/dev/null 2>&1; then
            sleep "$SETTLE_SECS"
            case "$(neigh_state)" in
                REACHABLE)          ;;
                FAILED|INCOMPLETE|"") verdict=dead ;;
                *)                  exit 0 ;;   # still resolving — no verdict this run
            esac
        fi
        if [[ "$verdict" == dead ]] && (( $(tx_count) == tx0 )); then
            stalled=1
        fi
    fi
else
    verdict=dead
fi

strikes_f="$STATE_DIR/strikes"
if [[ "$verdict" == healthy ]]; then
    if [[ -f "$strikes_f" ]]; then
        log "LAN path to $gw via $dev recovered after $(rd "$strikes_f") strike(s)"
        rm -f "$strikes_f" "$STATE_DIR"/episode_*
    fi
    # Only touch the SD card when there is something to clear.
    [[ -f "$PERSIST_DIR/consecutive_reboots" ]] && rm -f "$PERSIST_DIR/consecutive_reboots"
    exit 0
fi

# --- 3. classify + count -------------------------------------------------------
strikes=$(( $(rd "$strikes_f") + 1 ))
echo "$strikes" > "$strikes_f"

carrier=$(rd "$NET_SYS/$dev/carrier")
# Episode memory. A bounce can leave a wedged NIC with no carrier and no route,
# which on its own looks like a pulled cable (never reboot) — exactly when a
# reboot is needed. So "never reboot" applies only if the link was already down
# when the episode began, and one observed tx-stall keeps the fast ladder for
# the rest of the episode.
(( strikes == 1 )) && echo "$carrier" > "$STATE_DIR/episode_carrier"
(( stalled )) && : > "$STATE_DIR/episode_stall"
if   (( ! carrier )) && (( ! $(rd "$STATE_DIR/episode_carrier") )); then
                                          kind=no-carrier; bounce_at=$GW_BOUNCE;    reboot_at=0
elif [[ -f "$STATE_DIR/episode_stall" ]]; then kind=tx-stall;   bounce_at=$STALL_BOUNCE; reboot_at=$STALL_REBOOT
else                                           kind=gw-dead;    bounce_at=$GW_BOUNCE;    reboot_at=$GW_REBOOT
fi
(( have_route )) || kind="$kind/no-route"

snapshot() {
    local f="$PERSIST_DIR/snapshots/$(date +%Y%m%dT%H%M%S).txt"
    {
        echo "### lan-watchdog snapshot $(date -Is) kind=$kind gw=$gw dev=$dev"
        echo "### ip -s link";  ip -s -s link show dev "$dev" 2>&1
        echo "### ip addr";     ip -4 addr show dev "$dev" 2>&1
        echo "### ip route";    ip -4 route 2>&1
        echo "### ip neigh";    ip -4 neigh show dev "$dev" 2>&1
        echo "### ethtool";     ethtool "$dev" 2>&1
        echo "### ethtool -S (non-zero)"; ethtool -S "$dev" 2>&1 | grep -v ': 0$'
        echo "### nmcli";       nmcli -t -f DEVICE,STATE,CONNECTION dev status 2>&1
        echo "### dmesg tail";  dmesg 2>&1 | tail -n 120
    } > "$f" 2>&1
    ls -1t "$PERSIST_DIR/snapshots" 2>/dev/null | tail -n +11 | while read -r old; do
        rm -f "$PERSIST_DIR/snapshots/$old"
    done
    log "evidence snapshot written: $f"
}

if (( strikes == 1 )); then
    log "LAN path DOWN ($kind): gateway $gw on $dev unresolved, carrier=$carrier — strike 1"
    snapshot
fi

bounce() {
    if [[ "$DRY_RUN" == 1 ]]; then log "DRY-RUN: would bounce $dev ($kind, strike $strikes)"; return; fi
    echo $(( $(rd "$PERSIST_DIR/bounce_count") + 1 )) > "$PERSIST_DIR/bounce_count"
    log "bouncing $dev ($kind, strike $strikes) — link down/up resets the NIC driver"
    ip link set dev "$dev" down
    sleep 3
    ip link set dev "$dev" up
    sleep 15
    # NM normally re-activates on carrier; nudge it if it has not.
    if command -v nmcli >/dev/null 2>&1 \
       && ! nmcli -t -f DEVICE,STATE dev status 2>/dev/null | grep -q "^$dev:connected"; then
        nmcli device connect "$dev" >/dev/null 2>&1 || true
    fi
}

maybe_reboot() {
    local now last consec gap
    now=$(date +%s)
    last=$(rd "$PERSIST_DIR/last_reboot")
    consec=$(rd "$PERSIST_DIR/consecutive_reboots")
    gap=$(( REBOOT_MIN_GAP << (consec > 3 ? 3 : consec) ))
    (( gap > REBOOT_MAX_GAP )) && gap=$REBOOT_MAX_GAP
    if (( now - last < gap )); then
        (( strikes % 30 == 0 )) && log "still DOWN ($kind, strike $strikes); reboot suppressed — last watchdog reboot $(( (now - last) / 60 )) min ago, gap $(( gap / 60 )) min"
        return 1
    fi
    if [[ "$DRY_RUN" == 1 ]]; then log "DRY-RUN: would reboot ($kind, strike $strikes)"; return 0; fi
    echo "$now" > "$PERSIST_DIR/last_reboot"
    echo $(( consec + 1 )) > "$PERSIST_DIR/consecutive_reboots"
    echo $(( $(rd "$PERSIST_DIR/reboot_count") + 1 )) > "$PERSIST_DIR/reboot_count"
    snapshot
    log "LAN path still DOWN after bounce ($kind, strike $strikes) — REBOOTING"
    sync
    systemctl reboot
}

# --- 4. act --------------------------------------------------------------------
# A rate-limited (suppressed) reboot falls through so the periodic bounce keeps
# trying for the rest of the episode.
if (( reboot_at > 0 && strikes >= reboot_at )) && maybe_reboot; then
    exit 0
fi
if (( strikes == bounce_at || (strikes > bounce_at && (strikes - bounce_at) % REBOUNCE_EVERY == 0) )); then
    bounce
fi
exit 0
