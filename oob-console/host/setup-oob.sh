#!/usr/bin/env bash
# setup-oob.sh — idempotent OOB host-layer installer + config renderer.
# Invoked by update.sh AND deploy-all.sh ONLY when DEPLOY_OOB_CONSOLE=enabled.
# Safe to re-run every deploy. Fails loud (non-zero) so a broken OOB install
# aborts the deploy rather than half-working.
#
# Rendering lives HERE (not render-configs.sh) so slots.rules is produced
# and installed in the same step — the old split meant every ports.yaml
# change needed TWO update.sh runs before consoles worked (review finding #3).
set -euo pipefail
EDGE_DIR=/opt/d2-edge
HOSTD="$EDGE_DIR/oob-console/host"
OOBD="$EDGE_DIR/oob-console"

echo "[oob] installing host layer..."

# 0. Helpers first — everything below may need the AT sender.
install -m 0755 "$HOSTD/oob-at.py" /usr/local/sbin/oob-at.py
mkdir -p "$OOBD/logs" "$OOBD/rendered"

# 1. Packages — guarded so a dpkg lock (unattended-upgrades) or a dead
#    mirror can't abort routine deploys over already-installed packages.
if ! dpkg -s python3-yaml vnstat >/dev/null 2>&1; then
    apt-get install -y -qq python3-yaml vnstat >/dev/null
fi
if dpkg -s brltty >/dev/null 2>&1; then
    apt-get purge -y -qq brltty >/dev/null
    echo "[oob] purged brltty"
fi

# 2. Render ser2net.yaml + slots.rules from ports.yaml (fail loud — an
#    enabled Pi without a console map is a misconfiguration).
if [[ ! -f "$OOBD/ports.yaml" ]]; then
    echo "[oob] ERROR: DEPLOY_OOB_CONSOLE=enabled but $OOBD/ports.yaml missing" >&2
    exit 1
fi
python3 "$OOBD/render-ser2net.py" "$OOBD/ports.yaml" \
    "$OOBD/rendered/ser2net.yaml" "$OOBD/slots.rules"
echo "[oob] rendered OK ($(grep -c '^connection:' "$OOBD/rendered/ser2net.yaml") slots)"

# 2.5. NetworkManager guard: stop NM activating wired profiles on wwan0
#      (it hijacked netplan-eth0 onto the modem on the pilot Pi, taking
#      eth0 down). Only relevant where NM exists; restart is safe — NM
#      keeps device state across restarts.
if command -v nmcli >/dev/null 2>&1; then
    mkdir -p /etc/NetworkManager/conf.d
    if ! cmp -s "$HOSTD/90-d2-oob-nm.conf" /etc/NetworkManager/conf.d/90-d2-oob.conf 2>/dev/null; then
        install -m 0644 "$HOSTD/90-d2-oob-nm.conf" /etc/NetworkManager/conf.d/90-d2-oob.conf
        systemctl try-restart NetworkManager 2>/dev/null || true
        echo "[oob] installed NetworkManager unmanaged-devices guard"
    fi
fi

# 3. udev: shipped rules + rendered slot rules. cmp-guarded — reload and
#    re-trigger only when something actually changed (an unconditional
#    trigger re-fires uevents for every tty on the bus each deploy).
udev_changed=false
if ! cmp -s "$HOSTD/99-d2-console.rules" /etc/udev/rules.d/99-d2-console.rules 2>/dev/null; then
    install -m 0644 "$HOSTD/99-d2-console.rules" /etc/udev/rules.d/99-d2-console.rules
    udev_changed=true
fi
if ! cmp -s "$OOBD/slots.rules" /etc/udev/rules.d/98-d2-console-slots.rules 2>/dev/null; then
    install -m 0644 "$OOBD/slots.rules" /etc/udev/rules.d/98-d2-console-slots.rules
    udev_changed=true
fi
if $udev_changed; then
    udevadm control --reload && udevadm trigger --subsystem-match=tty
    udevadm settle --timeout=10 || true
fi

# 4. networkd: pin wwan0 name + DHCP-into-table-200. The conf.d drop-in
#    stops networkd deleting our "foreign" table-200 rule/blackhole on
#    every interface reconfigure (fail-open otherwise).
mkdir -p /etc/systemd/networkd.conf.d
networkd_conf_changed=false
if ! cmp -s "$HOSTD/90-d2-oob-networkd.conf" /etc/systemd/networkd.conf.d/90-d2-oob.conf 2>/dev/null; then
    install -m 0644 "$HOSTD/90-d2-oob-networkd.conf" /etc/systemd/networkd.conf.d/90-d2-oob.conf
    networkd_conf_changed=true
fi
install -m 0644 "$HOSTD/10-wwan0.link"    /etc/systemd/network/10-wwan0.link
install -m 0644 "$HOSTD/30-wwan0.network" /etc/systemd/network/30-wwan0.network
systemctl enable --now systemd-networkd >/dev/null 2>&1 || true
if $networkd_conf_changed; then
    systemctl try-restart systemd-networkd 2>/dev/null || true
else
    networkctl reload 2>/dev/null || true
fi

# 5. Routing + power + watchdog units.
install -m 0755 "$HOSTD/oob-watchdog.sh" /usr/local/sbin/oob-watchdog.sh
for u in oob-routing.service sim7600-power.service oob-watchdog.service oob-watchdog.timer; do
    install -m 0644 "$HOSTD/$u" "/etc/systemd/system/$u"
done
systemctl daemon-reload
systemctl enable oob-routing.service oob-watchdog.timer sim7600-power.service
# restart (not enable --now): re-asserts the rule + blackhole on every run.
systemctl restart oob-routing.service
systemctl start oob-watchdog.timer 2>/dev/null || true

# Helper: wait for a condition with a cap instead of a fixed worst-case sleep.
wait_for() {  # wait_for <seconds> <cmd...>
    local deadline=$(( $(date +%s) + $1 )); shift
    until "$@" >/dev/null 2>&1; do
        (( $(date +%s) >= deadline )) && return 1
        sleep 1
    done
}

modem_pid() {
    local d
    for d in /sys/bus/usb/devices/*/idVendor; do
        if [[ "$(cat "$d" 2>/dev/null)" == "1e0e" ]]; then
            cat "${d%idVendor}idProduct" 2>/dev/null
            return 0
        fi
    done
    return 1
}

# 6. Pin the modem USB mode to RNDIS (persists in modem NVRAM). PID 9011 =
#    RNDIS composite. Uses oob-at.py (termios-correct, reads the reply) —
#    a raw printf inherits unknown tty state and can silently no-op.
cur_pid=$(modem_pid || true)
if [[ -n "$cur_pid" && "$cur_pid" != "9011" && -e /dev/d2-modem ]]; then
    echo "[oob] modem PID $cur_pid — pinning USB mode to RNDIS (AT+CUSBPIDSWITCH=9011,1,1); modem will re-enumerate"
    /usr/local/sbin/oob-at.py 'AT+CUSBPIDSWITCH=9011,1,1' >/dev/null 2>&1 || true
    wait_for 30 test -e /dev/d2-modem || true
    udevadm settle --timeout=10 || true
fi

# 6.5. APN: ensure PDP profile 1 matches OOB_APN from .env. Quote-stripped —
#      operators legally write OOB_APN="x" and embedded quotes would make
#      this re-issue a mangled CGDCONT + modem reset on EVERY deploy.
#      Type "IP" not IPV4V6 — v6-primary grants no v4 on these SIMs.
OOB_APN=$(grep -E '^OOB_APN=' "$EDGE_DIR/.env" 2>/dev/null | tail -1 | cut -d= -f2- \
          | sed -e 's/[[:space:]]*$//' -e 's/^["'\'']//' -e 's/["'\'']$//')
if [[ -n "$OOB_APN" && -e /dev/d2-modem ]]; then
    if ! /usr/local/sbin/oob-at.py 'AT+CGDCONT?' 2>/dev/null | grep -q "\"$OOB_APN\""; then
        echo "[oob] setting APN on PDP profile 1: $OOB_APN (modem will reset)"
        /usr/local/sbin/oob-at.py "AT+CGDCONT=1,\"IP\",\"$OOB_APN\"" >/dev/null 2>&1 || true
        /usr/local/sbin/oob-at.py 'AT+CFUN=1,1' >/dev/null 2>&1 || true
        wait_for 40 test -e /dev/d2-modem || true
        udevadm settle --timeout=10 || true
    fi
fi

# 7. Verify block — degrades gracefully when no SIM is fitted yet.
fail=0
say() { echo "[oob][verify] $*"; }
if modem_pid >/dev/null; then say "modem enumerated: OK"; else say "FAIL: no SIM7600 (vendor 1e0e) on USB bus"; fail=1; fi
[[ -e /dev/d2-modem ]] && say "AT port /dev/d2-modem: OK" || { say "FAIL: /dev/d2-modem missing"; fail=1; }
ip link show wwan0 >/dev/null 2>&1 && say "wwan0 present: OK" || { say "FAIL: wwan0 missing (mode pin pending? re-run update.sh after modem re-enumerates)"; fail=1; }
ip rule | grep -q "from 172.31.250.0/29 lookup 200" && say "ip rule: OK" || { say "FAIL: ip rule missing"; fail=1; }
ip route show table 200 2>/dev/null | grep -q blackhole && say "blackhole: OK" || { say "FAIL: blackhole route missing"; fail=1; }
if ip -4 addr show dev wwan0 2>/dev/null | grep -q inet; then
    say "modem-link IP on wwan0: OK (NOT proof of cellular registration)"
else
    say "WARN: no IP on wwan0 (modem DHCP not answering) — OOB path not live"
fi
# Slot symlinks: WARN per missing slot (an unplugged adapter must not block
# a fleet deploy), but say it loudly — ser2net will not serve that slot.
while read -r slot; do
    if [[ ! -e "/dev/d2-console/$slot" ]]; then
        say "WARN: /dev/d2-console/$slot missing (adapter unplugged or wrong port) — that console will be dead"
    fi
done < <(grep -oE 'slot[0-9]{2}' "$OOBD/rendered/ser2net.yaml" | sort -u)
(( fail == 0 )) || { echo "[oob] verify FAILED"; exit 1; }
echo "[oob] host layer OK"
