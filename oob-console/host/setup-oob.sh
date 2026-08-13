#!/usr/bin/env bash
# setup-oob.sh — idempotent OOB host-layer installer. Invoked by update.sh
# ONLY when DEPLOY_OOB_CONSOLE=enabled. Safe to re-run every deploy.
# Verify block at the end fails loud (non-zero) so a broken OOB install
# aborts the deploy rather than half-working.
set -euo pipefail
EDGE_DIR=/opt/d2-edge
HOSTD="$EDGE_DIR/oob-console/host"

echo "[oob] installing host layer..."

# 0. Packages: python3-yaml (renderer), vnstat (data-budget visibility).
#    ModemManager intentionally NOT installed — data path is RNDIS+DHCP.
apt-get install -y -qq python3-yaml vnstat >/dev/null

# 1. brltty hijacks CH340/CP2102 console adapters — remove if present.
if dpkg -s brltty >/dev/null 2>&1; then
    apt-get purge -y -qq brltty >/dev/null
    echo "[oob] purged brltty"
fi

# 2. udev: shipped rules + per-site rendered slot rules (if present).
install -m 0644 "$HOSTD/99-d2-console.rules" /etc/udev/rules.d/99-d2-console.rules
if [[ -f "$EDGE_DIR/oob-console/slots.rules" ]]; then
    install -m 0644 "$EDGE_DIR/oob-console/slots.rules" /etc/udev/rules.d/98-d2-console-slots.rules
fi
udevadm control --reload && udevadm trigger --subsystem-match=tty
# Give udev a moment to settle symlinks before the verify block.
udevadm settle --timeout=10 || true

# 3. networkd: pin wwan0 name + DHCP-into-table-200. The conf.d drop-in
#    stops networkd deleting our "foreign" table-200 rule/blackhole on
#    every interface reconfigure (ManageForeignRoutingPolicyRules default
#    is yes) — without it the fail-closed guarantee silently fails OPEN.
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

# 4. Routing + power + watchdog units.
install -m 0755 "$HOSTD/oob-watchdog.sh" /usr/local/sbin/oob-watchdog.sh
for u in oob-routing.service sim7600-power.service oob-watchdog.service oob-watchdog.timer; do
    install -m 0644 "$HOSTD/$u" "/etc/systemd/system/$u"
done
systemctl daemon-reload
systemctl enable oob-routing.service oob-watchdog.timer sim7600-power.service
# restart (not enable --now): re-asserts the rule + blackhole on every run,
# healing anything a networkd restart may have cleaned up before the
# conf.d drop-in landed. Idempotent (del-then-add semantics in the unit).
systemctl restart oob-routing.service
systemctl start oob-watchdog.timer 2>/dev/null || true

# 5. Pin the modem USB mode to RNDIS (persists in modem NVRAM). Skip when
#    already pinned: PID 9011 = RNDIS composite on SIM7600.
if [[ -e /dev/d2-modem ]]; then
    cur_pid=""
    for d in /sys/bus/usb/devices/*/idVendor; do
        if [[ "$(cat "$d" 2>/dev/null)" == "1e0e" ]]; then
            cur_pid=$(cat "${d%idVendor}idProduct" 2>/dev/null || true)
            break
        fi
    done
    if [[ -n "$cur_pid" && "$cur_pid" != "9011" ]]; then
        echo "[oob] modem PID $cur_pid — pinning USB mode to RNDIS (AT+CUSBPIDSWITCH=9011,1,1); modem will re-enumerate"
        printf 'AT+CUSBPIDSWITCH=9011,1,1\r' > /dev/d2-modem
        sleep 15
        udevadm settle --timeout=10 || true
    fi
fi

# 6. Verify block — degrades gracefully when no SIM is fitted yet.
fail=0
say() { echo "[oob][verify] $*"; }
hat=false
for d in /sys/bus/usb/devices/*/idVendor; do
    [[ "$(cat "$d" 2>/dev/null)" == "1e0e" ]] && hat=true && break
done
if $hat; then say "modem enumerated: OK"; else say "FAIL: no SIM7600 (vendor 1e0e) on USB bus"; fail=1; fi
[[ -e /dev/d2-modem ]] && say "AT port /dev/d2-modem: OK" || { say "FAIL: /dev/d2-modem missing"; fail=1; }
ip link show wwan0 >/dev/null 2>&1 && say "wwan0 present: OK" || { say "FAIL: wwan0 missing (mode pin pending? re-run update.sh after modem re-enumerates)"; fail=1; }
ip rule | grep -q "from 172.31.250.0/29 lookup 200" && say "ip rule: OK" || { say "FAIL: ip rule missing"; fail=1; }
ip route show table 200 2>/dev/null | grep -q blackhole && say "blackhole: OK" || { say "FAIL: blackhole route missing"; fail=1; }
if ip -4 addr show dev wwan0 2>/dev/null | grep -q inet; then
    # NOTE: in RNDIS mode the modem's internal DHCP hands out a
    # 192.168.225.x link IP even with NO SIM — this proves the modem
    # data path, not cellular registration.
    say "modem-link IP on wwan0: OK (NOT proof of cellular registration)"
else
    say "WARN: no IP on wwan0 (modem DHCP not answering) — OOB path not live"
fi
(( fail == 0 )) || { echo "[oob] verify FAILED"; exit 1; }
echo "[oob] host layer OK"
