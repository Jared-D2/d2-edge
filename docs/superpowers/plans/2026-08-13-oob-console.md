# OOB Console (4G HAT + ser2net) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Opt-in OOB console access on edge Pis: SIM7600 4G uplink (host-managed, policy-routed, fail-closed) + isolated-netns ser2net container pair under a dedicated `tag:oob` Tailscale identity.

**Architecture:** Host layer (udev, systemd-networkd, watchdog, `setup-oob.sh` installer) owns the modem and routing table 200; two profile-gated compose services (`oob-tailscale` netns owner on bridge 172.31.250.0/29, `oob-console` ser2net sharing that netns) serve consoles. Everything is gated three ways so only HAT-fitted Pis run any of it. Spec: `docs/superpowers/specs/2026-08-12-oob-console-design.md`.

**Tech Stack:** bash, systemd-networkd, udev, docker compose, ser2net 4.x (alpine), python3+PyYAML (renderer), Tailscale.

**Branch:** work in worktree `d2-edge-oob-spec`, branch `feat/oob-console` created off `docs/oob-console-design` (Task 1). Commit after every task.

**Execution inputs (operator-supplied at pilot time, not plan gaps):** test-Pi LAN IP + SSH approval (Pi SSH allowlist currently permits only `.34` and `192.168.21.16` — the new Pi needs Jared's explicit OK), `EDGE_HOSTNAME` for the test Pi, `TS_OOB_AUTHKEY` (new OAuth client), `OOB_APN`.

---

### Task 1: Branch + `.env.template` keys

**Files:**
- Modify: `.env.template` (append at end)

- [ ] **Step 1: Create the feature branch**

```bash
cd C:/Users/JaredCooper/Claude/d2-edge-oob-spec && git switch -c feat/oob-console
```

- [ ] **Step 2: Append the OOB section to `.env.template`**

```bash
# --- OOB console (4G HAT) -------------------------------------------------
# DEPLOY_OOB_CONSOLE gates the entire OOB stack: setup-oob.sh host install,
# ser2net config render, and the oob-tailscale/oob-console containers.
# 'disabled' is the fleet default — enable ONLY on Pis with a SIM7600 HAT
# fitted. preflight.sh aborts if enabled with no HAT on the USB bus.
DEPLOY_OOB_CONSOLE=disabled

# OOB_APN: carrier APN for the 4G SIM (e.g. telstra.internet). Required
# (non-empty) only when DEPLOY_OOB_CONSOLE=enabled.
OOB_APN=

# TS_OOB_AUTHKEY: OAuth client secret for the SEPARATE oob Tailscale
# identity (<EDGE_HOSTNAME>-oob, tag:oob). This is NOT the fleet
# TS_AUTHKEY client — the oob OAuth client is scoped to tag:oob only.
# Required (non-empty) only when DEPLOY_OOB_CONSOLE=enabled.
TS_OOB_AUTHKEY=
```

- [ ] **Step 3: Verify template still parses as sourceable env**

Run: `bash -c 'set -a; source .env.template 2>/dev/null; echo "${DEPLOY_OOB_CONSOLE}"'`
Expected: `disabled`

- [ ] **Step 4: Commit**

```bash
git add .env.template && git commit -m "feat(oob): add DEPLOY_OOB_CONSOLE / OOB_APN / TS_OOB_AUTHKEY to .env.template"
```

### Task 2: udev rules (console slots + modem identity)

**Files:**
- Create: `oob-console/host/99-d2-console.rules`

- [ ] **Step 1: Write the rules file**

```udev
# oob-console/host/99-d2-console.rules
# Installed to /etc/udev/rules.d/ by setup-oob.sh. Two jobs:
#
# 1. SIM7600 modem (vendor 1e0e): tag every tty it exposes so
#    ModemManager never probes it destructively, and symlink the AT
#    command port (interface 02 on SIM7600) to /dev/d2-modem. The
#    presence of /dev/d2-modem is the "HAT is fitted" signal used by
#    the oob-console entrypoint guard and the watchdog.
SUBSYSTEM=="tty", ATTRS{idVendor}=="1e0e", ENV{ID_MM_DEVICE_IGNORE}="1"
SUBSYSTEM=="tty", ATTRS{idVendor}=="1e0e", ENV{ID_USB_INTERFACE_NUM}=="02", SYMLINK+="d2-modem"
#
# 2. Console slots: stable /dev/d2-console/slotNN symlinks keyed on the
#    PHYSICAL USB port (ID_PATH), not adapter serial — CH340s have no
#    unique serial. Slot identity = labelled hub port, by design. The
#    ID_PATH values below are per-Pi and appended by setup-oob.sh from
#    /opt/d2-edge/oob-console/slots.rules (rendered from ports.yaml);
#    this shipped file carries only the modem + catch-all MM guard.
#
# 3. Any USB-serial adapter that is NOT the modem: still guard against
#    ModemManager AT probing (it would type garbage into a live device
#    console). brltty is removed by setup-oob.sh for the same reason.
SUBSYSTEM=="tty", SUBSYSTEMS=="usb", DRIVERS=="ch341-uart|cp210x|ftdi_sio|pl2303", ENV{ID_MM_DEVICE_IGNORE}="1"
```

- [ ] **Step 2: Commit**

```bash
git add oob-console/host/99-d2-console.rules && git commit -m "feat(oob): udev rules — modem identity + MM guard for console adapters"
```

### Task 3: systemd-networkd link/network for wwan0

**Files:**
- Create: `oob-console/host/10-wwan0.link`
- Create: `oob-console/host/30-wwan0.network`

- [ ] **Step 1: Write `10-wwan0.link`** (pins the RNDIS iface name so routing config has a stable anchor)

```ini
# Pins the SIM7600 RNDIS network interface to the name wwan0.
# Matched by USB vendor ID so the name survives re-enumeration.
[Match]
Property=ID_VENDOR_ID=1e0e

[Link]
Name=wwan0
```

- [ ] **Step 2: Write `30-wwan0.network`** (DHCP from the modem's internal gateway, routes confined to table 200)

```ini
# wwan0 (SIM7600 RNDIS): DHCP from the modem's internal NAT/DHCP.
# ALL routes land in table 200 — never the main table. The ip rule
# steering the OOB bridge subnet into table 200 and the fail-closed
# blackhole are installed by setup-oob.sh (oob-routing.service),
# unconditionally — so with the modem absent, OOB traffic dies at the
# blackhole instead of leaking out eth0.
[Match]
Name=wwan0

[Network]
DHCP=ipv4
IPv6AcceptRA=no

[DHCPv4]
RouteTable=200
UseDNS=no
```

- [ ] **Step 3: Commit**

```bash
git add oob-console/host/10-wwan0.link oob-console/host/30-wwan0.network && git commit -m "feat(oob): networkd link/network — pin wwan0, DHCP into table 200"
```

### Task 4: OOB routing + power + watchdog units

**Files:**
- Create: `oob-console/host/oob-routing.service`
- Create: `oob-console/host/sim7600-power.service`
- Create: `oob-console/host/oob-watchdog.sh`
- Create: `oob-console/host/oob-watchdog.service`
- Create: `oob-console/host/oob-watchdog.timer`

- [ ] **Step 1: Write `oob-routing.service`** (fail-closed rules, installed unconditionally at boot)

```ini
[Unit]
Description=D2 OOB policy routing (table 200 rule + fail-closed blackhole)
After=network-pre.target
Before=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
# Idempotent: replace semantics via del-then-add.
ExecStart=/bin/sh -c 'ip rule del from 172.31.250.0/29 lookup 200 2>/dev/null; ip rule add from 172.31.250.0/29 lookup 200 priority 200'
ExecStart=/bin/sh -c 'ip route replace blackhole default metric 1000 table 200'

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Write `sim7600-power.service`** (PWRKEY pulse if modem absent 30s after boot; GPIO pin is a variable — pilot confirms)

```ini
[Unit]
Description=D2 SIM7600 power-on pulse (only if modem not enumerated)
After=multi-user.target

[Service]
Type=oneshot
EnvironmentFile=-/etc/default/d2-oob
# OOB_PWRKEY_GPIO default 6 (Waveshare SIM7600X HAT(B)); override in
# /etc/default/d2-oob if the fitted HAT revision differs.
ExecStart=/bin/sh -c '\
  sleep 30; \
  [ -e /dev/d2-modem ] && exit 0; \
  gpio="${OOB_PWRKEY_GPIO:-6}"; \
  echo "d2-oob: no modem after 30s, pulsing PWRKEY on GPIO $gpio" ; \
  pinctrl set "$gpio" op dh; sleep 3; pinctrl set "$gpio" dl'

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 3: Write `oob-watchdog.sh`** (self-heal for silently wedged LTE modules)

```bash
#!/usr/bin/env bash
# oob-watchdog.sh — runs every 5 min via oob-watchdog.timer.
# Pings via wwan0; after 3 consecutive failures soft-resets the modem
# (AT+CFUN=1,1); after 2 failed soft-reset cycles, PWRKEY power-cycle.
# State in /run/d2-oob (tmpfs — resets on reboot, intentionally).
set -u
STATE_DIR=/run/d2-oob; mkdir -p "$STATE_DIR"
FAILS_F="$STATE_DIR/ping_fails"; RESETS_F="$STATE_DIR/cfun_resets"
fails=$(cat "$FAILS_F" 2>/dev/null || echo 0)
resets=$(cat "$RESETS_F" 2>/dev/null || echo 0)

# No HAT → nothing to watch (unit is only installed when OOB enabled,
# but stay safe on a Pi where the HAT was pulled).
[[ -e /dev/d2-modem ]] || exit 0

# No SIM/carrier yet is NOT a wedge — skip until wwan0 has an address.
ip -4 addr show dev wwan0 2>/dev/null | grep -q inet || exit 0

if ping -I wwan0 -c 2 -W 5 1.1.1.1 >/dev/null 2>&1; then
    echo 0 > "$FAILS_F"; echo 0 > "$RESETS_F"; exit 0
fi
fails=$((fails + 1)); echo "$fails" > "$FAILS_F"
logger -t oob-watchdog "wwan0 ping failure $fails/3"
(( fails < 3 )) && exit 0

echo 0 > "$FAILS_F"
if (( resets < 2 )); then
    echo $((resets + 1)) > "$RESETS_F"
    logger -t oob-watchdog "soft-resetting modem (AT+CFUN=1,1), attempt $((resets + 1))/2"
    printf 'AT+CFUN=1,1\r' > /dev/d2-modem
else
    echo 0 > "$RESETS_F"
    gpio="${OOB_PWRKEY_GPIO:-6}"
    logger -t oob-watchdog "soft resets exhausted — PWRKEY power-cycle on GPIO $gpio"
    pinctrl set "$gpio" op dh; sleep 3; pinctrl set "$gpio" dl
fi
```

- [ ] **Step 4: Write `oob-watchdog.service` + `oob-watchdog.timer`**

```ini
# oob-watchdog.service
[Unit]
Description=D2 OOB 4G link watchdog

[Service]
Type=oneshot
EnvironmentFile=-/etc/default/d2-oob
ExecStart=/usr/local/sbin/oob-watchdog.sh
```

```ini
# oob-watchdog.timer
[Unit]
Description=Run D2 OOB 4G link watchdog every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

- [ ] **Step 5: Syntax-check the script, then commit**

Run: `bash -n oob-console/host/oob-watchdog.sh`
Expected: no output (exit 0)

```bash
git add oob-console/host/oob-routing.service oob-console/host/sim7600-power.service oob-console/host/oob-watchdog.* && git commit -m "feat(oob): routing/power/watchdog systemd units"
```

### Task 5: ports.yaml → ser2net.yaml renderer (with test)

**Files:**
- Create: `oob-console/ports.yaml.example`
- Create: `oob-console/render-ser2net.py`
- Create: `tests/test_render_ser2net.py`
- Test: `tests/test_render_ser2net.py`

- [ ] **Step 1: Write `oob-console/ports.yaml.example`**

```yaml
# Per-site console map. Copy to ports.yaml (gitignored) and edit.
# slot N ↔ /dev/d2-console/slotNN ↔ TCP 300N ↔ the hub port labelled N.
# usb_path: from `udevadm info -q property /dev/ttyUSBx | grep ID_PATH=`
#           after plugging the adapter into its labelled hub port.
# Shaped to mirror NetBox ConsoleServerPort→ConsolePort so a phase-2
# generator can emit this file from NetBox.
slots:
  - slot: 1
    device: ncm-fgt01        # log filename + Graylog field, free text
    baud: 9600
    platform: fortigate
    usb_path: platform-fd500000.usb-usb-0:1.1:1.0
  - slot: 2
    device: ncm-cx01
    baud: 115200
    platform: aruba-cx
    usb_path: platform-fd500000.usb-usb-0:1.2:1.0
```

- [ ] **Step 2: Write the failing test `tests/test_render_ser2net.py`**

```python
#!/usr/bin/env python3
"""Plain-assert tests for oob-console/render-ser2net.py (no pytest dep)."""
import subprocess, sys, tempfile, pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
RENDER = REPO / "oob-console" / "render-ser2net.py"

SAMPLE = """\
slots:
  - slot: 1
    device: ncm-fgt01
    baud: 9600
    platform: fortigate
    usb_path: platform-fd500000.usb-usb-0:1.1:1.0
  - slot: 2
    device: ncm-cx01
    baud: 115200
    platform: aruba-cx
    usb_path: platform-fd500000.usb-usb-0:1.2:1.0
"""

def render(yaml_text):
    with tempfile.TemporaryDirectory() as td:
        ports = pathlib.Path(td, "ports.yaml"); ports.write_text(yaml_text)
        out = pathlib.Path(td, "ser2net.yaml")
        rules = pathlib.Path(td, "slots.rules")
        r = subprocess.run([sys.executable, str(RENDER), str(ports), str(out), str(rules)],
                           capture_output=True, text=True)
        return r, (out.read_text() if out.exists() else ""), \
               (rules.read_text() if rules.exists() else "")

r, ser2net, rules = render(SAMPLE)
assert r.returncode == 0, r.stderr
# ser2net: one connection per slot, port 3000+slot, device symlink, baud
assert "tcp,127.0.0.1,3001" not in ser2net  # binds all-interfaces inside netns
assert "3001" in ser2net and "3002" in ser2net
assert "/dev/d2-console/slot01" in ser2net and "/dev/d2-console/slot02" in ser2net
assert "9600n81" in ser2net and "115200n81" in ser2net
assert "ncm-fgt01" in ser2net  # trace log path carries device name
# udev fragment: ID_PATH-keyed symlink per slot
assert 'ENV{ID_PATH}=="platform-fd500000.usb-usb-0:1.1:1.0"' in rules
assert 'SYMLINK+="d2-console/slot01"' in rules

# duplicate slot numbers must fail loud
r2, _, _ = render(SAMPLE.replace("slot: 2", "slot: 1"))
assert r2.returncode != 0 and "duplicate" in r2.stderr.lower()

print("OK")
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python tests/test_render_ser2net.py`
Expected: FAIL — `render-ser2net.py` does not exist yet

- [ ] **Step 4: Write `oob-console/render-ser2net.py`**

```python
#!/usr/bin/env python3
"""Render ser2net.yaml + udev slot rules from ports.yaml.

Usage: render-ser2net.py <ports.yaml> <ser2net.yaml out> <slots.rules out>
Exits non-zero on duplicate slots, bad slot range, or missing fields.
Requires python3-yaml (installed by setup-oob.sh).
"""
import sys
import yaml

CONN_TMPL = """\
connection: &slot{slot:02d}
  accepter: telnet(rfc2217),tcp,{port}
  connector: serialdev,/dev/d2-console/slot{slot:02d},{baud}n81,local
  options:
    banner: "D2 OOB console — {device} ({platform}) slot {slot}\\r\\n"
    trace-both: '/var/log/oob-console/{device}-\\p-\\Y\\M\\D.log'
    trace-timestamp: true
    max-connections: 1
"""

RULE_TMPL = ('SUBSYSTEM=="tty", ENV{{ID_PATH}}=="{usb_path}", '
             'SYMLINK+="d2-console/slot{slot:02d}", ENV{{ID_MM_DEVICE_IGNORE}}="1"\n')


def main():
    ports_f, ser2net_f, rules_f = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(ports_f) as f:
        data = yaml.safe_load(f)
    slots = data.get("slots") or []
    if not slots:
        sys.exit("render-ser2net: no slots defined in %s" % ports_f)
    seen = set()
    conns, rules = [], []
    for s in slots:
        try:
            n = int(s["slot"]); dev = str(s["device"])
            baud = int(s["baud"]); path = str(s["usb_path"])
            platform = str(s.get("platform", "unknown"))
        except (KeyError, TypeError, ValueError) as e:
            sys.exit("render-ser2net: bad slot entry %r (%s)" % (s, e))
        if not 1 <= n <= 16:
            sys.exit("render-ser2net: slot %d out of range 1-16" % n)
        if n in seen:
            sys.exit("render-ser2net: duplicate slot %d" % n)
        seen.add(n)
        conns.append(CONN_TMPL.format(slot=n, port=3000 + n, baud=baud,
                                      device=dev, platform=platform))
        rules.append(RULE_TMPL.format(usb_path=path, slot=n))
    with open(ser2net_f, "w") as f:
        f.write("%YAML 1.1\n---\n" + "\n".join(conns))
    with open(rules_f, "w") as f:
        f.write("# Rendered by render-ser2net.py from ports.yaml — do not edit\n"
                + "".join(rules))


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python tests/test_render_ser2net.py`
Expected: `OK`

- [ ] **Step 6: Gitignore the rendered/per-site files, commit**

Append to `.gitignore`:

```
oob-console/ports.yaml
oob-console/ser2net.yaml
oob-console/slots.rules
oob-console/logs/
```

```bash
git add oob-console/ports.yaml.example oob-console/render-ser2net.py tests/test_render_ser2net.py .gitignore
git commit -m "feat(oob): ports.yaml renderer (ser2net.yaml + udev slot rules) with tests"
```

### Task 6: setup-oob.sh (idempotent host installer + verify)

**Files:**
- Create: `oob-console/host/setup-oob.sh`

- [ ] **Step 1: Write the installer**

```bash
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

# 3. networkd: pin wwan0 name + DHCP-into-table-200.
install -m 0644 "$HOSTD/10-wwan0.link"    /etc/systemd/network/10-wwan0.link
install -m 0644 "$HOSTD/30-wwan0.network" /etc/systemd/network/30-wwan0.network
systemctl enable --now systemd-networkd >/dev/null 2>&1 || true
networkctl reload 2>/dev/null || true

# 4. Routing + power + watchdog units.
install -m 0755 "$HOSTD/oob-watchdog.sh" /usr/local/sbin/oob-watchdog.sh
for u in oob-routing.service sim7600-power.service oob-watchdog.service oob-watchdog.timer; do
    install -m 0644 "$HOSTD/$u" "/etc/systemd/system/$u"
done
systemctl daemon-reload
systemctl enable --now oob-routing.service sim7600-power.service oob-watchdog.timer

# 5. Pin the modem USB mode to RNDIS (persists in modem NVRAM). Skip when
#    already pinned: PID 9011 = RNDIS composite on SIM7600.
if [[ -e /dev/d2-modem ]]; then
    cur_pid=$(cat /sys/bus/usb/devices/*/idProduct 2>/dev/null | grep -m1 '^90' || true)
    if [[ "$cur_pid" != "9011" ]]; then
        echo "[oob] pinning modem USB mode to RNDIS (AT+CUSBPIDSWITCH=9011,1,1) — modem will re-enumerate"
        printf 'AT+CUSBPIDSWITCH=9011,1,1\r' > /dev/d2-modem
        sleep 15
    fi
fi

# 6. Verify block — degrades gracefully when no SIM is fitted yet.
fail=0
say() { echo "[oob][verify] $*"; }
if compgen -G '/sys/bus/usb/devices/*/idVendor' >/dev/null \
   && grep -q 1e0e /sys/bus/usb/devices/*/idVendor 2>/dev/null; then
    say "modem enumerated: OK"
else
    say "FAIL: no SIM7600 (vendor 1e0e) on USB bus"; fail=1
fi
[[ -e /dev/d2-modem ]] && say "AT port /dev/d2-modem: OK" || { say "FAIL: /dev/d2-modem missing"; fail=1; }
ip link show wwan0 >/dev/null 2>&1 && say "wwan0 present: OK" || { say "FAIL: wwan0 missing (mode pin pending? re-run after re-enumeration)"; fail=1; }
ip rule | grep -q "from 172.31.250.0/29 lookup 200" && say "ip rule: OK" || { say "FAIL: ip rule missing"; fail=1; }
ip route show table 200 | grep -q blackhole && say "blackhole: OK" || { say "FAIL: blackhole route missing"; fail=1; }
if ip -4 addr show dev wwan0 2>/dev/null | grep -q inet; then
    say "carrier IP on wwan0: OK"
else
    say "WARN: no carrier IP on wwan0 (no SIM fitted, or not registered) — OOB path not live yet"
fi
(( fail == 0 )) || { echo "[oob] verify FAILED"; exit 1; }
echo "[oob] host layer OK"
```

- [ ] **Step 2: Syntax-check + commit**

Run: `bash -n oob-console/host/setup-oob.sh`
Expected: no output

```bash
git add oob-console/host/setup-oob.sh && git commit -m "feat(oob): setup-oob.sh idempotent host installer with verify block"
```

### Task 7: oob-console container image + entrypoint guard

**Files:**
- Create: `oob-console/Dockerfile`
- Create: `oob-console/entrypoint.sh`

- [ ] **Step 1: Write `oob-console/Dockerfile`**

```dockerfile
FROM alpine:3.20
RUN apk add --no-cache ser2net
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

- [ ] **Step 2: Write `oob-console/entrypoint.sh`**

```sh
#!/bin/sh
# Guard: refuse to run on a Pi with no 4G HAT. Covers the compose-profiles
# gotcha where an explicit `docker compose up -d oob-console` enables a
# disabled profile — on a HAT-less Pi this crash-loops visibly instead of
# half-running. /dev is bind-mounted from the host, so /dev/d2-modem is
# the HAT-present signal (created by udev, host netns irrelevant).
if [ ! -e /dev/d2-modem ]; then
    echo "oob-console: FATAL — /dev/d2-modem not present (no SIM7600 HAT?). Refusing to start." >&2
    exit 1
fi
if [ ! -f /etc/ser2net/ser2net.yaml ]; then
    echo "oob-console: FATAL — /etc/ser2net/ser2net.yaml missing (render-configs.sh not run?)." >&2
    exit 1
fi
mkdir -p /var/log/oob-console
exec ser2net -n -c /etc/ser2net/ser2net.yaml
```

- [ ] **Step 3: Commit**

```bash
git add oob-console/Dockerfile oob-console/entrypoint.sh && git commit -m "feat(oob): ser2net container image with HAT-presence entrypoint guard"
```

### Task 8: compose services (oob-tailscale + oob-console)

**Files:**
- Modify: `docker-compose.yml` (append after `netflow-proxy`, plus top-level `networks:` at end of file)

- [ ] **Step 1: Append the two services and the bridge network**

```yaml
  # ─── OOB console (4G HAT) ─────────────────────────────────────────────────
  # Opt-in per Pi: profiles default DISABLED (unlike every other service).
  # oob-tailscale owns an ISOLATED netns on the br-oob bridge — deliberately
  # NOT network_mode:host. The host ip rule steers 172.31.250.0/29 into
  # table 200 (wwan0-or-blackhole), so this pair can only ever egress via
  # 4G, and nothing else on the Pi can. Own node identity <hostname>-oob,
  # tag:oob, minted by the DEDICATED oob OAuth client (TS_OOB_AUTHKEY).
  oob-tailscale:
    image: tailscale/tailscale:v1.96.5@sha256:dbeff02d2337344b351afac203427218c4d0a06c43fc10a865184063498472a6
    container_name: oob-tailscale
    profiles: ["${DEPLOY_OOB_CONSOLE:-disabled}"]
    hostname: ${EDGE_HOSTNAME}-oob
    restart: unless-stopped
    networks:
      - oob
    dns:
      - 1.1.1.1
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    volumes:
      - ./oob-console/ts-state:/var/lib/tailscale
    environment:
      - TS_AUTHKEY=${TS_OOB_AUTHKEY:-}
      - TS_HOSTNAME=${EDGE_HOSTNAME}-oob
      - TS_STATE_DIR=/var/lib/tailscale
      - TS_USERSPACE=false
    # In-band fallback: consoles reachable from the Pi itself via
    # `telnet localhost 300N` (SSH in normally) — loopback-only publish,
    # does not weaken the 4G-only rule for remote access.
    ports:
      - "127.0.0.1:3001-3016:3001-3016"
    command: >
      sh -c "tailscaled &
      until tailscale status --json >/dev/null 2>&1; do sleep 2; done;
      tailscale up
      --authkey=$$TS_AUTHKEY
      --hostname=$$TS_HOSTNAME
      --advertise-tags=tag:oob && wait"
    healthcheck:
      test: ["CMD", "tailscale", "status", "--json"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

  # ser2net console server sharing oob-tailscale's netns. /dev is a ro
  # bind (device I/O still works; ro only blocks fs writes) because the
  # /dev/d2-console/* symlinks are relative and need their /dev/ttyUSB*
  # targets visible. cgroup rules grant char majors 188 (ttyUSB) and
  # 166 (ttyACM); hotplugged adapters appear without a recreate.
  oob-console:
    build: ./oob-console
    image: d2-edge-oob-console
    container_name: oob-console
    profiles: ["${DEPLOY_OOB_CONSOLE:-disabled}"]
    restart: unless-stopped
    network_mode: "service:oob-tailscale"
    depends_on:
      oob-tailscale:
        condition: service_healthy
    device_cgroup_rules:
      - "c 188:* rwm"
      - "c 166:* rwm"
    volumes:
      - /dev:/dev:ro
      - ./oob-console/ser2net.yaml:/etc/ser2net/ser2net.yaml:ro
      - ./oob-console/logs:/var/log/oob-console

networks:
  oob:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.name: br-oob
    ipam:
      config:
        - subnet: 172.31.250.0/29
```

- [ ] **Step 2: Validate compose parses with the profile off and on**

Run: `docker compose config --quiet` (if docker available locally; otherwise defer to pilot)
Then: `DEPLOY_OOB_CONSOLE=enabled EDGE_HOSTNAME=test TS_OOB_AUTHKEY=x docker compose config --quiet`
Expected: both exit 0. (On this Windows workstation `docker compose config` works without a daemon; if not, this validation runs as the first pilot step.)

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml && git commit -m "feat(oob): oob-tailscale + oob-console compose services on isolated br-oob bridge"
```

### Task 9: render-configs.sh + syslog-proxy log shipping

**Files:**
- Modify: `render-configs.sh` (append before final echo)
- Modify: `syslog-proxy/config/syslog-ng.conf.template` (append)
- Modify: `docker-compose.yml` (syslog-proxy volumes)

- [ ] **Step 1: Append OOB render block to `render-configs.sh`**

```bash
# ─── oob-console (ser2net) ────────────────────────────────────────────────
# Only when the OOB toggle is on AND the operator has written ports.yaml.
# Renders ser2net.yaml (mounted into the container) + slots.rules (udev
# fragment installed by setup-oob.sh on the next update.sh run).
if [[ "${DEPLOY_OOB_CONSOLE:-disabled}" == "enabled" ]]; then
    if [[ -f "${EDGE_DIR}/oob-console/ports.yaml" ]]; then
        python3 "${EDGE_DIR}/oob-console/render-ser2net.py" \
            "${EDGE_DIR}/oob-console/ports.yaml" \
            "${EDGE_DIR}/oob-console/ser2net.yaml" \
            "${EDGE_DIR}/oob-console/slots.rules"
        echo "[oob] rendered OK ($(grep -c '^connection:' "${EDGE_DIR}/oob-console/ser2net.yaml") slots)"
    else
        echo "[ERROR] DEPLOY_OOB_CONSOLE=enabled but oob-console/ports.yaml missing" >&2
        exit 1
    fi
fi
```

- [ ] **Step 2: Append OOB file source to `syslog-ng.conf.template`** (read the template first; match its existing destination/log-path names for the Graylog GELF destination — the block below assumes destination `d_graylog` and adapts if named differently)

```
# OOB console session transcripts → Graylog. Directory exists (empty) on
# every Pi; wildcard-file is a cheap no-op where OOB is disabled.
source s_oob_console {
    wildcard-file(
        base-dir("/var/log/oob-console")
        filename-pattern("*.log")
        recursive(no)
        flags(no-parse)
        program-override("oob-console")
    );
};
log { source(s_oob_console); destination(d_graylog); };
```

- [ ] **Step 3: Mount the logs dir into syslog-proxy in `docker-compose.yml`**

Add to the existing `syslog-proxy` volumes list:

```yaml
      - ./oob-console/logs:/var/log/oob-console:ro
```

- [ ] **Step 4: Verify + commit**

Run: `bash -n render-configs.sh`
Expected: no output

```bash
git add render-configs.sh syslog-proxy/config/syslog-ng.conf.template docker-compose.yml
git commit -m "feat(oob): render ser2net config; ship console transcripts via syslog-proxy"
```

### Task 10: preflight.sh gating (conditional keys + HAT presence)

**Files:**
- Modify: `shared/scripts/preflight.sh`

- [ ] **Step 1: Add `DEPLOY_OOB_CONSOLE=disabled` to `heal_defaults`** (discoverability heal, same pattern as the other toggles — note the OOB toggle heals to **disabled**, unlike the rest)

```bash
        [DEPLOY_OOB_CONSOLE]=disabled
```

- [ ] **Step 2: Append the OOB conditional block after the required-key loop** (locate the loop that iterates `required[@]` and add after it)

```bash
# --- OOB console: conditional requirements + hardware gating ------------
# Only when the operator has switched the OOB stack on. Both directions:
# enabled-without-HAT aborts (flag on wrong Pi / HAT not seated);
# HAT-without-enabled is a non-fatal notice (freshly fitted, not yet on).
if [[ -f "$ENV_FILE" ]]; then
    oob_flag=$(grep -E '^DEPLOY_OOB_CONSOLE=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '[:space:]')
    hat_present=false
    if compgen -G '/sys/bus/usb/devices/*/idVendor' >/dev/null 2>&1 \
       && grep -q 1e0e /sys/bus/usb/devices/*/idVendor 2>/dev/null; then
        hat_present=true
    fi
    if [[ "${oob_flag:-disabled}" == "enabled" ]]; then
        for k in OOB_APN TS_OOB_AUTHKEY; do
            v=$(grep -E "^${k}=" "$ENV_FILE" | tail -1 | cut -d= -f2-)
            [[ -n "$v" && "$v" != "REPLACE_ME" ]] || fail "DEPLOY_OOB_CONSOLE=enabled but $k is empty"
        done
        [[ -f "$COMPOSE_DIR/oob-console/ports.yaml" ]] \
            || fail "DEPLOY_OOB_CONSOLE=enabled but oob-console/ports.yaml missing"
        $hat_present || fail "DEPLOY_OOB_CONSOLE=enabled but no SIM7600 (USB vendor 1e0e) found — wrong Pi, or HAT not seated"
    elif $hat_present; then
        echo "  preflight: NOTE 4G HAT detected but DEPLOY_OOB_CONSOLE is not 'enabled'" >&2
    fi
fi
```

- [ ] **Step 3: Syntax-check + commit**

Run: `bash -n shared/scripts/preflight.sh`
Expected: no output

```bash
git add shared/scripts/preflight.sh && git commit -m "feat(oob): preflight — conditional OOB keys + bidirectional HAT gating"
```

### Task 11: update.sh integration

**Files:**
- Modify: `shared/scripts/update.sh`

- [ ] **Step 1: Add the setup-oob heal** (in step `[3/6]`, after the lego-radsec block, before `echo "  OK"`; uses the same `deploy_flag` semantics but that function is defined later — read the flag inline, matching the file's existing style in the CONTROLLER_URL migration)

```bash
# OOB console host layer (4G HAT): idempotent install of udev/networkd/
# routing/watchdog + modem mode pin. STRICTLY gated — only runs when the
# operator has enabled OOB on this Pi; every other Pi is untouched.
# Unlike the fail-soft heals above this one is fail-LOUD (no || true):
# a half-installed OOB layer must abort the deploy, not limp.
if grep -qE '^DEPLOY_OOB_CONSOLE=enabled' "$EDGE_DIR/.env" 2>/dev/null; then
    bash "$EDGE_DIR/oob-console/host/setup-oob.sh"
fi
```

- [ ] **Step 2: Add both services to the DEPLOY partition loop** (extend the existing `for entry in ...` list)

```bash
             oob-tailscale:DEPLOY_OOB_CONSOLE \
             oob-console:DEPLOY_OOB_CONSOLE \
```

Note: `deploy_flag` returns `${val:-enabled}` — for the OOB key an *absent* key would count enabled, which is wrong for a disabled-by-default service. The preflight heal (Task 10 Step 1) guarantees the key exists on every Pi after one update run, and compose's own `${DEPLOY_OOB_CONSOLE:-disabled}` default is the backstop: with the key absent, `deploy_flag` says enabled → `up -d oob-tailscale oob-console` names the services → compose auto-enables the profile → entrypoint guard kills it on HAT-less Pis. To close even that window, special-case the default:

```bash
# deploy_flag defaults absent keys to 'enabled' (correct for the original
# eight). OOB is disabled-by-default: absent key must mean OFF.
oob_flag=$(deploy_flag DEPLOY_OOB_CONSOLE)
if ! grep -qE '^DEPLOY_OOB_CONSOLE=' "$EDGE_DIR/.env" 2>/dev/null; then
    oob_flag=disabled
fi
```

…and use `oob_flag` for the two OOB entries instead of the generic loop. Concretely: keep the two services OUT of the `for entry` list and add after the loop:

```bash
if [[ "$oob_flag" == "enabled" ]]; then
    RECREATE+=(oob-tailscale oob-console)
else
    DISABLED+=(oob-tailscale oob-console)
fi
```

- [ ] **Step 3: Build the oob-console image when enabled** (in step `[5/6]`, after the d2-agent build block)

```bash
if [[ " ${RECREATE[*]} " == *" oob-console "* ]]; then
    docker compose build oob-console
    echo "  OK (oob-console)"
fi
```

- [ ] **Step 4: Syntax-check + commit**

Run: `bash -n shared/scripts/update.sh`
Expected: no output

```bash
git add shared/scripts/update.sh && git commit -m "feat(oob): update.sh — gated setup-oob heal, service partition, image build"
```

### Task 12: Regression check on validation Pi (OOB disabled path)

The fleet-shared files (preflight/update/render/compose) changed; per the two-Pi validation rule, prove the disabled path is a no-op **before** touching the pilot Pi. Validation Pi: `admin@192.168.21.16` (allowlisted).

- [ ] **Step 1: Push branch, point validation Pi at it**

```bash
git push -u origin feat/oob-console
ssh -i ~/.ssh/id_claude admin@192.168.21.16 "cd /opt/d2-edge && sudo -u admin git fetch && sudo -u admin git checkout feat/oob-console"
```

- [ ] **Step 2: Run update.sh; assert OOB stayed off**

```bash
ssh -i ~/.ssh/id_claude admin@192.168.21.16 "sudo bash /opt/d2-edge/shared/scripts/update.sh"
```

Expected: preflight heals `DEPLOY_OOB_CONSOLE=disabled` into `.env`; `Services disabled:` line includes `oob-tailscale oob-console`; no oob containers in `docker ps`; no `/etc/udev/rules.d/99-d2-console.rules`; all 8 existing services healthy.

- [ ] **Step 3: Return validation Pi to main**

```bash
ssh -i ~/.ssh/id_claude admin@192.168.21.16 "cd /opt/d2-edge && sudo -u admin git checkout main && sudo bash shared/scripts/update.sh"
```

### Task 13: Pilot deploy on the new test Pi (partial verify — no SIM yet)

**Execution inputs required from Jared before this task:** test Pi IP + SSH approval, `EDGE_HOSTNAME`, `TS_OOB_AUTHKEY` (see Task 14 — the OAuth client must exist first), `OOB_APN` (any placeholder-free value; carrier APN once SIM arrives).

- [ ] **Step 1: Standard fresh-Pi bootstrap** (fresh-Pi gotchas apply: set `preserve_hostname: true` in cloud-init BEFORE hostnamectl; watch for the trixie apt empty-index silent-success). Follow the normal bootstrap runbook: clone repo to `/opt/d2-edge`, checkout `feat/oob-console`, fill `.env` (staging tenant values), `sudo bash shared/scripts/bootstrap.sh`.
- [ ] **Step 2: Fit check** — HAT seated, USB jumper into a USB **2.0** port, `usb_max_current_enable=1` in `/boot/firmware/config.txt`, 27W PSU.
- [ ] **Step 3: Enable OOB** — in `.env`: `DEPLOY_OOB_CONSOLE=enabled`, `OOB_APN=<carrier apn>`, `TS_OOB_AUTHKEY=<oauth secret>`. Write `oob-console/ports.yaml` with one real slot (any USB-serial adapter + a lab device, or loop to a second adapter). Get `usb_path` via `udevadm info -q property /dev/ttyUSB0 | grep ID_PATH=`.
- [ ] **Step 4: Deploy** — `sudo bash /opt/d2-edge/shared/scripts/update.sh`.
  Expected: setup-oob verify prints all OK except `WARN: no carrier IP on wwan0` (no SIM); `oob-tailscale` + `oob-console` containers up; `<hostname>-oob` visible in tailnet **only after SIM** (tailscaled cannot reach the coordination server via a blackholed table 200 — expected dark until SIM arrives).
- [ ] **Step 5: What CAN be verified SIM-less** — modem enumerated + mode pinned (`wwan0` exists); `ip rule`/blackhole present; fail-closed proof: `docker exec oob-tailscale ping -c2 -W2 1.1.1.1` must FAIL (blackhole) while `ping` from the host still works; in-band console path: `telnet localhost 3001` from the Pi reaches the ser2net banner; transcript file appears under `oob-console/logs/` and ships to Graylog (`program:oob-console`).
- [ ] **Step 6: When the SIM arrives** — insert, `sudo systemctl restart systemd-networkd && sudo systemctl start oob-routing`, confirm carrier IP on wwan0, `<hostname>-oob` joins the tailnet, and an end-to-end `telnet <hostname>-oob:3001` from the workstation (over 4G!) reaches the console. Confirm PWRKEY GPIO for this HAT revision; if not GPIO 6, set `OOB_PWRKEY_GPIO` in `/etc/default/d2-oob` AND update the plan default.
- [ ] **Step 7: Record pilot findings** — burn actual values (PWRKEY GPIO, mode-pin behaviour, RNDIS PID) back into `setup-oob.sh` defaults + spec; commit.

### Task 14: One-time central/tailnet prerequisites (manual, Jared or with Jared's creds)

- [ ] Tailscale admin: add `tag:oob` to `tagOwners`; create **new OAuth client** scoped `Keys → Auth Keys → Write`, tag `tag:oob` only; ACL rule: admin group → `tag:oob:3001-3016`. (Existing `tag:edge-pi` rules untouched — Netflow→Zabbix:443 rule is never-delete.)
- [ ] Graylog: stream `OOB console transcripts` matching `program:oob-console`, routed to a restricted role (transcripts include keystrokes → credentials).
- [ ] Zabbix: confirm the Pi host's `net.if` LLD discovers `wwan0` once live; add "wwan0 no carrier" trigger. (May be automatic via existing interface discovery — check before adding.)

---

## Self-Review Notes

- **Spec coverage:** §2 hardware → Task 13 steps 1–2; §4 host layer → Tasks 2–4, 6; §5 container → Tasks 5, 7, 8; §6 access paths → Task 8 (loopback ports) + Task 13 step 5; §7 fleet integration → Tasks 1, 9–11; §8 audit → Task 9 + Task 14; §10 failure modes exercised in Tasks 12–13; §11 runbook = Task 13; §12 phase 2 explicitly out.
- **Deviation from spec, intentional:** spec's `oob-watchdog` pings even pre-SIM; plan version skips until wwan0 has an address (prevents pointless PWRKEY cycles on the SIM-less pilot). Spec says ModemManager "telemetry only if present" — plan doesn't install it at all (YAGNI; signal strength readable later via AT if wanted).
- **Type consistency check:** `DEPLOY_OOB_CONSOLE` / `OOB_APN` / `TS_OOB_AUTHKEY` names identical across Tasks 1, 8, 9, 10, 11; slot symlink format `slot%02d` identical in renderer (Task 5) and ser2net template; `/dev/d2-modem` consistent across Tasks 2, 4, 6, 7; bridge subnet `172.31.250.0/29` identical in Tasks 4 (routing) and 8 (compose).
