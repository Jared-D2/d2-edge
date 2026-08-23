# OOB Console via 4G HAT — Design

**Date:** 2026-08-12
**Status:** Draft — pending review
**Scope:** d2-edge Pi fleet, opt-in per Pi

## 1. Purpose

Give selected edge Pis an out-of-band (OOB) management path: a Waveshare SIM7600X
4G HAT provides an independent uplink, and USB serial adapters provide console
access to site devices (firewall, core switch, etc.). When the primary WAN — or
the site's whole in-band network — is down, an engineer reaches device consoles
over the tailnet via 4G.

The OOB path is **console access only**. It is not a WAN failover: the main
stack (Zabbix, syslog, NetFlow, RADIUS proxies) never uses the 4G link.

### Goals

- Reach device serial consoles over 4G when the site is otherwise unreachable.
- Structurally independent path: shares no routing, no Tailscale identity, and
  no failure domain with the in-band stack.
- Opt-in per Pi: only Pis with the HAT fitted run any of it; the rest of the
  fleet is byte-for-byte unaffected.
- Replicable: a new site is hardware fitting + 3 `.env` keys + one YAML file +
  `update.sh`. No hand-run commands.
- Full audit trail of console sessions into Graylog.

### Non-goals (v1)

- WAN failover for the monitoring stack (structure permits adding a metered,
  rate-limited mode later; see §12).
- Power-cycling hung devices (needs smart PDU / relay hardware — known gap).
- OOB access to the Pi itself if the Pi wedges (mitigated by hardware watchdog;
  accepted limit).
- NetBox modelling of HAT presence and console cabling (phase 2).
- Weekly synthetic end-to-end console test from central (phase 2).

## 2. Hardware standard

| Item | Standard | Why |
|---|---|---|
| 4G HAT | Waveshare SIM7600**G-H** (or E-H) | Must support LTE **B28 (700 MHz)** for AU regional coverage. SIM7600**A** (Americas) will not register — verify before fitting. |
| HAT connection | USB jumper into a Pi **USB 2.0** port | Keeps USB 3.0 free for the console hub. |
| SIM | Data SIM, **PIN disabled** at activation, ≥1 GB/month | PIN off = one less secret and one less wedge state. CGNAT is fine (Tailscale); do not buy static IP / private APN. |
| Consoles, 1–2 devices | USB-serial adapters direct into Pi | |
| Consoles, 3+ devices | **Powered** USB hub + adapters | Unpowered hubs full of FTDI/CH340s brown out; SIM7600 TX bursts draw ~2 A. |
| Pi 5 power | 27 W PSU + `usb_max_current_enable=1` | Same reason. |
| Labelling | Printed slot numbers on hub ports | Slot identity = physical USB port (see §5). Cable moves require a `ports.yaml` edit. |

## 3. Architecture overview

```
Engineer ──tailnet──▶ <pi>-oob (tag:oob, own Tailscale node)
                          │ inside isolated container netns
                          ▼
                      ser2net :3001..:300N ──▶ /dev/d2-console/slotNN ──▶ device consoles
                          │
   container bridge 172.31.250.0/29
                          │  ip rule: from 172.31.250.0/29 → table 200
                          ▼
                      wwan0 (SIM7600, RNDIS) ──▶ 4G carrier ──▶ internet
```

Two containers, gated by one profile toggle:

- **`oob-tailscale`** — owns an isolated network namespace on a dedicated
  Docker bridge (`172.31.250.0/29`). Runs its own `tailscaled` with its own
  state dir and its own node identity `<EDGE_HOSTNAME>-oob`, advertising
  `tag:oob`. Not `network_mode: host` — this is a deliberate break from the
  fleet convention, because isolation is the point.
- **`oob-console`** — `network_mode: "service:oob-tailscale"` (shares the
  netns). Runs ser2net 4.x exposing one TCP port per console slot.

Both: `profiles: ["${DEPLOY_OOB_CONSOLE:-disabled}"]` — the only
disabled-by-default service in the stack.

### Why this shape (alternatives rejected)

- **Host-network + shared Tailscale node, UID-marked traffic:** fewer parts,
  but two `tailscaled` in one netns is fragile, the ACL surface is shared with
  `tag:edge-pi`, and "is this actually on 4G?" becomes an iptables owner-match
  you trust rather than a subnet you can see.
- **4G as default-route failover:** not out-of-band at all, and a multi-day
  outage puts syslog + NetFlow on a metered SIM.

The chosen design fails closed: no modem → OOB packets hit a blackhole route,
never the LAN. And the in-band fallback (loopback ports, §6) means a dead modem
still leaves consoles reachable via normal SSH to the Pi.

## 4. Host layer

Everything below lives in the repo under `oob-console/host/` and is installed
by `setup-oob.sh` (§7). The modem is managed on the **host**, not in a
container: Docker starting late or a container crash-loop must never take the
OOB uplink down.

### Modem bring-up

- The SIM7600 is pinned to **RNDIS mode** once via `AT+CUSBPIDSWITCH`
  (persists in modem NVRAM; done by `setup-oob.sh`). It presents a network
  interface with internal DHCP+NAT, plus `/dev/ttyUSB0-4` AT/diag ports.
- A systemd **`.link`** file matches the modem interface (driver/VID:PID) and
  pins the name **`wwan0`** — the stable anchor everything else references.
  (Without this it enumerates as `usb0`/`eth1` unpredictably.)
- `30-wwan0.network` (systemd-networkd): DHCP, with routes forced into
  **table 200 only** — never the main table.
- ModemManager is **telemetry only** (signal, registration) if present; it does
  not own the data path.
- `sim7600-power.service`: pulses PWRKEY via GPIO if no modem has enumerated
  30 s after boot (some HAT revisions don't auto-power). PWRKEY GPIO pin is a
  config variable — it differs by HAT revision; pilot confirms the value.

### Policy routing — the isolation mechanism

- `ip rule from 172.31.250.0/29 lookup 200 priority 200` — the OOB bridge
  subnet, nothing else.
- Table 200: wwan0 DHCP default route **plus** `blackhole default metric 1000`.
  Modem down → OOB traffic dies at the blackhole; it cannot leak out `eth0`.
- Routing decision precedes Docker's MASQUERADE, so the rule matches container
  source addresses correctly.
- Nothing else on the Pi has a rule into table 200, so no other service can
  use 4G — the data cap is structurally protected.

### Modem self-heal

`oob-watchdog.timer` (host): every 5 min, probe (AT, registration, CSQ,
ping via `wwan0`, `-oob` tailnet liveness, data budget) → record
`/run/d2-oob/status` → heal, non-destructively. LTE modules wedge
silently ("registered, passing nothing", or — pilot 2026-08-23 —
enumerated on USB with the function side dead) — without local self-heal
the first real outage finds the modem in a state a replug would have
fixed. Ladder (as built; the original CFUN → PWRKEY sketch was replaced by
the 2026-08-13 hardening review + the 2026-08-23 incident):

- absent from USB → PWRKEY power-ON pulse, ≤1/h (the only PWRKEY use — a
  3 s hold on a running SIM7600 is power-OFF).
- on USB, AT dead ×2 probes → **USB recovery ladder**: USBDEVFS_RESET port
  reset → if ttyUSB/wwan0 not back (device unconfigured) driver
  unbind/bind of the device path → restart `oob-tailscale` + `oob-console`
  (tailscaled sits on a dead control connection after a modem bounce).
  Manual: `oob-watchdog.sh --usb-recover`.
- registered, no data ×3 → `AT+CFUN=1,1` ×2 → USB recovery ladder.
- data OK, `-oob` node offline ×2 → restart the oob pair (≤1/30 min).
- not registered → no action (carrier/SIM condition, not a modem wedge).

### Data budget controls

- `tc` egress cap ~2 Mbit on `wwan0` (egress only — ingress shaping needs an
  ifb mirror and isn't worth it; egress is what runs away).
- `vnstat` on `wwan0` + Zabbix `net.if` items and a "wwan0 no carrier" trigger.
- Idle Tailscale keepalive is a few hundred MB/month — inside the 1 GB budget.

### udev — console slot identity

`99-d2-console.rules`:

- Symlinks `/dev/d2-console/slotNN` keyed on **`ID_PATH`** (physical USB
  topology), NOT `ID_SERIAL` — CH340 adapters have no unique serial.
  Consequence (accepted): slot identity = physical hub port; hub ports carry
  printed labels; moving a cable means editing `ports.yaml`.
- `ENV{ID_MM_DEVICE_IGNORE}="1"` on every console slot — otherwise
  ModemManager probes unknown serial ports with AT commands, i.e. **types
  garbage into a live firewall console**. Load-bearing; do not remove.
- The modem's own `/dev/ttyUSB0-4` never match slot rules (different
  `ID_PATH`), so no collision.
- `setup-oob.sh` removes **`brltty`**, which hijacks CH340/CP2102 adapters on
  modern Debian.

## 5. Console serving (`oob-console` container)

- **ser2net 4.x**, one TCP listener per slot from 3001 upward, telnet/RFC2217.
- Binding `0.0.0.0` inside the netns is safe: the netns's only ingress is
  `tailscale0` (governed by ACL) and the bridge (host-only).
- Device access: bind-mount **`/dev:/dev:ro`** plus `device_cgroup_rules` for
  char majors 188 (`ttyUSB`) and 166 (`ttyACM`). The full-`/dev` bind is
  required because `/dev/d2-console/slotNN` are relative symlinks to
  `../ttyUSBn` — mounting only the symlink dir leaves dangling links. Hotplug
  works without recreating the container; ser2net opens only configured slots.
- **Entrypoint guard:** exits non-zero if `wwan0` does not exist. Guards the
  known compose-profiles gotcha where an explicit
  `docker compose up -d oob-console` enables a disabled profile — on a HAT-less
  Pi this now crash-loops visibly instead of half-running.

### Per-site config: `oob-console/ports.yaml`

Gitignored; `ports.yaml.example` committed. Rendered into `ser2net.yaml` by
`render-configs.sh`.

```yaml
slots:
  - slot: 1            # → /dev/d2-console/slot01 → TCP 3001
    device: ncm-fgt01  # free text; used in log filenames + Graylog fields
    baud: 9600
    platform: fortigate
  - slot: 2
    device: ncm-cx01
    baud: 115200
    platform: aruba-cx
```

Shape deliberately mirrors NetBox `ConsoleServerPort` → `ConsolePort` cabling
so a phase-2 generator can emit this file from NetBox.

## 6. Access paths

| Path | How | When |
|---|---|---|
| OOB (4G) | `telnet <pi>-oob:300N` over tailnet | Site in-band network down — the reason this exists |
| In-band fallback | SSH to Pi as normal → `telnet localhost 300N` | LAN fine, or modem hardware dead; via loopback-published ports on the host — does not weaken the 4G-only rule |

Transport security: telnet is plaintext, but the OOB path runs entirely inside
WireGuard (tailnet) and the fallback inside SSH. Authorisation is the Tailscale
ACL on `tag:oob` (§8) — ser2net itself does no auth.

## 7. Fleet integration & deploy gating

**Constraint: only Pis with the HAT fitted run any part of this.** Three
layers enforce it:

1. **Off by default.** `DEPLOY_OOB_CONSOLE=disabled` in `.env.template`.
   Fleet-wide `update.sh` / Ansible rollout starts OOB on zero Pis.
2. **Preflight checks hardware, both directions.** In `preflight.sh`:
   - `enabled` + no SIM7600 on USB (vendor `1e0e` in `lsusb`) → **abort**
     (flag on wrong Pi, or HAT not seated).
   - HAT present + `disabled` → non-fatal notice (legit state: freshly
     fitted, not yet enabled).
3. **Entrypoint guard** (§5) as last line of defence.

### `setup-oob.sh` (idempotent installer)

Runs only when `DEPLOY_OOB_CONSOLE=enabled`; invoked by `update.sh` each
deploy, so host state self-heals like the rest of the stack. Steps: install
udev/networkd/systemd payload → remove brltty → pin modem USB mode (skip if
already pinned) → reload → **verify block**: modem enumerated, `wwan0` up with
carrier IP, table 200 populated, blackhole present, `ip rule` in place. Any
verify failure exits non-zero and fails the deploy loudly.

### New `.env` keys — conditionally validated

`DEPLOY_OOB_CONSOLE`, `OOB_APN`, `TS_OOB_AUTHKEY`. `preflight.sh` requires
them non-empty **only when the toggle is `enabled`** — HAT-less Pis must
deploy exactly as today with none of them set.

### Tailscale (one-time, fleet-level)

- New **dedicated OAuth client** scoped to `tag:oob` only → `TS_OOB_AUTHKEY`.
  The existing fleet client cannot mint `tag:oob` keys, and extending it would
  couple the two identities this design separates.
- ACL: add `tag:oob` to `tagOwners`; access rule granting **admin group only**
  → `tag:oob:3001-3016`. (Existing `tag:edge-pi` rules untouched, including
  the never-delete Netflow→Zabbix:443 rule.)

## 8. Audit trail

- ser2net `trace-both` per slot → `oob-console/logs/<device>-<date>.log`.
- **Full transcript including keystrokes** (decision: audit value of
  break-glass sessions outweighs password capture; one-line change to
  output-only if revisited).
- New file source in the existing `syslog-proxy` ships logs → Graylog
  `:12203` (GELF, `_tenant_id` set) into a **restricted-role** stream —
  transcripts contain credentials typed at device login prompts.
- Connect/disconnect events carry the source tailnet IP; `tailscale whois`
  resolves it to a person.

## 9. Security considerations

- **Blast-radius separation:** `tag:oob` node compromise ≠ `tag:edge-pi`
  compromise; separate OAuth clients; separate state dirs.
- **The Pi becomes the site's highest-value object** — console to firewall +
  core switch. Physical security of the Pi + hub now matters more.
- **Break-glass credentials:** every device on a slot needs a documented local
  emergency account (vaulted password) — console access exists precisely for
  when RADIUS is unreachable. Devices should have `exec-timeout` so abandoned
  sessions don't sit logged in. (Rollout checklist item, not code.)
- Transcript stream in Graylog is restricted-role (§8).

## 10. Failure modes

| Failure | Behaviour |
|---|---|
| Modem dead / no carrier | Table 200 blackhole — no LAN leak. Watchdog attempts CFUN reset → PWRKEY cycle. Zabbix trigger fires. Consoles still reachable in-band (§6). |
| Container crash-loop | Host uplink unaffected (modem is host-managed). In-band path unaffected. |
| Docker down | OOB console down (accepted — consoles are container-served), uplink still up for nothing. Pi hardware watchdog (`RuntimeWatchdogSec`) is the mitigation for full-Pi wedges. |
| Flag enabled, no HAT | Preflight aborts deploy. |
| Explicit `up oob-console` on HAT-less Pi | Entrypoint guard crash-loops visibly. |
| Data-cap runaway | Structurally prevented (only OOB subnet routes to 4G) + tc cap + vnstat/Zabbix visibility. |
| Adapter unplugged/moved | Slot symlink vanishes; ser2net reports connection failure on that port; hotplug re-attach needs no container restart. |

## 11. Replication — per-site runbook (~15 min after pilot)

1. Fit HAT (verify G-H/E-H variant) + SIM (PIN off), jumper → USB 2.0 port;
   console cables → labelled hub ports. *(~10 min)*
2. Set `DEPLOY_OOB_CONSOLE=enabled`, `OOB_APN`, `TS_OOB_AUTHKEY` in `.env`. *(1 min)*
3. `cp ports.yaml.example ports.yaml`; fill slot/device/baud rows. *(2 min)*
4. `sudo bash /opt/d2-edge/shared/scripts/update.sh` — runs setup-oob, renders,
   deploys, verifies. *(2 min)*
5. Confirm `<pi>-oob` in tailnet; open one console over it. *(2 min)*

The **first** site is the pilot and will take longer: confirm PWRKEY GPIO for
the HAT revision, confirm RNDIS mode pin, burn down modem quirks into
`setup-oob.sh` defaults.

## 12. Phase 2 (explicitly out of v1)

- Weekly synthetic OOB test from central: connect to each `tag:oob` node, open
  a console, confirm a prompt, record pass/fail. (A dark OOB link is a broken
  OOB link; v1 covers link-liveness via watchdog + Zabbix, not end-to-end.)
- NetBox: HAT presence (inventory/custom field, same spirit as `has_edge_pi`)
  + console cabling as `ConsoleServerPort`s; generate `ports.yaml` from NetBox.
- Optional metered WAN-failover mode (rate-limited, per-Pi opt-in) — routing
  structure already permits it.
- Smart PDU / relay integration for power-cycling hung devices.

## 13. Implementation surface (for the plan)

| Area | Changes |
|---|---|
| `docker-compose.yml` | +`oob-tailscale`, +`oob-console` (profile-gated, disabled default) |
| `oob-console/` (new) | `host/` payload, `setup-oob.sh`, `ports.yaml.example`, `ser2net.yaml.tmpl`, entrypoint |
| `render-configs.sh` | Render ser2net.yaml from ports.yaml when enabled |
| `shared/scripts/preflight.sh` | Conditional key validation + HAT presence checks |
| `shared/scripts/update.sh` | Invoke setup-oob.sh when enabled |
| `.env.template` | 3 new keys, documented |
| Tailnet (manual, one-time) | OAuth client for `tag:oob`, tagOwners, ACL rule |
| Graylog (manual, one-time) | Restricted stream/role for console transcripts |
| Zabbix (one-time) | wwan0 items + no-carrier trigger |

---

## 14. Pilot findings addendum (2026-08-13, d2-lab-pi01)

Full E2E proven: workstation → tailnet → 4G (ALDI/Telstra wholesale, APN
mdata.net.au) → ser2net → FortiGate (JC-FG61E) console; SIM-in cold boot
self-assembles unattended. Six defects found and fixed during the pilot —
all now on this branch:

1. **Blackhole metric** must be WORSE than networkd's DHCP default (1024).
   Originally 1000 → all OOB egress blackholed even with live carrier.
   Now 2000.
2. **`throw 172.31.250.0/29` required in table 200** — the from-subnet ip
   rule otherwise captures kernel reverse-path validation for the bridge,
   silently breaking gateway ARP (zero container egress).
3. **networkd deletes "foreign" RPDB rules/routes on reconfigure**
   (fail-open). `ManageForeignRoutingPolicyRules=no` +
   `ManageForeignRoutes=no` conf.d drop-in; oob-routing re-asserts every
   setup run.
4. **NetworkManager activates unpinned wired profiles on wwan0** (RNDIS =
   ethernet class) — took eth0 down on the pilot. NM unmanaged-devices
   drop-in (wwan0/br-oob/veth*/docker0); also pin the wired profile's
   interface-name.
5. **Alpine ser2net is 3.5.1** (line-based config, cannot parse YAML,
   binds nothing, logs nothing). Image now debian:trixie-slim (ser2net 4.x).
6. **Modem AT port is USB interface 04 in RNDIS mode** (02 = diag).
   udev symlink rules are PID-conditional (9001→02, 9011→04).

Operational facts (fleet-relevant):

- PDP type must be `"IP"` — `IPV4V6` yields a v6-only session on
  Telstra-wholesale SIMs (no IPv4). setup-oob enforces OOB_APN on PDP
  profile 1 via `oob-at.py` and resets the modem when changing it.
- The classic "SIM7600X 4G HAT" auto-powers at boot; PWRKEY pulse was
  never needed on the pilot. Its "USB TO UART" micro-USB socket hosts an
  onboard CP2102 that masquerades as a console adapter — the data cable
  belongs in the socket marked "USB". Antenna pigtail → MAIN.
- The RNDIS modem-link IP (192.168.225.x) appears even with no SIM — it
  proves the USB data path, not cellular registration.
- ser2net silently skips binding a slot whose serial device is absent at
  startup: after plugging an adapter, restart oob-console. compose now
  carries `depends_on: restart: true` so oob-console follows
  oob-tailscale netns recreation automatically.
- docker-proxy accepts loopback connections even when the backend is
  dead — a bare TCP connect on 127.0.0.1:300N is NOT proof ser2net is up;
  expect the banner.
- Convention: keep the modem's spare AT port as a synthetic self-test
  slot (connect → `AT` → `OK`) on every OOB Pi.
- USB 3.0 ports are fine for console adapters; the "USB 2.0 for the
  modem" guidance is about the modem itself.

### 14.1 Addendum 2026-08-23 — cold-boot dead modem (d2-lab-pi01)

Incident: Pi powered on after ~6 days off. Modem enumerated at t=5 s
(`1e0e:9011`, 5 option ttys + rndis, `/dev/d2-modem` → ttyUSB2 = interface
04, correct) but its function side never came up: wwan0 had carrier and no
DHCP lease, AT never answered, `oob-tailscale` crash-looped 42× (no route
to control). The old watchdog heal — an `authorized` 0→1 toggle — made it
worse at t=622 s: SET_CONFIGURATION(0) succeeded, SET_CONFIGURATION(1) got
EPROTO (-71), and the device sat UNCONFIGURED (`bConfigurationValue`
empty, no ttys, no wwan0) — OOB dark until a manual USBDEVFS_RESET + driver
rebind at t=888 s (ports back, registered, `-oob` online). Root cause is
inside the modem (firmware boot state — reproduced in miniature: after
`AT+CFUN=1,1` the SIM7600 re-enumerates at ~20 s and answers AT only at
~41 s; at cold boot the same state persisted indefinitely). Not a udev /
probe-port problem: interface 04 is the AT port in RNDIS mode (05 also
answers; 02/03/06 do not).

Findings, all pilot-verified on hardware:

1. The `authorized` toggle recovers nothing it is meant for: EPROTO on a
   modem whose function side is down (strands it unconfigured), no-op on
   an unconfigured device, ~2 s success only on a healthy modem. Dropped.
2. USBDEVFS_RESET (port reset) un-wedges the control pipe; the kernel
   re-applies the config and rebinds drivers itself if the device was
   still configured (~2 s). On an unconfigured device a reset rebinds
   nothing — hence "usbreset didn't help" in the incident.
3. `echo 3-2 > /sys/bus/usb/drivers/usb/unbind` / `bind` re-issues
   SET_CONFIGURATION(1): ports back in ~2 s on a healthy modem; on the hung
   modem it worked only after the port reset. Ladder = reset → rebind.
4. After any modem bounce, tailscaled in `oob-tailscale` sits on a dead
   control connection indefinitely (new flows from the netns work; node
   Offline 15+ min; `docker restart` → Online in 5 s). The watchdog now
   restarts the pair after a recovery and on "data OK, node offline ×2".
5. A `sudo reboot` does NOT power-cycle the HAT (Pi 5 keeps the header 5 V
   up); only pulling the Pi's power does.
6. vnstatd never auto-added wwan0 on the pilot — the data-budget item read
   0 MB since install. setup-oob now registers it (`vnstat --add`).
7. setup-oob's APN check treated an unanswered `AT+CGDCONT?` (AT port busy
   with the watchdog probe) as "APN wrong" and rebooted the modem with
   `AT+CFUN=1,1` on the deploy. It now acts only on a query that answered.

8. **Reproduced the genuine dead state**: a port reset issued while the
   modem was still in its post-`AT+CFUN=1,1` boot window (t+36 s, ttys
   present, AT not yet answering) left it enumerated-but-dead — no AT, no
   DHCP, `oob-tailscale` restart-looping — i.e. the cold-boot phenotype.
   Best root-cause model for the incident: the Pi's USB bus reset at
   kernel boot (~5 s after kernel start, ~20 s after power) lands inside
   the SIM7600's firmware-boot window and can wedge its function side.
   The watchdog's 2×5-min gate means it never resets a modem inside that
   window itself; the ladder recovered the wedged modem 6 min later in
   6 s (port reset → AT OK at +8 s → registered → `-oob` Online).
9. AT also went dead twice more during the session minutes after a USB
   bounce + `oob-console` restart with no USB event in dmesg (once ~3–5
   min after a CFUN reboot). The ladder heals it within 10–15 min either
   way; the underlying modem-side flakiness is OPEN (firmware
   `SIM7600G_V2.0.2`; watch the Zabbix `oob.status[at_ok]` history for
   recurrence and correlate with `journalctl -t oob-hotplug`).

Timings with the final ladder: dead-state simulation recovered on the 2nd
probe in ~10 s (reset + rebind), `-oob` back online ~5–15 s later; manual
`--usb-recover` on a healthy modem ~15 s incl. pair restart; on the
genuinely wedged modem 6 s.
