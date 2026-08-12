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

`oob-watchdog.timer` (host): every 5 min, ping a known IP sourced from
`wwan0`. After 3 consecutive failures: `AT+CFUN=1,1` (modem soft reset);
if still dead after 2 cycles, GPIO PWRKEY power-cycle. LTE modules wedge
silently ("registered, passing nothing") — without local self-heal, the first
real outage likely finds the modem in a state a reboot would have fixed.

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
