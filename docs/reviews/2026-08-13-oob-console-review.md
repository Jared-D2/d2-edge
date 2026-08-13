# OOB Console — Full Review (2026-08-13, pre-fleet-rollout gate)

**Scope:** everything merged in `1ddfc9c` (spec §1–14, host layer, containers,
renderer, fleet integration), reviewed by an 8-angle multi-agent pass over the
merge diff + live verification on d2-lab-pi01, plus UX and hardware assessment.

**Verdict: the architecture is sound and E2E-proven, but NOT fleet-ready yet.**
The isolation model, opt-in gating, and audit pipeline all held up under
review. However the review found 10 verified defects (4 of them serious), the
"plug in a console cable" workflow is not yet operator-proof, and two spec
promises (tc cap, Zabbix monitoring) were never implemented. Fix the P0 list
below before enabling OOB on any customer-site Pi.

## 1. Verified defects (filed via review tooling, summarized)

**P0 — fix before any further rollout:**

1. **Watchdog can permanently power the modem off** (`oob-watchdog.sh`).
   The no-SIM gate tests "wwan0 has an IP", but RNDIS hands out 192.168.225.x
   with no SIM/registration. An unregistered modem (pre-SIM state, or any
   multi-hour carrier outage) walks the CFUN→CFUN→PWRKEY ladder; a 3 s PWRKEY
   hold on a running SIM7600 is power-OFF and nothing powers it back on.
   The pilot survived only because GPIO6 turned out not to be this HAT
   revision's PWRKEY — i.e. the last-resort recovery path is ALSO unproven.
   Fix: gate on cellular registration (AT+CEREG via oob-at.py), never
   PWRKEY-off a modem that is enumerated and responding to AT; verify the
   real PWRKEY GPIO on the bench before trusting the escalation at all.
2. **`deploy-all.sh` boots the OOB pair fail-OPEN** — it never runs
   setup-oob.sh, so no table-200 rule/blackhole exists and br-oob traffic
   MASQUERADEs out eth0; the tag:oob node joins the tailnet in-band over the
   customer LAN. Fix: deploy-all must run the same gated setup-oob heal, and
   oob-tailscale should refuse to start if the ip rule is absent (entrypoint
   check — cheap, closes every path).
3. **First-enable / every ports.yaml change takes TWO update.sh runs** —
   setup-oob.sh (step 3) installs `slots.rules` before render-configs.sh
   (step 4) produces it. First deploy ends green with every console dead.
   Fix: render ser2net.yaml + slots.rules inside setup-oob.sh (or a step
   before it), and add slot-symlink presence to the verify block.
4. **Preflight dies silently when OOB keys are absent** (not empty): bare
   `v=$(grep …)` under `set -euo pipefail`. Legacy Pi + `enabled` flag +
   missing `OOB_APN=` line = zero-diagnostic abort. Fix: use the already-
   sourced variables like every other preflight check.

**P1 — fix in the same hardening pass:**

5. **The toggle is parsed four different ways** (prefix-grep in update.sh,
   whitespace-stripped `deploy_flag`, sourced exact-match in render-configs,
   compose dotenv). `enabled # comment` or a trailing space half-deploys OOB
   (host layer live, containers removed, render skipped). Fix: one shared
   `env_get()` (exists in `install-wazuh-agent.sh`) + `deploy_flag KEY DEFAULT`,
   flag read once.
6. **`ser2net.yaml` single-file bind wedge**: a premature `docker compose up
   oob-console` makes docker create a root-owned *directory* at that path;
   every later render then fails (IsADirectoryError) until manual rmdir.
   Fix: mount the `oob-console/` config dir instead of the file, or pre-create
   the file and add a heal.
7. **Quoted `OOB_APN` = modem reset on every deploy**: the grep keeps quotes,
   the CGDCONT? match never succeeds, so each update re-issues a mangled
   CGDCONT + CFUN + 20 s sleep. Same env_get() fix as #5.
8. **Unconditional `apt-get install` inside the fail-loud setup-oob**: a dpkg
   lock held by unattended-upgrades aborts the whole deploy. Guard with
   `dpkg -s` (pattern already used for brltty three lines below).
9. **Raw `printf` AT writes** (mode pin, watchdog CFUN) configure no termios
   and read no reply — ERROR is indistinguishable from OK. oob-at.py exists;
   install it first and use it for all AT traffic.
10. **Renderer doesn't validate `device` names**: a quote breaks the entire
    ser2net config (all slots down); a `/` writes transcripts outside the
    audited directory. Enforce `^[A-Za-z0-9._-]+$`.

**Notable non-defect verifications:** the watchdog's `ping -I wwan0` works
correctly on a healthy link (empirically confirmed — a finder claim that it
could never route was refuted live); `stop/rm` of profile-disabled services
works on current compose (verified on the pilot); the syslog wildcard source
is a true no-op on non-OOB Pis.

## 2. Below-threshold items & themes (do opportunistically)

- **NM/networkd guards belong fleet-wide, not OOB-gated.** The
  `unmanaged-devices` drop-in protects docker0/veth on *every* Pi (the hazard
  class the pilot proved), and `ManageForeignRoutingPolicyRules=no` protects
  any future policy routing. Move both to `shared/files/` + an unconditional
  update.sh heal; keep only wwan0/br-oob specifics under the OOB flag.
- **On-Pi docker build over site WANs**: first enable per Pi pulls
  debian:trixie-slim + apt over the uplink mid-deploy. Publish a prebuilt
  multi-arch `d2-edge-oob-console` image pinned by digest (matching the
  repo's own pinning convention), or at minimum gate the build on a
  Dockerfile hash.
- The SIM7600 vendor-scan loop exists in 3 places, the PWRKEY pulse in 2,
  and `.env` parsing in 4 dialects — one `shared/scripts/lib.sh` ends the
  drift class.
- render-configs.sh's OOB block runs *after* the "All configs rendered and
  validated" success line and can still exit 1 — move it above the sentinel.
- `oob-console/logs` is created implicitly by docker as root; add it to the
  bootstrap/deploy-all mkdir lists.
- udev reload/trigger/settle + fixed 15–20 s modem sleeps run unconditionally
  every deploy — cmp-guard the rules and poll instead of sleeping.
- **Pre-existing (not from this merge, fleet-wide):** `deploy_flag`'s
  parse diverges from compose dotenv for the *original eight* services — a
  quoted toggle value would tear a production service down on the next
  update. Filed as a separate follow-up.

## 3. UX review — "will it work if I plug a serial cable into any USB port?"

**Today: no.** A slot is bound to a *physical port* (`ID_PATH`), because
CH340-class adapters have no serial numbers. Plugging into a different port =
no symlink = dead slot. Worse, the current workflow for any change is:
edit ports.yaml → update.sh → update.sh again (defect #3) → restart
oob-console (ser2net won't bind late-appearing devices). That is not
operator-proof.

**Target state (recommended, all cheap):**

- **Serial-number slot binding where possible.** FTDI FT232R adapters (like
  the one on the lab FortiGate) carry unique serials — udev can match
  `ID_SERIAL_SHORT` instead of port path, making the slot follow the adapter
  to ANY port, any hub position. Add optional `usb_serial:` to ports.yaml
  (renderer emits the matching rule; `usb_path:` stays as fallback).
  **Fleet standard: buy FTDI-based adapters only.** (CP2102s often share the
  non-unique serial "0001"; CH340s have none — those stay port-bound.)
- **Hotplug that actually works:** a systemd `.path` unit watching
  `/dev/d2-console/` that restarts oob-console when slots appear/change —
  removes the "restart the container after plugging" tribal knowledge.
- **`kickolduser: true` + idle timeout on every slot** — the pilot hit the
  stale-session lockout (max-connections 1 + a dead TCP session blocks the
  port until restart); kickolduser makes the newest connection win. Idle
  timeout also closes the abandoned-logged-in-console security hole.
- **Single-run enable** (defect #3 fix) so the runbook is truly:
  plug → ports.yaml → update.sh → connect.
- **A directory banner on :3000** listing the Pi's slots (device, port,
  baud) so an engineer who remembers only the hostname can discover the rest.
- **Monitoring the OOB path** (spec promised, never built): Zabbix items for
  wwan0 (net.if via existing LLD), vnstat monthly data vs cap, `-oob`-node
  liveness (UserParameter wrapping `tailscale status` in the container), and
  the never-implemented `tc` egress cap. A dark OOB link must page someone.
- Windows note for the team: `telnet` client isn't installed by default —
  document PuTTY profiles (telnet, port 300N) in the runbook.

## 4. Hardware — compact HAT→Pi connection options

Constraint: current classic SIM7600X HAT needs an external USB-A↔micro-B
cable from its `USB` socket to a Pi port; the loop doesn't fit the housing.
Pogo-pin option is Pi-4-only (pads moved on Pi 5). Options, best first:

1. **Switch fleet hardware to the Waveshare "PCIe TO 4G/5G M.2 USB3.2 HAT+"
   (Pi 5) + SIM7600G-H-M.2 module.** Connects via the Pi 5's internal
   PCIe FFC ribbon — **no external cable at all**, everything inside the
   HAT footprint — and adds **3× USB 3.2 ports** (more console-adapter
   capacity, hub often unnecessary). The modem is the same SIM7600G-H
   family behind a PCIe-USB bridge, so our whole software stack (vendor
   1e0e udev, RNDIS pin, wwan0) should carry over — validate on ONE unit
   before a fleet buy (enumeration path + ID_PATH shapes will differ).
   This is the correct fleet answer if the budget allows re-kitting.
2. **For the existing classic HAT: rigid U-shaped USB bridge** (often in the
   Waveshare box) or a **short right-angle/ribbon USB-A↔micro-B jumper** —
   a few dollars, hugs the board, fits most housings. Keeps current stack
   untouched. This is the pragmatic answer for the lab Pi and any HATs
   already purchased.
3. **UART/PPP fallback (zero cables)**: the HAT can run PPP over the 40-pin
   header alone. Viable for console-class traffic but slower, more fragile,
   and a contained rework of the modem layer — documented fallback only.
4. **Case selection**: whatever connection wins, the fleet case needs
   HAT-stack clearance + antenna pass-through; spec it in the kit BOM.

## 5. Recommended order of work

1. P0 defects (#1–4) + `kickolduser`/timeout — one hardening PR.
2. P1 defects (#5–10) + shared lib/env_get consolidation + NM guard
   promotion to fleet heal + prebuilt image.
3. UX: usb_serial slots, hotplug path unit, single-run enable verification,
   runbook page, :3000 directory banner.
4. Monitoring: Zabbix items + tc cap + data-budget alert (80% of plan).
5. Hardware: order one PCIe M.2 HAT+ + SIM7600G-H-M2 for validation; U-bridge
   for the lab Pi meanwhile.
6. Only then: first customer-site OOB Pi.
