# Disable IPv6 on the D2 Edge Appliance — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Disable IPv6 on the Raspberry Pi 5 edge appliances (system-wide via a sysctl drop-in) and turn off UFW's IPv6 ruleset, removing every "Anywhere (v6)" firewall twin, while keeping Tailscale and all IPv4 internal/platform endpoints reachable.

**Architecture:** Add one idempotent installer script (`scripts/disable-ipv6.sh`) plus one sysctl drop-in (`shared/files/99-disable-ipv6.conf`), wired into both `bootstrap.sh` (fresh provisioning, post-clone heal block) and `update.sh` (existing fleet, `[3/6]` heal block) exactly like the existing `52-d2-auto-reboot` drop-in and `heal-firewall.sh`. The installer applies the drop-in live (no reboot), confirms IPv6 is actually down on the LAN uplink, and only **then** flips `IPV6=no` in `/etc/default/ufw` + `ufw reload` so no unfiltered v6 listener is ever left behind.

**Tech Stack:** Bash, sysctl / `/etc/sysctl.d`, UFW, systemd, Docker Compose (all services `network_mode: host`), Tailscale.

---

## Critical Architecture Note (read before implementing)

Every service in `docker-compose.yml` runs `network_mode: host` — including `tailscale` (line 9) and `d2-agent` (line 161). Consequences:

1. **`tailscale0` lives in the host netns.** A global `net.ipv6.conf.all.disable_ipv6=1` flushes IPv6 from **all** existing interfaces, and `net.ipv6.conf.default.disable_ipv6=1` disables it on interfaces created later — so `tailscale0` loses its `fd7a:115c:a1e0::/48` ULA. Tailscale itself runs fine over IPv4 (CGNAT 100.64/10, DERP/direct over IPv4), so connectivity is *expected* to survive. **This is the exact risk we must validate.**
2. **`d2-agent`'s active probes share the host netns.** `d2-agent/app.py` opens `socket.AF_INET6` sockets for AAAA-resolved targets (app.py:1871, 1941, 2289). Disabling host IPv6 means any IPv6-only probe target becomes unreachable. Per the task scope the monitored estate is IPv4-only, so this is accepted — but the validation includes a d2-agent health check to confirm no regression.

**Two drop-in variants are fully specified below.** Ship the **global** variant (Task 2) per the task's stated primary approach. If validation (Task 6) shows Tailscale or any internal endpoint broke, swap to the **per-interface** variant (Task 7) — `tailscale0` keeps its ULA, only `eth0`/`wlan0` lose IPv6, and the LAN attack surface + UFW v6 twins are still gone. Given the host-mode Tailscale architecture, **be prepared for the fallback to be the shipped solution.**

---

## File Structure

- **Create** `shared/files/99-disable-ipv6.conf` — the sysctl drop-in (source of truth for the IPv6 kernel knobs). High number (`99`) so it wins over distro/RPi defaults. Mirrors `shared/files/52-d2-auto-reboot.conf`.
- **Create** `scripts/disable-ipv6.sh` — idempotent installer: copies the drop-in to `/etc/sysctl.d/`, applies it live, verifies IPv6 down on `eth0`, then (only if confirmed) sets `IPV6=no` in `/etc/default/ufw` + `ufw reload`. Mirrors `scripts/heal-firewall.sh` (additive UFW only, never `reset`).
- **Modify** `shared/scripts/bootstrap.sh` — call `disable-ipv6.sh` in the post-clone heal block (next to the `52-d2-auto-reboot` / lldpd / oxidized-proxy installs, ~line 197).
- **Modify** `shared/scripts/update.sh` — call `disable-ipv6.sh` in the `[3/6]` host-heals block, **after** `heal-firewall.sh` (~line 148) so it cleans up any v6 twin that `heal-firewall.sh` just created.

No other files change. `preflight.sh`, `render-configs.sh`, `docker-compose.yml`, and `.env` are untouched.

---

## Conventions this plan follows (from the existing repo)

- **Drop-in install:** `install -m 0644 -o root -g root "$SRC" "$DST"` guarded by `[[ ! -f "$DST" ]] || ! cmp -s "$SRC" "$DST"` (see `update.sh:99-104`).
- **UFW safety:** additive only — `ufw allow` / `ufw reload`, **never** `ufw reset` / `ufw disable` (SSH-lockout risk; see `heal-firewall.sh` header).
- **Heal-script invocation:** guard with `[[ -f ... ]]`, invoke via `bash "$EDGE_DIR/scripts/<name>.sh"` (avoids dependence on the git exec bit, which Windows-side edits may drop).
- **update.sh self-edit lag:** a new call added to `update.sh` takes effect on the **second** post-pull run on a given Pi (`feedback_update_sh_self_mod`). Validation runs `update.sh` twice on Pi #2.
- **Two-Pi workflow:** push from control Pi `192.168.166.34`, validate with `update.sh` on Pi #2 `192.168.21.16` each revision (`feedback_d2_edge_two_pi_validation`). **Only** SSH the D2-owned Pis `.34` and `192.168.21.16` — never a customer-tenant Pi (`feedback_pi_ssh_allowlist`).

---

## Task 1: Create the idempotent installer `scripts/disable-ipv6.sh`

**Files:**
- Create: `scripts/disable-ipv6.sh`

- [ ] **Step 1: Write the script**

Create `C:\Users\JaredCooper\Claude\d2-edge\scripts\disable-ipv6.sh` with exactly:

```bash
#!/usr/bin/env bash
# Idempotent IPv6 disable for the D2 edge appliance.
#
# Installs the sysctl drop-in, applies it live (no reboot), confirms IPv6 is
# actually down on the LAN uplink, and ONLY THEN sets IPV6=no in
# /etc/default/ufw + reloads UFW so it stops emitting "(v6)" rule twins.
#
# WHY: the stack is IPv4-only — every internal/platform endpoint is IPv4
# (10.255.255.x, 192.168.166.8) and the appliance is outbound-only. With IPv6
# up, UFW emits an "Anywhere (v6)" twin for every "Anywhere" allow rule (SSH
# 22, syslog 514, RADIUS 1812/1813, iperf3 5201, Auvik 10021, flow
# 2055/6343/4739/9995/9996), so those services also listen on / are reachable
# over IPv6. See shared/files/99-disable-ipv6.conf.
#
# SAFETY: additive + ordered. We NEVER `ufw reset`/`disable` (SSH-lockout
# risk — has locked us out of fleet Pis before). UFW's IPV6=no is flipped ONLY
# after the kernel confirms IPv6 is disabled on eth0, so we never leave an
# unfiltered v6 listener behind. Re-running on an already-disabled Pi is a
# no-op. Tolerates per-interface sysctl keys whose interface is absent.
set -euo pipefail

EDGE_DIR="${EDGE_DIR:-/opt/d2-edge}"
DROPIN_SRC="$EDGE_DIR/shared/files/99-disable-ipv6.conf"
DROPIN_DST=/etc/sysctl.d/99-disable-ipv6.conf
UFW_DEFAULTS=/etc/default/ufw

if [[ $EUID -ne 0 ]]; then echo "[disable-ipv6] must run as root" >&2; exit 1; fi
[[ -f "$DROPIN_SRC" ]] || { echo "[disable-ipv6] $DROPIN_SRC missing; skip"; exit 0; }

# 1. Install/refresh the persistent drop-in (survives reboot).
if [[ ! -f "$DROPIN_DST" ]] || ! cmp -s "$DROPIN_SRC" "$DROPIN_DST"; then
    install -m 0644 -o root -g root "$DROPIN_SRC" "$DROPIN_DST"
    echo "[disable-ipv6] installed/updated $DROPIN_DST"
fi

# 2. Apply live (no reboot). Writing disable_ipv6=1 flushes v6 addresses
#    immediately. Apply each key from the drop-in with `|| true` so a missing
#    interface (e.g. a Pi with no wlan0) can't abort under `set -e`.
grep -E '^[[:space:]]*net\.ipv6\.' "$DROPIN_DST" | sed -E 's/[[:space:]]+//g' \
  | while read -r kv; do
        [[ -n "$kv" ]] && sysctl -w "$kv" >/dev/null 2>&1 || true
    done || true
# Reload the full sysctl.d tree too so state is consistent; tolerate warnings.
sysctl --system >/dev/null 2>&1 || true

# 3. Confirm IPv6 is actually down on the primary LAN uplink BEFORE touching
#    UFW. eth0 is the Pi 5 built-in ethernet and is always present. Ground
#    truth = no inet6 address on eth0 (disable_ipv6=1 strips even link-local),
#    which holds for BOTH the global and per-interface drop-in variants.
ipv6_down_eth0() {
    [[ ! -e /sys/class/net/eth0 ]] && return 0   # no eth0 -> nothing to guard
    ! ip -6 addr show dev eth0 2>/dev/null | grep -q 'inet6'
}
if ! ipv6_down_eth0; then
    echo "[disable-ipv6] WARN: IPv6 still up on eth0 after apply — leaving UFW IPV6 setting untouched (no unfiltered v6 listener risk)" >&2
    exit 0
fi
echo "[disable-ipv6] IPv6 confirmed disabled on eth0"

# 4. Stop UFW emitting v6 rule twins. Idempotent sed + SAFE reload (not reset).
if grep -qE '^[[:space:]]*IPV6=yes' "$UFW_DEFAULTS"; then
    sed -i 's/^[[:space:]]*IPV6=yes/IPV6=no/' "$UFW_DEFAULTS"
    echo "[disable-ipv6] set IPV6=no in $UFW_DEFAULTS"
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw reload >/dev/null 2>&1 || true
        echo "[disable-ipv6] reloaded UFW (v6 twins removed)"
    fi
elif ! grep -qE '^[[:space:]]*IPV6=' "$UFW_DEFAULTS"; then
    echo "IPV6=no" >> "$UFW_DEFAULTS"
    echo "[disable-ipv6] appended IPV6=no to $UFW_DEFAULTS"
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw reload >/dev/null 2>&1 || true
        echo "[disable-ipv6] reloaded UFW (v6 twins removed)"
    fi
else
    echo "[disable-ipv6] $UFW_DEFAULTS already IPV6=no"
fi

echo "[disable-ipv6] OK"
```

- [ ] **Step 2: Syntax-check the script**

Run: `bash -n C:\Users\JaredCooper\Claude\d2-edge\scripts\disable-ipv6.sh`
Expected: no output, exit 0 (a syntax error prints `disable-ipv6.sh: line N: ...`).

- [ ] **Step 3: (optional) shellcheck if available**

Run: `shellcheck C:\Users\JaredCooper\Claude\d2-edge\scripts\disable-ipv6.sh`
Expected: clean, or only style-level (SC2086-class) notes. If `shellcheck` is not installed, skip — `bash -n` is sufficient.

---

## Task 2: Create the sysctl drop-in `shared/files/99-disable-ipv6.conf` (GLOBAL variant — ship first)

**Files:**
- Create: `shared/files/99-disable-ipv6.conf`

- [ ] **Step 1: Write the drop-in**

Create `C:\Users\JaredCooper\Claude\d2-edge\shared\files\99-disable-ipv6.conf` with exactly:

```
# D2 Edge fleet — disable IPv6 to reduce attack surface.
#
# Installed by scripts/disable-ipv6.sh (invoked from shared/scripts/
# {bootstrap,update}.sh) into /etc/sysctl.d/99-disable-ipv6.conf and applied
# live with `sysctl --system`. High number (99) so it wins over distro/RPi
# defaults in /usr/lib/sysctl.d and /etc/sysctl.d.
#
# WHY: the stack is IPv4-only. Every internal/platform endpoint is IPv4
# (10.255.255.x, 192.168.166.8) and the appliance is outbound-only. With IPv6
# up, UFW emits an "Anywhere (v6)" twin for every "Anywhere" allow rule (SSH
# 22, syslog 514, RADIUS 1812/1813, iperf3 5201, Auvik 10021, flow
# 2055/6343/4739/9995/9996), so those services also listen on / are reachable
# over IPv6. Disabling IPv6 removes that twin attack surface. Tailscale runs
# fine over IPv4 (CGNAT 100.64/10, DERP/direct over IPv4).
#
# NOTE: all containers run network_mode: host, so tailscale0 is in the host
# netns. This GLOBAL disable strips tailscale0's fd7a:115c:a1e0::/48 ULA. If
# validation shows that breaks the overlay, switch to the per-interface
# variant (eth0/wlan0 only) — see docs/superpowers/plans/2026-06-17-disable-ipv6.md.
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
```

- [ ] **Step 2: Verify the keys parse for `sysctl -w`**

Run (on any Linux box or Pi, dry parse): `grep -E '^[[:space:]]*net\.ipv6\.' C:\Users\JaredCooper\Claude\d2-edge\shared\files\99-disable-ipv6.conf | sed -E 's/[[:space:]]+//g'`
Expected output:
```
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
```
(Confirms the installer's parse pipeline produces valid `sysctl -w` arguments.)

---

## Task 3: Wire the installer into `bootstrap.sh` (fresh provisioning)

**Files:**
- Modify: `shared/scripts/bootstrap.sh:194-197` (insert a new heal call after the oxidized-proxy block, before the Log-rotation section)

**Why here, not in the `[6/8]` firewall block:** the drop-in is a repo file, only available after the clone in `[7/8]`. This mirrors how `52-d2-auto-reboot.conf`, lldpd, and the oxidized-proxy user are all installed post-clone. On a fresh Pi the `[6/8]` UFW enable briefly creates v6 twins; `disable-ipv6.sh` (post-clone, seconds later, on a Pi with no production traffic) disables the stack first and **then** flips `IPV6=no` + reload, leaving a clean v4-only ruleset. We deliberately do **not** reorder the working `[6/8]` block (lower risk).

- [ ] **Step 1: Add the call after the oxidized-proxy provisioning block**

In `shared/scripts/bootstrap.sh`, find (lines 194-197):

```bash
# Provision the Oxidized bastion user (svc_oxidized_proxy, nologin shell,
# locked authorized_keys). Idempotent — safe to run on every bootstrap.
if [[ -x "${EDGE_DIR}/scripts/setup-oxidized-proxy-user.sh" ]]; then
    bash "${EDGE_DIR}/scripts/setup-oxidized-proxy-user.sh"
fi
```

Insert immediately **after** that `fi` (before the blank lines and `# ─── Log rotation ───`):

```bash

# Disable IPv6 (attack-surface reduction). Installs the sysctl drop-in,
# applies it live, and — only once IPv6 is confirmed down on eth0 — sets
# IPV6=no in /etc/default/ufw + reloads UFW so no "(v6)" rule twins remain.
# Idempotent + additive (never `ufw reset`). See scripts/disable-ipv6.sh.
if [[ -f "${EDGE_DIR}/scripts/disable-ipv6.sh" ]]; then
    bash "${EDGE_DIR}/scripts/disable-ipv6.sh"
fi
```

- [ ] **Step 2: Syntax-check bootstrap.sh**

Run: `bash -n C:\Users\JaredCooper\Claude\d2-edge\shared\scripts\bootstrap.sh`
Expected: no output, exit 0.

---

## Task 4: Wire the installer into `update.sh` (existing fleet)

**Files:**
- Modify: `shared/scripts/update.sh:146-148` (insert a new heal call after the `heal-firewall.sh` call, inside the `[3/6]` block)

**Why after `heal-firewall.sh`:** `heal-firewall.sh` runs `ufw allow` for the flow ports; while `IPV6` is still `yes` (before our flip lands), that creates v6 twins. Running `disable-ipv6.sh` immediately after disables the stack and reloads UFW with `IPV6=no`, cleaning up those twins in the same pass.

- [ ] **Step 1: Add the call after the firewall heal**

In `shared/scripts/update.sh`, find (lines 146-148):

```bash
if [[ -x "$EDGE_DIR/scripts/heal-firewall.sh" ]]; then
    bash "$EDGE_DIR/scripts/heal-firewall.sh"
fi
```

Insert immediately **after** that `fi` (before `echo "  OK"` on line 149):

```bash
# IPv6 disable heal: install the sysctl drop-in, apply it live, and — only
# once IPv6 is confirmed down on eth0 — set IPV6=no in /etc/default/ufw +
# reload UFW so it stops emitting "(v6)" rule twins. Runs AFTER heal-firewall
# so it also cleans up any v6 twin that the flow-port heal just created.
# Idempotent + additive (never `ufw reset` — no SSH-lockout risk). The stack
# is IPv4-only; see scripts/disable-ipv6.sh + shared/files/99-disable-ipv6.conf.
if [[ -f "$EDGE_DIR/scripts/disable-ipv6.sh" ]]; then
    bash "$EDGE_DIR/scripts/disable-ipv6.sh"
fi
```

- [ ] **Step 2: Syntax-check update.sh**

Run: `bash -n C:\Users\JaredCooper\Claude\d2-edge\shared\scripts\update.sh`
Expected: no output, exit 0.

---

## Task 5: Commit and push from the control Pi (192.168.166.34)

> **Outward-facing / live-infra gate.** Pushing to the fleet repo and running `update.sh` on a Pi are outward-facing actions. Get the user's go-ahead before this task. Follow the established two-Pi workflow exactly — do not improvise remotes, branches, or force operations (`followup_deferred_backup_git_remediation`).

**Files:** none (git + deploy only)

- [ ] **Step 1: Stage and review the diff on the control Pi**

From the control Pi `192.168.166.34` repo checkout:
```bash
git -C /opt/d2-edge add scripts/disable-ipv6.sh shared/files/99-disable-ipv6.conf \
    shared/scripts/bootstrap.sh shared/scripts/update.sh
git -C /opt/d2-edge status
git -C /opt/d2-edge diff --cached
```
Expected: 2 new files (`scripts/disable-ipv6.sh`, `shared/files/99-disable-ipv6.conf`) + 2 modified (`bootstrap.sh`, `update.sh`); no unrelated changes.

- [ ] **Step 2: Commit**

```bash
git -C /opt/d2-edge commit -m "edge: disable IPv6 fleet-wide (sysctl drop-in + UFW IPV6=no)

Stack is IPv4-only; IPv6 only widened the UFW attack surface (a (v6) twin
per Anywhere allow rule). Adds scripts/disable-ipv6.sh + shared/files/
99-disable-ipv6.conf, wired into bootstrap.sh (post-clone) and update.sh
([3/6] heal). Idempotent, additive UFW only (no reset). Verifies IPv6 down
on eth0 before flipping IPV6=no so no unfiltered v6 listener is left behind."
```
Expected: commit succeeds.

- [ ] **Step 3: Push to the fleet branch the appliances track (main)**

```bash
git -C /opt/d2-edge push origin HEAD
```
Expected: push succeeds. (Customer-Pi rollout stays manual/Ansible-gated on Jared — `project_fleet_rollout_ansible`. This push only enables validation on Pi #2.)

---

## Task 6: Validate on Pi #2 (192.168.21.16) — GLOBAL variant

> SSH only `192.168.21.16` here (D2-owned). Run `update.sh` **twice** — the new call in `update.sh` only takes effect on the second post-pull run (`feedback_update_sh_self_mod`).

**Files:** none (validation only)

- [ ] **Step 1: First update run (loads the new update.sh + scripts)**

```bash
sudo bash /opt/d2-edge/shared/scripts/update.sh
```
Expected: completes through `[6/6] ... Update complete`. The IPv6 heal likely does **not** run yet (old `update.sh` still in effect).

- [ ] **Step 2: Second update run (executes the new IPv6 heal)**

```bash
sudo bash /opt/d2-edge/shared/scripts/update.sh
```
Expected: among the `[3/6]` heal output you now see lines like:
```
[disable-ipv6] installed/updated /etc/sysctl.d/99-disable-ipv6.conf
[disable-ipv6] IPv6 confirmed disabled on eth0
[disable-ipv6] set IPV6=no in /etc/default/ufw
[disable-ipv6] reloaded UFW (v6 twins removed)
[disable-ipv6] OK
```

- [ ] **Step 3: Confirm IPv6 is down on the LAN interfaces**

```bash
ip -6 addr show dev eth0; echo "---"; ip -6 addr show dev wlan0 2>/dev/null
cat /proc/sys/net/ipv6/conf/all/disable_ipv6
```
Expected: **no `inet6` lines** on `eth0` (and `wlan0` if present); `all/disable_ipv6` prints `1`.

- [ ] **Step 4: Confirm UFW has no v6 twins**

```bash
sudo ufw status verbose | grep -i v6 || echo "NO V6 RULES"
grep '^IPV6' /etc/default/ufw
```
Expected: `NO V6 RULES`; `/etc/default/ufw` shows `IPV6=no`. (Also eyeball `sudo ufw status` — every rule should be IPv4-only, SSH 22 still `ALLOW`.)

- [ ] **Step 5: CRITICAL — confirm Tailscale still works**

```bash
docker exec tailscale tailscale status
ip -6 addr show dev tailscale0 2>/dev/null | grep inet6 || echo "tailscale0 has no v6 (expected for global disable)"
docker exec tailscale tailscale ping --until-direct=false --c 3 <a-known-tailnet-peer>
```
Expected: `tailscale status` shows this node + peers (no `Logged out`); a `tailscale ping` to a known peer succeeds over IPv4. `tailscale0` losing its v6 ULA is acceptable **iff** status/ping are healthy. **If `tailscale status` shows logged-out / no peers, or ping fails → STOP and go to Task 7 (fallback).**

- [ ] **Step 6: Confirm every internal endpoint is still reachable (over IPv4 via Tailscale)**

TCP-reachable endpoints (ICMP is NSG-blocked on 10.255.255.0/24 — `reference_azure_nsg_constraints` — so use TCP):
```bash
for hp in 10.255.255.4:10051 10.255.255.20:12203 10.255.255.36:9000; do
  timeout 4 bash -c "echo > /dev/tcp/${hp/:/\/}" && echo "OK  $hp" || echo "FAIL $hp"
done
ip route get 10.255.255.4 | head -1      # should route via tailscale0
ip route get 192.168.166.8 | head -1     # goflow2 host — should have a route
```
Expected: `OK 10.255.255.4:10051` (Zabbix), `OK 10.255.255.20:12203` (Graylog), `OK 10.255.255.36:9000` (UXI controller); both `ip route get` lines resolve a route (via `tailscale0` or the subnet router). **If any `FAIL` → STOP and go to Task 7.**

- [ ] **Step 7: Confirm UDP-only endpoints indirectly (container health + agent connection)**

```bash
docker ps --format '{{.Names}}\t{{.Status}}'
docker logs --since 3m d2-agent 2>&1 | grep -iE 'connect|websocket|controller|error' | tail -20
docker logs --since 3m freeradius-proxy 2>&1 | tail -10
docker logs --since 3m netflow-proxy 2>&1 | tail -10
```
Expected: all containers `Up`/healthy; `d2-agent` shows an established controller WebSocket (UXI `10.255.255.36:9000`, WSS) and no new connection errors; `freeradius-proxy` (central FreeRADIUS `10.255.255.13`) and `netflow-proxy` (goflow2 `192.168.166.8`) show no new failures. **If d2-agent lost its controller link or RADIUS/flow proxies error → STOP and go to Task 7.**

- [ ] **Step 8: Re-check outbound IPv4 services (DNS, NTP, apt, registry, GitHub, Tailscale)**

```bash
getent hosts github.com download.docker.com pkgs.tailscale.com
chronyc tracking | grep -E 'Reference ID|Leap status'
sudo apt-get update -qq && echo "APT OK"
docker pull hello-world:latest >/dev/null && echo "REGISTRY OK"
docker exec tailscale tailscale netcheck 2>/dev/null | grep -iE 'UDP|IPv4|DERP' | head
```
Expected: DNS resolves (IPv4 A records); chrony has a reference + `Leap status: Normal`; `APT OK`; `REGISTRY OK`; Tailscale netcheck reports IPv4/DERP connectivity. (The `git pull` + `docker compose build --pull` already inside Step 2 also prove GitHub + registry egress.)

- [ ] **Step 9: Decision gate**

- **All of Steps 3-8 pass →** GLOBAL variant is good. Skip Task 7. Proceed to Task 8.
- **Any Tailscale/endpoint/agent check failed →** proceed to **Task 7** (per-interface fallback), then re-run Task 6 Steps 3-8.

---

## Task 7: FALLBACK — per-interface drop-in (only if Task 6 failed)

Use this **only if** the global disable broke Tailscale or an internal endpoint. It disables IPv6 on the physical LAN interfaces (`eth0`, `wlan0`) only, leaving `lo` and `tailscale0` (and its v6 ULA) intact — while still removing the LAN v6 attack surface and the UFW v6 twins. `scripts/disable-ipv6.sh` is **unchanged**; only the drop-in body differs (and its on-Pi verification is identical: `eth0` ends with no `inet6`).

**Files:**
- Modify: `shared/files/99-disable-ipv6.conf` (swap the two `net.ipv6.conf.*` lines)

- [ ] **Step 1: Replace the drop-in body with the per-interface variant**

Overwrite `C:\Users\JaredCooper\Claude\d2-edge\shared\files\99-disable-ipv6.conf` with exactly:

```
# D2 Edge fleet — disable IPv6 to reduce attack surface (per-interface variant).
#
# Installed by scripts/disable-ipv6.sh (invoked from shared/scripts/
# {bootstrap,update}.sh) into /etc/sysctl.d/99-disable-ipv6.conf and applied
# live with `sysctl --system`. High number (99) so it wins over distro/RPi
# defaults in /usr/lib/sysctl.d and /etc/sysctl.d.
#
# WHY: the stack is IPv4-only. Every internal/platform endpoint is IPv4
# (10.255.255.x, 192.168.166.8) and the appliance is outbound-only. With IPv6
# up, UFW emits an "Anywhere (v6)" twin for every "Anywhere" allow rule (SSH
# 22, syslog 514, RADIUS 1812/1813, iperf3 5201, Auvik 10021, flow
# 2055/6343/4739/9995/9996), so those services also listen on / are reachable
# over IPv6. Disabling IPv6 on the physical LAN interfaces removes that twin
# attack surface.
#
# WHY PER-INTERFACE (not the global all/default knobs): all containers run
# network_mode: host, so tailscale0 lives in the host netns. A global disable
# strips tailscale0's fd7a:115c:a1e0::/48 ULA and broke the overlay/endpoints
# in validation (see docs/superpowers/plans/2026-06-17-disable-ipv6.md). This
# variant disables IPv6 only on eth0/wlan0 — the customer LAN-facing
# interfaces — so tailscale0 keeps its v6 ULA while the LAN v6 listeners and
# the UFW (v6) twins are still gone.
net.ipv6.conf.eth0.disable_ipv6 = 1
net.ipv6.conf.wlan0.disable_ipv6 = 1
```

- [ ] **Step 2: Re-validate the parse**

Run: `grep -E '^[[:space:]]*net\.ipv6\.' C:\Users\JaredCooper\Claude\d2-edge\shared\files\99-disable-ipv6.conf | sed -E 's/[[:space:]]+//g'`
Expected:
```
net.ipv6.conf.eth0.disable_ipv6=1
net.ipv6.conf.wlan0.disable_ipv6=1
```

- [ ] **Step 3: Commit + push the variant swap (control Pi)**

```bash
git -C /opt/d2-edge add shared/files/99-disable-ipv6.conf
git -C /opt/d2-edge commit -m "edge: IPv6 disable — use per-interface variant (preserve tailscale0 ULA)

Global all/default disable stripped tailscale0's v6 ULA (host-net tailscale)
and broke overlay/endpoints in validation. Disable IPv6 only on eth0/wlan0;
tailscale0 keeps its ULA, LAN v6 attack surface + UFW (v6) twins still gone."
git -C /opt/d2-edge push origin HEAD
```

- [ ] **Step 4: Re-run validation on Pi #2**

Re-run **Task 6 Steps 1-8** on `192.168.21.16` (two `update.sh` runs again — the changed file is a heal input, but re-run twice to be safe). Additional expectation this time:
```bash
ip -6 addr show dev tailscale0 | grep inet6
```
Expected: `tailscale0` **retains** an `inet6 fd7a:115c:a1e0:...` ULA, while `eth0`/`wlan0` have **no** `inet6`. All Tailscale/endpoint/agent checks now pass.

---

## Task 8: Idempotency + persistence re-check, then mark complete

**Files:** none

- [ ] **Step 1: Re-run update.sh once more — confirm no-op**

On `192.168.21.16`:
```bash
sudo bash /opt/d2-edge/shared/scripts/update.sh 2>&1 | grep -i disable-ipv6
```
Expected: `[disable-ipv6] $UFW_DEFAULTS already IPV6=no` (or just `[disable-ipv6] OK`) and **no** "installed/updated" line — proving the heal is idempotent (drop-in already in place, UFW already `IPV6=no`).

- [ ] **Step 2: Confirm persistence across reboot (optional but recommended)**

If a maintenance window allows, reboot `192.168.21.16` and after it returns:
```bash
cat /proc/sys/net/ipv6/conf/eth0/disable_ipv6   # -> 1
sudo ufw status | grep -i v6 || echo "NO V6 RULES"
docker exec tailscale tailscale status | head -3
```
Expected: IPv6 still disabled on `eth0` (drop-in re-applied by `systemd-sysctl` at boot); no UFW v6 rules; Tailscale up. If no window is available, note that `systemd-sysctl` applies `/etc/sysctl.d/99-disable-ipv6.conf` at every boot, so persistence is structural.

- [ ] **Step 3: Final summary to the user**

Report: which variant shipped (global vs per-interface), the validation evidence (no `inet6` on eth0, `NO V6 RULES`, Tailscale + all endpoints OK), and that customer-fleet rollout remains gated on Jared (Ansible / manual `update.sh`), since this change only landed on the D2-owned validation Pi.

---

## Self-Review

**1. Spec coverage (task → task):**
- *Sysctl drop-in under `shared/files/`, installed idempotently by bootstrap.sh, applied to existing Pis by update.sh, same pattern as 52-d2-auto-reboot / heal-firewall* → Tasks 1-4. ✅
- *Verify Tailscale still works after disabling; check control plane + Zabbix/Graylog/FreeRADIUS/UXI/goflow2/Oxidized reachability* → Task 6 Steps 5-7. ✅
- *Fallback to per-interface (eth0, wlan0) if global breaks tailscale0* → Task 7 (full file content, not a placeholder). ✅
- *Set `IPV6=no` in `/etc/default/ufw` only after IPv6 is actually disabled; confirm `ufw status` shows no (v6) rules* → installer Step "confirm IPv6 down before touching UFW" (Task 1) + Task 6 Step 4. ✅
- *Re-check DNS, NTP, apt, Docker registry, GitHub, Tailscale outbound over IPv4* → Task 6 Step 8. ✅
- *Two-Pi workflow: push from .34, validate via update.sh on .16; never customer Pis; never `ufw reset`; update.sh self-edits apply on 2nd run* → Tasks 5-6 (explicit double-run), safety conventions section. ✅

**2. Placeholder scan:** Both drop-in variants and the installer are written in full. The only intentional `<...>` placeholders are operator-supplied runtime values in validation commands (`<a-known-tailnet-peer>`) — these are inputs to a live check, not unwritten code. No "TBD"/"add error handling"/"similar to Task N". ✅

**3. Type/name consistency:** File paths are consistent everywhere — drop-in source `shared/files/99-disable-ipv6.conf`, dest `/etc/sysctl.d/99-disable-ipv6.conf`, installer `scripts/disable-ipv6.sh`, UFW defaults `/etc/default/ufw`. The installer guards on `[[ -f ... ]]` and both bootstrap.sh and update.sh invoke it via `bash "$EDGE_DIR/scripts/disable-ipv6.sh"` (matching guard style). The verification ground-truth (`no inet6 on eth0`) is identical across both variants, so `disable-ipv6.sh` needs no change when swapping to the fallback. ✅
