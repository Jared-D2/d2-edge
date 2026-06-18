# Source-Scope the Edge Host Firewall — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the edge appliance host firewall so every UFW service rule is scoped to the Tailscale tailnet (`100.64.0.0/10`) **and** the customer LAN (RFC1918) instead of `Anywhere`, with iperf3 (5201) and Auvik FTP-backup (10021) carved out to RFC1918-only, applied to fresh Pis via `bootstrap.sh` and to the existing fleet via an **additive, lockout-safe** `heal-firewall.sh`.

**Architecture:** Three moving parts. (1) `bootstrap.sh` `[6/8]` UFW block is rewritten to emit per-source scoped `ufw allow` rules (fresh Pis are clean — no `Anywhere`). (2) `heal-firewall.sh` is extended to **add** the same scoped rules to already-bootstrapped Pis **alongside** their legacy broad rules (never removing anything — a `ufw reset`/`delete` on a Tailscale-only Pi is a lockout). (3) A new **manual, later-phase** `scripts/firewall-tighten.sh` removes the legacy broad `Anywhere` rules, but only after confirming a scoped SSH rule exists and the operator's own SSH session source is inside a scoped range, so it cannot drop the running session.

**Tech Stack:** Bash, UFW, Tailscale (CGNAT 100.64/10), Docker Compose (all services `network_mode: host`), the two-Pi validation workflow (control Pi `192.168.166.34` → validation Pi `192.168.21.16`).

---

## Coordination with the concurrent "disable IPv6" task (read first)

A **separate, already-running** task disables IPv6 (`docs/superpowers/plans/2026-06-17-disable-ipv6.md`). Its working-tree changes already exist on this branch:

- `scripts/disable-ipv6.sh` + `shared/files/99-disable-ipv6.conf` (new files).
- `bootstrap.sh` — a `disable-ipv6.sh` call inserted **after the oxidized-proxy block (~line 199)**, *not* in the `[6/8]` UFW block.
- `update.sh` — a `disable-ipv6.sh` call inserted **after the `heal-firewall.sh` call** (`[3/6]`).

**No textual overlap with this plan:** this plan rewrites the `[6/8]` UFW block (bootstrap lines 99-125) and the body of `heal-firewall.sh`, and only touches the *comment* above the existing `heal-firewall.sh` invocation in `update.sh`. The IPv6 edits are in different regions of the same files. Apply this plan's edits with `Edit` against the current (IPv6-modified) working tree; do **not** revert or restage the IPv6 changes.

**Behavioural interaction is benign and complementary:**
- IPv6 task sets `IPV6=no` in `/etc/default/ufw` → appliance is IPv4-only. Every source here (`100.64.0.0/10`, RFC1918) is IPv4, so the scoped rules are IPv4-only and **never emit a `(v6)` twin** — source-scoping inherently removes the v6 surface the IPv6 task is also removing.
- Order in `update.sh` is `heal-firewall.sh` (this task) → `disable-ipv6.sh` (IPv6 task). The IPv6 heal's `ufw reload` after `IPV6=no` cleans up any transient v6 twin; our scoped rules produce none anyway.
- Both scripts are **additive-only, never `ufw reset`** — same lockout-safety contract.

---

## Decisions locked for this plan

- **Keep LAN + overlay** (Jared): scope to tailnet **AND** RFC1918, not overlay-only.
- **Tailnet source = the CIDR `100.64.0.0/10`** (not `ufw allow in on tailscale0`). Rationale: the task allows implementer's choice; the CIDR gives per-port source visibility in `ufw status verbose` (the verification expects each port scoped), is uniform with the RFC1918 CIDRs (one loop), and keeps per-port control (so the iperf/Auvik LAN-only carve-outs are expressible). Tailscale's CGNAT range is fixed at `100.64.0.0/10`, so the CIDR is stable.
- **RFC1918 = `10.0.0.0/8 172.16.0.0/12 192.168.0.0/16`** (full set — supersedes the hardcoded `192.168.0.0/16` on 80/2083, closing REVIEW.md **C6**; we do **not** derive from `LOCAL_CLIENT_SUBNET`).
- **5201/tcp (iperf3): RFC1918 ONLY** — Pi-to-Pi LAN throughput tests only, never over the overlay.
- **10021/tcp (Auvik FTP-backup ingress): RFC1918 ONLY** — Jared confirmed it IS in use; device-facing, not tailnet.
- **Broad-rule removal is a SEPARATE, LATER, MANUAL phase** — `heal-firewall.sh` only ADDS scoped rules; `firewall-tighten.sh` removes the broad rules later, guarded.

### Per-port source matrix

| Port(s) | Proto | Source scope | Comment |
|---|---|---|---|
| 22 | tcp | tailnet + RFC1918 | SSH |
| 514 | tcp+udp | tailnet + RFC1918 | Syslog |
| 1812, 1813 | udp | tailnet + RFC1918 | RADIUS auth/acct |
| 80 | tcp | tailnet + RFC1918 | cert-server (was 192.168.0.0/16-only) |
| 2083 | tcp | tailnet + RFC1918 | RadSec (was 192.168.0.0/16-only) |
| 2055, 6343, 4739 | udp | tailnet + RFC1918 | netflow-proxy relay (gated on `DEPLOY_NETFLOW_PROXY` in heal) |
| 9995, 9996 | udp | tailnet + RFC1918 | Auvik TrafficInsights flow |
| 5201 | tcp | **RFC1918 only** | iperf3 P2P (LAN only) |
| 10021 | tcp | **RFC1918 only** | Auvik FTP-backup ingress (LAN only) |

---

## File Structure

- **Modify** `shared/scripts/bootstrap.sh` — rewrite the `[6/8]` UFW block (lines 99-125): define `TAILNET`/`RFC1918`/`LAN_TS`/`LAN_ONLY` + a `ufw_scoped` helper, emit per-source rules, drop all `Anywhere` rules. Fresh Pis only — `ufw --force reset` here is fine (fresh box, no SSH session at risk).
- **Rewrite** `scripts/heal-firewall.sh` — additive scoped-rule migration for the existing fleet (every Pi) + the existing flow-relay-port heal (gated). Never deletes.
- **Create** `scripts/firewall-tighten.sh` — manual, later-phase removal of the legacy broad `Anywhere` rules, with two guards so it cannot self-lock. NOT wired into bootstrap/update.
- **Modify** `shared/scripts/update.sh` — update only the comment above the existing `heal-firewall.sh` call to describe the new scoping behaviour (the functional change rides in `heal-firewall.sh`, which runs on the *first* post-pull cycle; the comment is cosmetic and may lag one cycle per `feedback_update_sh_self_mod` — irrelevant for a comment).

---

## Conventions this plan follows (from the existing repo)

- **UFW safety:** additive only — `ufw allow` / `ufw reload`; **never** `ufw reset` / `ufw disable` / `ufw delete` in any auto-run path (SSH-lockout risk; `heal-firewall.sh` header, `feedback_pi_ssh_allowlist`).
- **Heal idempotency:** `ufw allow <identical rule>` is a no-op, so re-running never duplicates.
- **Heal-script invocation:** guard with `[[ -x ... ]]` / `[[ -f ... ]]`, invoke via `bash "$EDGE_DIR/scripts/<name>.sh"` (no dependence on the git exec bit, which Windows-side edits may drop).
- **update.sh self-edit lag:** a change to `update.sh` itself takes effect on the **second** post-pull run; a change to a script it *calls* (`heal-firewall.sh`) takes effect on the **first** run (`feedback_update_sh_self_mod`). The behaviour here lives in `heal-firewall.sh` → first-run effective.
- **Two-Pi workflow:** push from control Pi `192.168.166.34`, validate with `update.sh` on Pi #2 `192.168.21.16` (`feedback_d2_edge_two_pi_validation`). **Only** SSH the D2-owned Pis `.34` and `192.168.21.16` — never a customer-tenant Pi (`feedback_pi_ssh_allowlist`).
- **Outward-facing gate:** committing/pushing to the fleet repo and running `update.sh` on a live Pi require Jared's explicit go-ahead; do not improvise remotes/branches/force ops (`followup_deferred_backup_git_remediation`).

---

## Task 1: Rewrite the `bootstrap.sh` UFW block (fresh provisioning)

**Files:**
- Modify: `shared/scripts/bootstrap.sh:99-125` (the `# Firewall` block, ending at the `echo "  UFW: enabled with service rules"` line)

- [ ] **Step 1: Replace the firewall block**

Find the current block (starts at `# Firewall`, ends at the `echo "  UFW: enabled with service rules"` line) and replace it **exactly** with:

```bash
# Firewall — source-scoped, no service is exposed to "Anywhere".
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null

# The appliance is dual-homed: the customer LAN (RFC1918) and the Tailscale
# overlay (CGNAT 100.64.0.0/10). Every service rule is scoped to those two —
# nothing listens to the whole internet. (REVIEW.md C6: this retires the old
# hardcoded 192.168.0.0/16 on 80/2083 in favour of the full RFC1918 set.)
# Keep these source ranges in lockstep with scripts/heal-firewall.sh.
TAILNET="100.64.0.0/10"
RFC1918=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)
LAN_TS=("$TAILNET" "${RFC1918[@]}")   # tailnet + customer LAN
LAN_ONLY=("${RFC1918[@]}")            # customer LAN only (never the overlay)

# ufw_scoped <port[/proto]> <comment> <src>...
# Emits one source-scoped `ufw allow` per src. Omitting the proto (e.g. 514)
# opens both tcp+udp, matching the legacy bare-port rule. Idempotent.
ufw_scoped() {
    local spec="$1" comment="$2"; shift 2
    local port="${spec%%/*}" proto="" src
    [[ "$spec" == */* ]] && proto="${spec#*/}"
    for src in "$@"; do
        if [[ -n "$proto" ]]; then
            ufw allow from "$src" to any port "$port" proto "$proto" comment "$comment" >/dev/null
        else
            ufw allow from "$src" to any port "$port" comment "$comment" >/dev/null
        fi
    done
}

# Device + management ports — reachable from the customer LAN AND the overlay.
ufw_scoped 22/tcp   'SSH'                                "${LAN_TS[@]}"
ufw_scoped 514      'Syslog'                             "${LAN_TS[@]}"
ufw_scoped 1812/udp 'RADIUS auth'                        "${LAN_TS[@]}"
ufw_scoped 1813/udp 'RADIUS acct'                        "${LAN_TS[@]}"
ufw_scoped 80/tcp   'cert-server (LAN onboarding)'       "${LAN_TS[@]}"
ufw_scoped 2083/tcp 'RadSec from customer devices'       "${LAN_TS[@]}"
# Flow telemetry ingress (UDP). netflow-proxy (nginx stream, host network) binds
# 2055/NetFlow, 6343/sFlow, 4739/IPFIX and relays each datagram to the central
# goflow2 collector (NETFLOW_COLLECTOR_HOST); all three MUST be open or non-
# NetFlow exporters are silently dropped before reaching the relay. 9995/9996
# are Auvik TrafficInsights' own flow ports (the relay does not listen on them).
# NOTE: .env isn't populated yet here, so these open unconditionally; the
# netflow profile gate is (re)applied by update.sh -> heal-firewall.sh.
ufw_scoped 2055/udp 'Flow: NetFlow -> netflow-proxy relay' "${LAN_TS[@]}"
ufw_scoped 6343/udp 'Flow: sFlow -> netflow-proxy relay'   "${LAN_TS[@]}"
ufw_scoped 4739/udp 'Flow: IPFIX -> netflow-proxy relay'   "${LAN_TS[@]}"
ufw_scoped 9995/udp 'Flow: Auvik TrafficInsights (NetFlow)' "${LAN_TS[@]}"
ufw_scoped 9996/udp 'Flow: Auvik TrafficInsights (sFlow)'   "${LAN_TS[@]}"

# Customer-LAN-only ports — never reachable over the Tailscale overlay.
# iperf3 is only ever used for Pi-to-Pi throughput tests across the customer
# LAN. Auvik's 10021 is its FTP-backup ingress (FTP/21 -> 10021), device-facing.
ufw_scoped 5201/tcp  'iperf3 P2P (LAN only)'               "${LAN_ONLY[@]}"
ufw_scoped 10021/tcp 'Auvik FTP-backup ingress (LAN only)' "${LAN_ONLY[@]}"

echo "y" | ufw enable >/dev/null
echo "  UFW: enabled — services scoped to tailnet (100.64/10) + RFC1918; iperf3/Auvik LAN-only"
```

- [ ] **Step 2: Syntax-check bootstrap.sh**

Run: `bash -n C:\Users\JaredCooper\Claude\d2-edge\shared\scripts\bootstrap.sh`
Expected: no output, exit 0.

---

## Task 2: Rewrite `heal-firewall.sh` (additive migration for the existing fleet)

**Files:**
- Modify: `scripts/heal-firewall.sh` (full rewrite — keeps the flow-relay heal, adds the source-scope migration)

- [ ] **Step 1: Overwrite the file**

Overwrite `C:\Users\JaredCooper\Claude\d2-edge\scripts\heal-firewall.sh` **exactly** with:

```bash
#!/usr/bin/env bash
# Idempotent, ADDITIVE UFW heal for already-bootstrapped edge Pis. Two jobs:
#
#  (A) Source-scope migration. bootstrap.sh used to open most ports to
#      "Anywhere"; it now emits tailnet(100.64.0.0/10)+RFC1918-scoped rules
#      (RFC1918-only for iperf3/Auvik). This heal ADDS those scoped rules to
#      Pis bootstrapped before scoping existed, so they sit ALONGSIDE the
#      legacy broad rules. Removing the broad "Anywhere" rules is a DELIBERATE,
#      SEPARATE, MANUAL step (scripts/firewall-tighten.sh) run only AFTER SSH
#      over the tailnet (a 100.x source) is confirmed. This script NEVER
#      removes a rule, so it cannot lock anyone out.
#
#  (B) Flow relay ports. Open 2055/6343/4739 (scoped) on flow-exporter Pis
#      bootstrapped before the sFlow/IPFIX listeners existed (REVIEW.md R1).
#
# WHY scoped: the appliance is dual-homed (customer LAN + Tailscale overlay);
# no service needs the whole internet. iperf3 (5201) and Auvik's FTP-backup
# ingress (10021) are customer-LAN-only — never over the overlay.
#
# SAFETY: ADDITIVE ONLY. `ufw allow` is a no-op when an identical rule already
# exists; we NEVER `ufw reset`/`delete`/`disable`. A reset would briefly drop
# every rule incl. SSH (22) and has locked us out of remote fleet Pis before.
# Nothing in this script can remove a rule or close a port.
set -euo pipefail

EDGE_DIR="${EDGE_DIR:-/opt/d2-edge}"
ENV_FILE="$EDGE_DIR/.env"

if [[ $EUID -ne 0 ]]; then echo "[heal-fw] must run as root" >&2; exit 1; fi
command -v ufw >/dev/null 2>&1 || { echo "[heal-fw] ufw not installed; skip"; exit 0; }
ufw status 2>/dev/null | grep -q "Status: active" || { echo "[heal-fw] ufw inactive; skip"; exit 0; }

# Source ranges — keep in lockstep with shared/scripts/bootstrap.sh.
TAILNET="100.64.0.0/10"
RFC1918=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)
LAN_TS=("$TAILNET" "${RFC1918[@]}")   # tailnet + customer LAN
LAN_ONLY=("${RFC1918[@]}")            # customer LAN only (never the overlay)

# add_scoped <port[/proto]> <comment> <src>...  -- additive + idempotent.
# Omitting the proto (e.g. 514) opens both tcp+udp, matching the legacy rule.
add_scoped() {
    local spec="$1" comment="$2"; shift 2
    local port="${spec%%/*}" proto="" src
    [[ "$spec" == */* ]] && proto="${spec#*/}"
    for src in "$@"; do
        if [[ -n "$proto" ]]; then
            ufw allow from "$src" to any port "$port" proto "$proto" comment "$comment" >/dev/null
        else
            ufw allow from "$src" to any port "$port" comment "$comment" >/dev/null
        fi
    done
}

# ── (A) Source-scope migration — runs on EVERY Pi ──────────────────────────
echo "[heal-fw] adding source-scoped rules (legacy 'Anywhere' rules left intact — remove later via firewall-tighten.sh)"
add_scoped 22/tcp    'SSH'                                "${LAN_TS[@]}"
add_scoped 514       'Syslog'                             "${LAN_TS[@]}"
add_scoped 1812/udp  'RADIUS auth'                        "${LAN_TS[@]}"
add_scoped 1813/udp  'RADIUS acct'                        "${LAN_TS[@]}"
add_scoped 80/tcp    'cert-server (LAN onboarding)'       "${LAN_TS[@]}"
add_scoped 2083/tcp  'RadSec from customer devices'       "${LAN_TS[@]}"
add_scoped 9995/udp  'Flow: Auvik TrafficInsights (NetFlow)' "${LAN_TS[@]}"
add_scoped 9996/udp  'Flow: Auvik TrafficInsights (sFlow)'   "${LAN_TS[@]}"
add_scoped 5201/tcp  'iperf3 P2P (LAN only)'              "${LAN_ONLY[@]}"
add_scoped 10021/tcp 'Auvik FTP-backup ingress (LAN only)' "${LAN_ONLY[@]}"

# ── (B) Flow relay ports — only on flow-exporter Pis (netflow-proxy gated) ──
# Unlike bootstrap, .env exists here; only flow Pis run the relay (profile-
# gated), so don't open relay ports nothing listens on elsewhere.
# shellcheck disable=SC1090
[[ -f "$ENV_FILE" ]] && { set -a; source "$ENV_FILE" 2>/dev/null || true; set +a; }
if [[ "${DEPLOY_NETFLOW_PROXY:-enabled}" != "enabled" ]]; then
    echo "[heal-fw] netflow-proxy disabled on this Pi; skip relay ports"
    echo "[heal-fw] OK"
    exit 0
fi
declare -A RELAY_PROTO=( [2055]=NetFlow [6343]=sFlow [4739]=IPFIX )
for port in 2055 6343 4739; do
    add_scoped "${port}/udp" "Flow: ${RELAY_PROTO[$port]} -> netflow-proxy relay" "${LAN_TS[@]}"
done

echo "[heal-fw] OK"
```

- [ ] **Step 2: Syntax-check heal-firewall.sh**

Run: `bash -n C:\Users\JaredCooper\Claude\d2-edge\scripts\heal-firewall.sh`
Expected: no output, exit 0.

---

## Task 3: Create `scripts/firewall-tighten.sh` (manual, later-phase removal)

**Files:**
- Create: `scripts/firewall-tighten.sh`

**Why a separate script:** removing the legacy broad `Anywhere` rules is the *second* phase of a lockout-safe rollout — done per Pi only after `heal-firewall.sh` has added the scoped rules and SSH-over-tailnet is confirmed. It is **never** auto-run by bootstrap/update.

- [ ] **Step 1: Write the script**

Create `C:\Users\JaredCooper\Claude\d2-edge\scripts\firewall-tighten.sh` **exactly** with:

```bash
#!/usr/bin/env bash
# MANUAL, LATER-PHASE firewall tightening. Removes the legacy broad "Anywhere"
# UFW rules AFTER heal-firewall.sh has added the tailnet+RFC1918 scoped rules
# and you have confirmed SSH works over BOTH a tailnet (100.x) and a LAN source.
#
# NOT called by bootstrap.sh/update.sh — run it by hand, per Pi.
#
#   sudo bash firewall-tighten.sh            # DRY-RUN: print what it would delete
#   sudo bash firewall-tighten.sh --commit   # actually delete the broad rules
#
# Two guards make it self-lock-proof even with --commit:
#   1. A scoped SSH (22) rule must already exist (proves the migration ran).
#   2. The source IP of THIS SSH session (SSH_CONNECTION) must fall inside a
#      scoped range, so deleting the broad 22/tcp rule cannot drop this session.
#
# SAFETY: only ever `ufw delete allow <broad-spec>` — those match ONLY the
# unscoped "Anywhere" rules, never the `from <src> to any port` scoped rules.
# Never `ufw reset`/`disable`. Deleting an absent rule is a no-op.
set -euo pipefail

COMMIT=0
[[ "${1:-}" == "--commit" ]] && COMMIT=1

if [[ $EUID -ne 0 ]]; then echo "[fw-tighten] must run as root" >&2; exit 1; fi
command -v ufw >/dev/null 2>&1 || { echo "[fw-tighten] ufw not installed; abort" >&2; exit 1; }
ufw status 2>/dev/null | grep -q "Status: active" || { echo "[fw-tighten] ufw inactive; abort" >&2; exit 1; }

SCOPES=(100.64.0.0/10 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)

# Robust, dependency-free CIDR membership (integer math; no python needed).
ip2int() { local a b c d; IFS=. read -r a b c d <<<"$1"; echo $(( (a<<24)|(b<<16)|(c<<8)|d )); }
in_cidr() { # ip cidr
    local ip="$1" base="${2%/*}" bits="${2#*/}" mask
    mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
    [[ $(( $(ip2int "$ip") & mask )) -eq $(( $(ip2int "$base") & mask )) ]]
}
in_any_scope() { local ip="$1" c; for c in "${SCOPES[@]}"; do in_cidr "$ip" "$c" && return 0; done; return 1; }

# Guard 1: a scoped SSH rule must exist.
if ! ufw status | awk '/(^|[[:space:]])22(\/tcp)?[[:space:]].*ALLOW/' \
      | grep -qE '100\.64\.0\.0/10|10\.0\.0\.0/8|172\.16\.0\.0/12|192\.168\.0\.0/16'; then
    echo "[fw-tighten] no scoped SSH (22) rule found — run update.sh (heal-firewall.sh) first; abort" >&2
    exit 1
fi

# Guard 2: this SSH session's source must be inside a scoped range.
CLIENT_IP="${SSH_CONNECTION%% *}"
if [[ -z "$CLIENT_IP" ]]; then
    echo "[fw-tighten] no SSH_CONNECTION (not an SSH session?) — refusing to risk a console-less lockout; abort" >&2
    exit 1
fi
if ! in_any_scope "$CLIENT_IP"; then
    echo "[fw-tighten] your session source $CLIENT_IP is NOT in a scoped range; deleting broad rules could drop you; abort" >&2
    exit 1
fi
echo "[fw-tighten] guards passed (scoped SSH rule present; session source $CLIENT_IP is covered)"

# Legacy broad rules to remove (the pre-scoping bootstrap specs). Each delete
# matches ONLY the unscoped rule; the scoped `from <src> ...` rules are untouched.
BROAD=(
    'allow 22/tcp'
    'allow 514'
    'allow 1812/udp'
    'allow 1813/udp'
    'allow 5201/tcp'
    'allow 2055/udp'
    'allow 6343/udp'
    'allow 4739/udp'
    'allow 9995/udp'
    'allow 9996/udp'
    'allow 10021/tcp'
    'allow from 192.168.0.0/16 to any port 80 proto tcp'
    'allow from 192.168.0.0/16 to any port 2083 proto tcp'
)

for spec in "${BROAD[@]}"; do
    if [[ "$COMMIT" -eq 1 ]]; then
        # `ufw delete` is a no-op (non-zero, harmless) when the rule is absent.
        if ufw --force delete $spec >/dev/null 2>&1; then
            echo "[fw-tighten] deleted: ufw $spec"
        else
            echo "[fw-tighten] absent (ok): ufw $spec"
        fi
    else
        echo "[fw-tighten] DRY-RUN would delete: ufw delete $spec"
    fi
done

if [[ "$COMMIT" -eq 1 ]]; then
    echo "[fw-tighten] done — verify: ufw status verbose (no 'Anywhere'; SSH still ALLOW from scoped ranges)"
else
    echo "[fw-tighten] DRY-RUN only — re-run with --commit to apply"
fi
```

- [ ] **Step 2: Syntax-check firewall-tighten.sh**

Run: `bash -n C:\Users\JaredCooper\Claude\d2-edge\scripts\firewall-tighten.sh`
Expected: no output, exit 0.

---

## Task 4: Update the `update.sh` heal comment (accuracy only)

**Files:**
- Modify: `shared/scripts/update.sh` — the comment block above the `heal-firewall.sh` invocation (currently lines ~141-145)

**Why only a comment:** `update.sh` already calls `heal-firewall.sh`; the new scoping behaviour lives entirely in that called script (so it is effective on the *first* post-pull run). We only correct the comment to describe what the heal now does. Do **not** touch the `disable-ipv6.sh` call the IPv6 task added immediately after this block.

- [ ] **Step 1: Replace the comment**

Find (the comment directly above `if [[ -x "$EDGE_DIR/scripts/heal-firewall.sh" ]]; then`):

```bash
# Firewall heal: open the netflow-proxy relay's sFlow/IPFIX ports (6343/4739)
# on Pis bootstrapped before those listeners existed. bootstrap.sh sets UFW
# up only once and update.sh historically never touched it, so the relay's
# 6343/4739 inbound stayed dropped on existing Pis. Idempotent + additive
# (never resets/deletes — no SSH-lockout risk). Closes REVIEW.md R1.
```

Replace with:

```bash
# Firewall heal (additive, never resets/deletes — no SSH-lockout risk):
#  (A) add tailnet(100.64/10)+RFC1918 source-scoped rules to Pis bootstrapped
#      before source-scoping existed, ALONGSIDE the legacy broad 'Anywhere'
#      rules (whose removal is the separate manual scripts/firewall-tighten.sh
#      step, after SSH-over-tailnet is confirmed); and
#  (B) open the netflow-proxy relay's 2055/6343/4739 (scoped) on flow Pis
#      bootstrapped before those listeners existed.
# Closes REVIEW.md R1 + C6. Behaviour is in heal-firewall.sh (effective on the
# first post-pull run); this comment is the only update.sh change.
```

- [ ] **Step 2: Syntax-check update.sh**

Run: `bash -n C:\Users\JaredCooper\Claude\d2-edge\shared\scripts\update.sh`
Expected: no output, exit 0.

---

## Task 5: Commit + push from the control Pi (192.168.166.34)

> **Outward-facing / live-infra gate.** Get Jared's explicit go-ahead before this task. Coordinate the commit with the concurrent IPv6 task: the IPv6 files (`scripts/disable-ipv6.sh`, `shared/files/99-disable-ipv6.conf`, its bootstrap/update edits) may land in the same or a sibling commit — do not drop them. Do not improvise remotes/branches/force ops (`followup_deferred_backup_git_remediation`).

**Files:** none (git + deploy only)

- [ ] **Step 1: Stage and review on the control Pi**

```bash
git -C /opt/d2-edge add shared/scripts/bootstrap.sh shared/scripts/update.sh \
    scripts/heal-firewall.sh scripts/firewall-tighten.sh \
    docs/superpowers/plans/2026-06-17-firewall-source-scope.md
git -C /opt/d2-edge status
git -C /opt/d2-edge diff --cached
```
Expected: `bootstrap.sh` + `update.sh` + `heal-firewall.sh` modified, `firewall-tighten.sh` + the plan doc new; no unrelated changes (IPv6 files staged separately if co-committing).

- [ ] **Step 2: Commit**

```bash
git -C /opt/d2-edge commit -m "edge(firewall): source-scope UFW to tailnet+RFC1918 (iperf/Auvik LAN-only)

bootstrap.sh now emits per-source scoped rules instead of Anywhere; 5201
(iperf3) and 10021 (Auvik FTP-backup) are RFC1918-only. heal-firewall.sh
additively migrates the existing fleet (never deletes — broad-rule removal
is the separate, guarded firewall-tighten.sh step after SSH-over-tailnet is
confirmed). Closes REVIEW.md R1 + C6."
```
Expected: commit succeeds.

- [ ] **Step 3: Push the fleet branch**

```bash
git -C /opt/d2-edge push origin HEAD
```
Expected: push succeeds. (Customer-fleet rollout stays Ansible/manual-gated on Jared — `project_fleet_rollout_ansible`.)

---

## Task 6: Validate on Pi #2 (192.168.21.16) — additive scoping is live and SSH survives

> SSH only `192.168.21.16` (D2-owned). The functional change is in `heal-firewall.sh` (a *called* script) → effective on the **first** post-pull `update.sh` run. Run `update.sh` a second time to also pick up the `update.sh` comment + prove idempotency.

**Files:** none (validation only)

- [ ] **Step 1: Capture the pre-state**

```bash
sudo ufw status verbose
```
Expected: legacy broad rules present (`22/tcp ALLOW Anywhere`, etc.). Save this output for comparison.

- [ ] **Step 2: Run update.sh (first run — applies the scoped-rule heal)**

```bash
sudo bash /opt/d2-edge/shared/scripts/update.sh
```
Expected: in the `[3/6]` output:
```
[heal-fw] adding source-scoped rules (legacy 'Anywhere' rules left intact — remove later via firewall-tighten.sh)
[heal-fw] OK
```
The session must **not** drop (additive only).

- [ ] **Step 3: Confirm scoped rules were added ALONGSIDE the broad ones**

```bash
sudo ufw status verbose
```
Expected: for each device port there is now BOTH a legacy `Anywhere` rule AND scoped rules, e.g.:
```
22/tcp                     ALLOW IN    Anywhere
22/tcp                     ALLOW IN    100.64.0.0/10
22/tcp                     ALLOW IN    10.0.0.0/8
22/tcp                     ALLOW IN    172.16.0.0/12
22/tcp                     ALLOW IN    192.168.0.0/16
```
and `5201/tcp` + `10021/tcp` scoped to the three RFC1918 ranges **only** (no `100.64.0.0/10` line). The broad rules are still there — that is correct at this phase.

- [ ] **Step 4: CRITICAL — confirm SSH still works over BOTH paths (do this before any tighten)**

From a **tailnet (100.x)** host:
```bash
ssh -o IdentitiesOnly=yes -i id_claude admin@192.168.21.16 'echo SSH-OVER-TAILNET-OK; echo "$SSH_CONNECTION"'
```
Expected: `SSH-OVER-TAILNET-OK` and an `SSH_CONNECTION` whose first field is a `100.x` address.
From a **LAN (RFC1918)** host on the same site:
```bash
ssh -o IdentitiesOnly=yes -i id_claude admin@192.168.21.16 'echo SSH-OVER-LAN-OK'
```
Expected: `SSH-OVER-LAN-OK`. (Both must pass before the broad rules are ever removed.)

- [ ] **Step 5: Confirm services still function (scoped rules don't block existing traffic)**

```bash
docker ps --format '{{.Names}}\t{{.Status}}'
# iperf3 LAN-to-LAN (from another D2 Pi on the same customer LAN):
#   iperf3 -c 192.168.21.16 -t 3      -> expect a throughput result
docker logs --since 3m freeradius-proxy 2>&1 | tail -10   # RADIUS proxy healthy
docker logs --since 3m syslog-proxy 2>&1 | tail -5        # syslog ingest healthy
docker logs --since 3m netflow-proxy 2>&1 | tail -10      # flow relay healthy
docker logs --since 3m auvik 2>&1 | tail -10              # Auvik collector healthy
```
Expected: all containers `Up`; iperf3 from a LAN peer succeeds; RADIUS/syslog/flow/Auvik show no new errors. (Auvik 10021 + iperf 5201 are reachable from the LAN; both correctly NOT reachable over the tailnet.)

- [ ] **Step 6: Second update.sh run — idempotency + no duplicate rules**

```bash
sudo bash /opt/d2-edge/shared/scripts/update.sh
sudo ufw status numbered | sort | uniq -d
```
Expected: heal prints the same lines; `uniq -d` shows **no** duplicated rule lines (additive `ufw allow` is a no-op on identical rules).

- [ ] **Step 7: Decision gate**

- **Steps 3-6 all pass →** additive scoping is live and SSH is safe over both paths. Proceed to the (separate) tightening phase (Task 7) only when Jared approves removing the broad rules fleet-wide.
- **Any SSH path failed, or a service broke →** STOP. The broad rules are still in place so nothing is locked out; investigate (likely a source range omitted) before tightening.

---

## Task 7: (LATER PHASE — separate approval) Remove the broad rules via `firewall-tighten.sh`

> Do this per Pi **only after** Task 6 passed AND Jared approves. It is the lockout-sensitive step. Always start with a DRY-RUN, keep an out-of-band path open, and prefer doing the Tailscale-only fleet from a host that also has the customer-LAN path where possible.

**Files:** none (live firewall change)

- [ ] **Step 1: DRY-RUN on Pi #2**

```bash
sudo bash /opt/d2-edge/scripts/firewall-tighten.sh
```
Expected: `guards passed (...)` then a list of `DRY-RUN would delete: ufw delete allow ...` lines; nothing changed yet.

- [ ] **Step 2: Commit the tighten**

```bash
sudo bash /opt/d2-edge/scripts/firewall-tighten.sh --commit
sudo ufw status verbose
```
Expected: each broad rule reported `deleted` (or `absent (ok)`); `ufw status verbose` now shows **no** `Anywhere` ALLOW rules — SSH 22 only `ALLOW` from `100.64.0.0/10` + the three RFC1918 ranges; 5201/10021 from RFC1918 only.

- [ ] **Step 3: Re-confirm both SSH paths AFTER tightening**

Repeat Task 6 Step 4 (tailnet host + LAN host). Both must still return OK. If a path fails, immediately re-add the scoped rule it needs (additive) — e.g. `sudo ufw allow from <range> to any port 22 proto tcp comment 'SSH'` — never `ufw reset`.

- [ ] **Step 4: Re-confirm services** — repeat Task 6 Step 5. RADIUS/syslog/SNMP/flow/Auvik/iperf all still function.

---

## Lockout-safe rollout summary (the documented sequence)

1. **Fresh Pis** — new `bootstrap.sh` writes scoped rules only; clean from `[6/8]`. No broad rules ever exist.
2. **Existing fleet, phase 1 (additive)** — `update.sh` → `heal-firewall.sh` ADDS scoped rules next to the broad rules. Effective on the first post-pull run. SSH cannot drop (nothing removed). **Confirm SSH over a 100.x source AND a LAN source.**
3. **Existing fleet, phase 2 (tighten)** — only after phase 1 verified, run `firewall-tighten.sh` (dry-run, then `--commit`) per Pi. Its two guards refuse to delete the broad 22/tcp rule unless a scoped SSH rule exists and the operator's own session source is inside a scoped range.
4. **Never** `ufw reset` / `ufw disable` on a live Pi. All removals go through `firewall-tighten.sh` (rule-specific `ufw delete`). Only SSH the D2-owned Pis `.34` and `192.168.21.16`.

---

## Self-Review

**1. Spec coverage:**
- *Scope to tailnet AND RFC1918, not overlay-only* → Task 1/2 `LAN_TS`. ✅
- *Rewrite bootstrap UFW block to per-source rules* → Task 1. ✅
- *22 + device ports + flow ports → tailnet+RFC1918; supersede hardcoded 192.168.0.0/16 on 80/2083 (C6)* → Task 1 (`LAN_TS` incl. full RFC1918 on 80/2083). ✅
- *5201 RFC1918-only* → Task 1/2 `LAN_ONLY`. ✅
- *10021 → RFC1918-only (Jared confirmed in-use)* → Task 1/2 `LAN_ONLY`. ✅
- *Fresh bootstrap clean; existing Pis additive then remove broad rules separately; never `ufw reset`; follow heal-firewall additive pattern* → Task 2 (additive) + Task 3/7 (separate guarded removal) + safety conventions. ✅
- *Two-Pi workflow; update.sh self-edit lag; only D2 Pis* → Tasks 5-6 (behaviour in called script = first-run effective) + conventions. ✅
- *Coordinate merge with the concurrent IPv6 task on the same UFW block* → "Coordination" section (no textual overlap; benign interaction). ✅
- *VERIFY: ufw status scoped, no Anywhere, both SSH paths, iperf LAN-only, services function* → Task 6 + Task 7 Steps 2-4. ✅
- *Deliverable: updated bootstrap.sh + update.sh (+ heal extension), validated, sequence documented* → Tasks 1-4 + Task 6 + this summary. ✅

**2. Placeholder scan:** All file bodies are complete; the only `<...>` tokens are operator-supplied runtime values in validation commands (LAN peer IP, range to re-add). No TBD/"similar to Task N". ✅

**3. Type/name consistency:** `TAILNET`/`RFC1918`/`LAN_TS`/`LAN_ONLY` and the `ufw_scoped`/`add_scoped` helper signature `<port[/proto]> <comment> <src>...` are identical between bootstrap.sh and heal-firewall.sh. `firewall-tighten.sh`'s `BROAD` specs exactly mirror the legacy bootstrap rule specs being superseded. The scoped-SSH guard regex matches the four `SCOPES` CIDRs. ✅
