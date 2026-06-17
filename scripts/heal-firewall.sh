#!/usr/bin/env bash
# Idempotent UFW heal for the D2 edge appliance — source-scopes ingress.
#
# WHAT: brings already-deployed Pis up to the source-scoped firewall posture
# that bootstrap.sh now emits on fresh installs. Two phases:
#
#   Phase A (always, ADDITIVE) — ensure every service rule is pinned to a
#     trusted source zone: the Tailscale overlay (TAILNET 100.64.0.0/10)
#     and/or the local customer LAN (RFC1918). Carve-outs: iperf3 (5201) =
#     tailnet ONLY; Auvik FTP-backup (10021) = RFC1918 ONLY. The flow-relay
#     ports (2055/6343/4739) are gated on DEPLOY_NETFLOW_PROXY so we never
#     open ports nothing listens on. Closes REVIEW.md R1 (sFlow/IPFIX relay
#     ports stayed dropped on pre-existing Pis) and C6 (80/2083 were hardcoded
#     to 192.168.0.0/16, firewalling 10.x / 172.16.x sites out).
#
#   Phase B (GATED, de-broaden) — remove the legacy broad "Anywhere" rules
#     that the old bootstrap created, but ONLY when BOTH hold:
#       1. .env sets FIREWALL_DROP_ANYWHERE=yes, and
#       2. the scoped SSH rule (22/tcp from the tailnet) is provably present.
#     Defaults OFF, so this heal is lockout-safe to ship fleet-wide: existing
#     Pis just gain the scoped rules (Phase A) while keeping their broad rules
#     until an operator opts in. The operator flips the flag per-box (or via
#     Ansible) AFTER confirming admin SSH still works over BOTH the tailnet
#     and the local LAN with the scoped rules in place.
#
# SAFETY: additive-first. `ufw allow` is a no-op when the rule already exists;
# we NEVER `ufw reset`. Phase B's only deletions are the bare "Anywhere"
# rules (matched by exact spec — a scoped rule carries a `from` clause and is
# never touched), and they are guarded on the scoped SSH rule existing first.
# A reset would briefly drop every rule incl. SSH (22) and has locked us out
# of remote fleet Pis before; nothing in this script can do that.
set -euo pipefail

EDGE_DIR="${EDGE_DIR:-/opt/d2-edge}"
ENV_FILE="$EDGE_DIR/.env"

if [[ $EUID -ne 0 ]]; then echo "[heal-fw] must run as root" >&2; exit 1; fi
command -v ufw >/dev/null 2>&1 || { echo "[heal-fw] ufw not installed; skip"; exit 0; }
ufw status 2>/dev/null | grep -q "Status: active" || { echo "[heal-fw] ufw inactive; skip"; exit 0; }

# .env drives the netflow-proxy gate (DEPLOY_NETFLOW_PROXY) and the de-broaden
# opt-in (FIREWALL_DROP_ANYWHERE). Unlike bootstrap, .env exists by the time
# this heal runs under update.sh.
# shellcheck disable=SC1090
[[ -f "$ENV_FILE" ]] && { set -a; source "$ENV_FILE" 2>/dev/null || true; set +a; }

# Trust zones — IPv4 CIDRs (inherently no "(v6)" rule twin, which dovetails
# with scripts/disable-ipv6.sh). MUST stay in sync with bootstrap.sh.
TAILNET=(100.64.0.0/10)
RFC1918=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)
DEVICE_FACING=("${TAILNET[@]}" "${RFC1918[@]}")

ADDED=0
# allow_scoped <port> <proto|any> <comment> <src>...
# Idempotent: ufw skips an already-present rule. Logs only genuine adds.
allow_scoped() {
    local port="$1" proto="$2" comment="$3"; shift 3
    local src out
    for src in "$@"; do
        if [[ "$proto" == "any" ]]; then
            out=$(ufw allow from "$src" to any port "$port" \
                  comment "$comment" 2>&1) || true
        else
            out=$(ufw allow from "$src" to any port "$port" proto "$proto" \
                  comment "$comment" 2>&1) || true
        fi
        if grep -q 'Rule added' <<<"$out"; then
            ADDED=$((ADDED + 1))
            echo "[heal-fw] +scoped ${port}/${proto} from ${src}"
        fi
    done
}

# ── Phase A: ensure scoped rules (additive, idempotent) ───────────────────
allow_scoped 22   tcp 'SSH'                          "${DEVICE_FACING[@]}"
allow_scoped 514  any 'Syslog'                       "${DEVICE_FACING[@]}"
allow_scoped 1812 udp 'RADIUS auth'                  "${DEVICE_FACING[@]}"
allow_scoped 1813 udp 'RADIUS acct'                  "${DEVICE_FACING[@]}"
# cert-server onboarding + RadSec. Supersedes the old hardcoded
# 192.168.0.0/16-only rules (REVIEW.md C6).
allow_scoped 80   tcp 'cert-server (LAN onboarding)' "${DEVICE_FACING[@]}"
allow_scoped 2083 tcp 'RadSec from customer devices' "${DEVICE_FACING[@]}"
allow_scoped 9995 udp 'Flow: Auvik TrafficInsights (NetFlow)' "${DEVICE_FACING[@]}"
allow_scoped 9996 udp 'Flow: Auvik TrafficInsights (sFlow)'   "${DEVICE_FACING[@]}"
# iperf3 — CARVE-OUT: tailnet only.
allow_scoped 5201 tcp 'iperf3 P2P (tailnet only)'    "${TAILNET[@]}"
# Auvik FTP-backup (FTP/21 -> 10021) — CARVE-OUT: RFC1918 only.
allow_scoped 10021 tcp 'Auvik FTP-backup (RFC1918)'  "${RFC1918[@]}"

# Flow-relay ports only on Pis that actually run the netflow-proxy relay.
if [[ "${DEPLOY_NETFLOW_PROXY:-enabled}" == "enabled" ]]; then
    allow_scoped 2055 udp 'Flow: NetFlow -> netflow-proxy relay' "${DEVICE_FACING[@]}"
    allow_scoped 6343 udp 'Flow: sFlow -> netflow-proxy relay'   "${DEVICE_FACING[@]}"
    allow_scoped 4739 udp 'Flow: IPFIX -> netflow-proxy relay'   "${DEVICE_FACING[@]}"
else
    echo "[heal-fw] netflow-proxy disabled on this Pi; skipping flow-relay ports (2055/6343/4739)"
fi

if [[ "$ADDED" -gt 0 ]]; then
    echo "[heal-fw] Phase A: added $ADDED scoped rule(s)"
else
    echo "[heal-fw] Phase A: scoped rules already present"
fi

# ── Phase B: drop legacy broad "Anywhere" rules (gated) ───────────────────
if [[ "${FIREWALL_DROP_ANYWHERE:-no}" != "yes" ]]; then
    echo "[heal-fw] Phase B: de-broaden disabled (FIREWALL_DROP_ANYWHERE!=yes); 'Anywhere' rules kept"
    echo "[heal-fw] OK"
    exit 0
fi

# GUARD: never remove the broad rules unless the scoped SSH rule (tailnet
# source) is provably in the ruleset — otherwise we could sever the only path
# into this box. Phase A ran above, so on a healthy box this always passes.
if ! ufw status | grep -E '^22/tcp[[:space:]]' | grep -q '100\.64\.0\.0/10'; then
    echo "[heal-fw] Phase B: REFUSING — scoped SSH (22/tcp from 100.64.0.0/10) not present; keeping 'Anywhere' rules" >&2
    echo "[heal-fw] OK"
    exit 0
fi

REMOVED=0
# Bare-spec rules the legacy bootstrap created as "Anywhere". Deleting by the
# exact spec only matches the Anywhere rule; scoped rules carry a `from`
# clause and are left intact. 80/2083 were already scoped to 192.168.0.0/16
# (no Anywhere rule), so they are not in this list.
for spec in 22/tcp 514 1812/udp 1813/udp 5201/tcp \
            2055/udp 6343/udp 4739/udp 9995/udp 9996/udp 10021/tcp; do
    if ufw delete allow "$spec" >/dev/null 2>&1; then
        REMOVED=$((REMOVED + 1))
        echo "[heal-fw] removed broad 'Anywhere' rule: allow ${spec}"
    fi
done
echo "[heal-fw] Phase B: removed $REMOVED broad 'Anywhere' rule(s)"
echo "[heal-fw] OK"
