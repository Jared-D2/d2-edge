#!/usr/bin/env bash
# Idempotent UFW heal for the NetFlow/sFlow/IPFIX relay ports.
#
# WHY: bootstrap.sh configures UFW exactly ONCE at provisioning and update.sh
# has never touched the firewall. Pis bootstrapped before the sFlow/IPFIX
# listeners existed only had 2055 (NetFlow) opened — that rule predated the
# relay and was even mislabelled 'Auvik'. The netflow-proxy container (nginx
# stream, host network) actually binds 2055/NetFlow, 6343/sFlow and
# 4739/IPFIX and relays each datagram to the central goflow2 collector
# (NETFLOW_COLLECTOR_HOST). With 6343/4739 closed at UFW, any sFlow or IPFIX
# exporter is silently dropped at the firewall before it reaches the relay.
# This heal lets already-bootstrapped Pis catch up on the next update.sh.
# Closes REVIEW.md R1 (decision: relay all three protocols to central —
# central goflow2 already listens on all three; see docs/reviews/).
#
# SAFETY: additive only. `ufw allow` is a no-op when the rule already exists;
# we NEVER `ufw reset`/`delete` here. A reset would briefly drop every rule
# incl. SSH (22) and has locked us out of remote fleet Pis before. Nothing in
# this script can remove the SSH rule or close a port.
set -euo pipefail

EDGE_DIR="${EDGE_DIR:-/opt/d2-edge}"
ENV_FILE="$EDGE_DIR/.env"

if [[ $EUID -ne 0 ]]; then echo "[heal-fw] must run as root" >&2; exit 1; fi
command -v ufw >/dev/null 2>&1 || { echo "[heal-fw] ufw not installed; skip"; exit 0; }
ufw status 2>/dev/null | grep -q "Status: active" || { echo "[heal-fw] ufw inactive; skip"; exit 0; }

# Only flow-exporter Pis run the relay (netflow-proxy is profile-gated). Don't
# open ports nothing listens on elsewhere. Unlike bootstrap, .env exists here.
# shellcheck disable=SC1090
[[ -f "$ENV_FILE" ]] && { set -a; source "$ENV_FILE" 2>/dev/null || true; set +a; }
if [[ "${DEPLOY_NETFLOW_PROXY:-enabled}" != "enabled" ]]; then
    echo "[heal-fw] netflow-proxy disabled on this Pi; skip relay ports"
    exit 0
fi

# netflow-proxy relay ingress ports -> central goflow2.
declare -A RELAY_PROTO=( [2055]=NetFlow [6343]=sFlow [4739]=IPFIX )
for port in 2055 6343 4739; do
    # ufw renders allowed ports as e.g. "6343/udp  ALLOW IN ..." (and a v6
    # twin). Either present -> nothing to do.
    if ufw status | grep -qE "^${port}/udp[[:space:]]"; then
        continue
    fi
    ufw allow "${port}/udp" comment "Flow: ${RELAY_PROTO[$port]} -> netflow-proxy relay" >/dev/null
    echo "[heal-fw] opened ${port}/udp (${RELAY_PROTO[$port]} relay)"
done

echo "[heal-fw] OK"
