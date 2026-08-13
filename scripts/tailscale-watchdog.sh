#!/usr/bin/env bash
# tailscale-watchdog.sh — self-heal a wedged tailscale container.
#
# Failure mode (wer001-wr-pi01, 2026-08-14): the control plane deletes an
# ephemeral node while a site outage has it offline; when the WAN comes
# back (e.g. failover to a backup service) tailscaled loops
# "PollNetMap: initial fetch failed 404: node not found" forever. Only a
# fresh `tailscale up --authkey` re-registers the node, and with our
# compose command that only happens when the container (re)starts — the
# site stayed dark 7.5 h until a manual reboot. Docker's healthcheck
# cannot see this state: `tailscale status --json` keeps succeeding while
# logged out / not in map poll, so the container reads "healthy".
#
# Restart condition — BOTH must hold on TWO consecutive runs:
#   1. tailscaled is unhealthy: BackendState != "Running" or Self.Online
#      is false (covers the 404 wedge, logged-out, and stopped states).
#   2. The control plane is reachable from the host (any HTTPS response
#      on 443) — proof that a restart can actually help. During a genuine
#      WAN outage we hold off instead of restart-flapping; tailscaled
#      recovers on its own once a durable (non-ephemeral) node regains
#      connectivity.
# The 2-strike rule (~10 min at the 5-min timer cadence) gives a healthy
# but briefly-disconnected tailscaled time to reconnect unaided.
# Backoff: at most one restart per 30 min.
#
# NOTE: an operator running `tailscale down` for maintenance will be
# auto-undone by this watchdog within ~10 minutes. Stop the timer first:
#   systemctl stop tailscale-watchdog.timer
set -u

STATE_DIR=/run/tailscale-watchdog
FAILS_F="$STATE_DIR/consecutive_fails"
LAST_F="$STATE_DIR/last_restart"
mkdir -p "$STATE_DIR"

log() { logger -t tailscale-watchdog "$*"; }

# --- 1. health probe ------------------------------------------------------
json=$(docker exec tailscale tailscale status --peers=false --json 2>/dev/null) || json=""
if [[ -n "$json" ]] \
   && grep -q '"BackendState": "Running"' <<<"$json" \
   && grep -q '"Online": true' <<<"$json"; then
    rm -f "$FAILS_F"
    exit 0
fi

# --- 2. would a restart help? ---------------------------------------------
# curl exits 0 on ANY http response (we pass no -f); TLS handshake success
# alone proves the control plane is reachable, whatever the status code.
if ! curl -sS -o /dev/null --max-time 10 https://controlplane.tailscale.com/ 2>/dev/null; then
    log "tailscaled unhealthy but control plane unreachable — WAN down, holding off"
    rm -f "$FAILS_F"
    exit 0
fi

fails=$(( $(cat "$FAILS_F" 2>/dev/null || echo 0) + 1 ))
echo "$fails" > "$FAILS_F"
if (( fails < 2 )); then
    log "unhealthy with control plane reachable (strike $fails/2) — waiting one cycle"
    exit 0
fi

# --- 3. backoff + restart ---------------------------------------------------
now=$(date +%s)
last=$(cat "$LAST_F" 2>/dev/null || echo 0)
if (( now - last < 1800 )); then
    log "still unhealthy but last restart was $((now - last))s ago (<1800s) — backing off"
    exit 0
fi
echo "$now" > "$LAST_F"
rm -f "$FAILS_F"
log "tailscaled wedged (not Running/offline) with control plane reachable — restarting container"
if docker restart tailscale >/dev/null 2>&1; then
    log "docker restart tailscale issued"
else
    log "docker restart tailscale FAILED"
fi
