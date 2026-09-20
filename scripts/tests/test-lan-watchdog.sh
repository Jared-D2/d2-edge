#!/usr/bin/env bash
# Decision-logic tests for lan-watchdog.sh. Every external command is shimmed
# on PATH, so this never touches a real interface and runs anywhere bash does.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$HERE/lan-watchdog.sh"
fails=0
check(){ if [[ "$1" == "$2" ]]; then echo "ok: $3"; else echo "FAIL: $3 (got '$1', want '$2')"; fails=$((fails+1)); fi; }

T=""
setup() {
    [[ -n "$T" ]] && rm -rf "$T"
    T="$(mktemp -d)"
    mkdir -p "$T/bin" "$T/state" "$T/persist" "$T/sys/eth0/statistics"
    echo 1 > "$T/sys/eth0/carrier"; echo 1000 > "$T/sys/eth0/statistics/tx_packets"
    echo "default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.2 metric 100" > "$T/route_out"
    echo "10.0.0.1 lladdr aa:bb:cc:dd:ee:ff REACHABLE" > "$T/neigh_out"
    echo 0 > "$T/ping_rc"; : > "$T/actions"; : > "$T/log"
    cat > "$T/bin/ip" <<EOF
#!/usr/bin/env bash
case "\$*" in
  "-4 route show default") cat "$T/route_out" ;;
  "-4 neigh show to "*)    cat "$T/neigh_out" ;;
  "link set dev "*)        echo "ip \$*" >> "$T/actions" ;;
esac
exit 0
EOF
    cat > "$T/bin/ping" <<EOF
#!/usr/bin/env bash
# A working NIC transmits the ARP/ICMP we provoke; a stalled one does not.
if [[ -e "$T/tx_advances" ]]; then
  echo \$(( \$(cat "$T/sys/eth0/statistics/tx_packets") + 3 )) > "$T/sys/eth0/statistics/tx_packets"
fi
exit \$(cat "$T/ping_rc")
EOF
    printf '#!/usr/bin/env bash\necho "$*" >> "%s/log"\n' "$T" > "$T/bin/logger"
    printf '#!/usr/bin/env bash\necho "systemctl $*" >> "%s/actions"\n' "$T" > "$T/bin/systemctl"
    for c in sleep nmcli ethtool dmesg sync; do printf '#!/usr/bin/env bash\nexit 0\n' > "$T/bin/$c"; done
    chmod +x "$T/bin/"*
}
run() {  # run [N] — invoke the watchdog N times (default 1)
    local n="${1:-1}" i
    for ((i = 0; i < n; i++)); do
        PATH="$T/bin:$PATH" LAN_WD_STATE_DIR="$T/state" LAN_WD_PERSIST_DIR="$T/persist" \
        LAN_WD_NET_SYS="$T/sys" LAN_WD_DISABLE_FILE="$T/disabled" LAN_WD_SETTLE_SECS=0 \
        LAN_WD_DRY_RUN="${DRY:-0}" bash "$SCRIPT"
    done
}
strikes()  { cat "$T/state/strikes" 2>/dev/null || echo 0; }
bounces()  { grep -c "link set dev eth0 down" "$T/actions"; }
reboots()  { grep -c "systemctl reboot" "$T/actions"; }
dead_gw()  { echo 1 > "$T/ping_rc"; echo "10.0.0.1 FAILED" > "$T/neigh_out"; }

# --- healthy paths -------------------------------------------------------------
setup; run 3
check "$(strikes)/$(bounces)" "0/0" "REACHABLE neighbour: healthy, no action"

setup; echo "10.0.0.1 lladdr aa:bb:cc:dd:ee:ff STALE" > "$T/neigh_out"; run 3
check "$(strikes)" "0" "STALE neighbour but ping answers: healthy"

setup; echo 1 > "$T/ping_rc"; run 3   # neigh_out stays REACHABLE
check "$(strikes)" "0" "gateway drops ICMP but answers ARP (lmc001): healthy"

setup; echo 1 > "$T/ping_rc"; echo "10.0.0.1 lladdr aa:bb:cc:dd:ee:ff DELAY" > "$T/neigh_out"; run 5
check "$(strikes)" "0" "neighbour still resolving: no verdict, no strike"

setup; : > "$T/route_out"; run 5
check "$(strikes)" "0" "no wired default route ever seen: nothing to guard"

setup; dead_gw; touch "$T/disabled"; run 12
check "$(strikes)/$(bounces)/$(reboots)" "0/0/0" "disable file: watchdog inert"

# --- tx-stall ladder (the 2026-09-19 signature) --------------------------------
setup; dead_gw; run 2
check "$(strikes)/$(bounces)" "2/0" "tx-stall: no bounce before strike 3"
run 1
check "$(bounces)/$(cat "$T/persist/bounce_count")" "1/1" "tx-stall: bounce at strike 3, counter bumped"
check "$(ls "$T/persist/snapshots" | wc -l | tr -d ' ')" "1" "evidence snapshot taken on first strike"
run 6
check "$(reboots)" "0" "tx-stall: no reboot before strike 10"
run 1
check "$(reboots)/$(cat "$T/persist/reboot_count")" "1/1" "tx-stall: reboot at strike 10, counter bumped"

# bounce leaves the NIC with no carrier and no route — must still reboot
setup; dead_gw; run 3
echo 0 > "$T/sys/eth0/carrier"; : > "$T/route_out"; run 7
check "$(reboots)" "1" "stall episode that loses carrier after the bounce still reboots"

# --- gw-dead ladder (tx works, gateway silent) ---------------------------------
setup; dead_gw; touch "$T/tx_advances"; run 4
check "$(bounces)" "0" "gw-dead: no bounce at strike 3-4"
run 1
check "$(bounces)" "1" "gw-dead: bounce at strike 5"
run 24
check "$(reboots)" "0" "gw-dead: no reboot through strike 29"
run 1
check "$(reboots)" "1" "gw-dead: reboot at strike 30"

# route vanished mid-boot (lease lost): judged against the cached route
setup; run 1; : > "$T/route_out"; touch "$T/tx_advances"; run 5
check "$(strikes)/$(bounces)" "5/1" "cached route + no current route: strikes and bounces"

# --- no-carrier from the outset: bounce, never reboot --------------------------
setup; dead_gw; echo 0 > "$T/sys/eth0/carrier"; run 40
check "$(reboots)" "0" "no-carrier at episode start: never reboots"
check "$(bounces)" "3" "no-carrier: bounces at 5, 20, 35"

# --- reboot rate limit + backoff ----------------------------------------------
setup; dead_gw; date +%s > "$T/persist/last_reboot"; run 18
check "$(reboots)" "0" "watchdog reboot <6 h ago: reboot suppressed"
check "$(bounces)" "2" "suppressed reboot still bounces periodically (3, 18)"

setup; dead_gw; echo $(( $(date +%s) - 7*3600 )) > "$T/persist/last_reboot"; echo 1 > "$T/persist/consecutive_reboots"; run 10
check "$(reboots)" "0" "2nd consecutive reboot needs 12 h gap: 7 h suppressed"
setup; dead_gw; echo $(( $(date +%s) - 13*3600 )) > "$T/persist/last_reboot"; echo 1 > "$T/persist/consecutive_reboots"; run 10
check "$(reboots)/$(cat "$T/persist/consecutive_reboots")" "1/2" "2nd consecutive reboot allowed after 13 h"

# --- recovery -----------------------------------------------------------------
setup; dead_gw; echo 2 > "$T/persist/consecutive_reboots"; run 4
echo 0 > "$T/ping_rc"; echo "10.0.0.1 lladdr aa:bb:cc:dd:ee:ff REACHABLE" > "$T/neigh_out"; run 1
check "$(strikes)" "0" "recovery clears strikes"
[[ -e "$T/persist/consecutive_reboots" || -e "$T/state/episode_stall" ]]; check "$?" "1" "recovery clears reboot backoff + episode memory"
grep -q "recovered after 4 strike" "$T/log"; check "$?" "0" "recovery is logged"

# --- dry run ------------------------------------------------------------------
setup; dead_gw; DRY=1 run 12
check "$(bounces)/$(reboots)" "0/0" "dry-run: no bounce, no reboot"
[[ -e "$T/persist/bounce_count" || -e "$T/persist/reboot_count" ]]; check "$?" "1" "dry-run: counters untouched"
grep -q "DRY-RUN: would reboot" "$T/log"; check "$?" "0" "dry-run: intent logged"

rm -rf "$T"
[[ "$fails" -eq 0 ]] && { echo "ALL PASS"; exit 0; } || { echo "$fails FAILED"; exit 1; }
