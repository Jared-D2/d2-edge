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
