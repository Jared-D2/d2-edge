#!/bin/sh
# Guard: refuse to run on a Pi with no 4G HAT. Covers the compose-profiles
# gotcha where an explicit `docker compose up -d oob-console` enables a
# disabled profile — on a HAT-less Pi this crash-loops visibly instead of
# half-running. /dev is bind-mounted from the host, so /dev/d2-modem is
# the HAT-present signal (created by udev; netns-independent).
if [ ! -e /dev/d2-modem ]; then
    echo "oob-console: FATAL — /dev/d2-modem not present (no SIM7600 HAT?). Refusing to start." >&2
    exit 1
fi
if [ ! -f /etc/ser2net/ser2net.yaml ]; then
    echo "oob-console: FATAL — /etc/ser2net/ser2net.yaml missing (render-configs.sh not run?)." >&2
    exit 1
fi
mkdir -p /var/log/oob-console
exec ser2net -n -c /etc/ser2net/ser2net.yaml
