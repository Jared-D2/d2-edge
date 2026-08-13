# OOB Console — Operator Runbook

Out-of-band serial console access to site devices over 4G, independent of
the site's WAN/LAN. Design: `docs/superpowers/specs/2026-08-12-oob-console-design.md`.

## Connecting to a console

From any tailnet device in the admin group:

```
telnet <pi-hostname>-oob 3000      # slot directory — what's on this Pi
telnet <pi-hostname>-oob 3001      # slot 1, 3002 = slot 2, ...
```

- `:3000` prints the slot table (device, platform, baud, binding) and needs
  no arguments — start there if you only remember the hostname.
- A busy slot is taken over by the NEWEST connection (kickolduser) — a
  dead/stale session can't lock you out, but don't connect twice yourself.
- **Windows:** the `telnet` client isn't installed by default — use PuTTY
  (connection type Telnet, port 300N), or `dism /online /Enable-Feature
  /FeatureName:TelnetClient` once.
- In-band fallback (LAN fine, or modem dead): SSH to the Pi normally, then
  `telnet localhost 300N`.
- Every session is transcribed (keystrokes included) into the restricted
  Graylog stream `OOB Console Transcripts` — treat consoles accordingly.
- Sessions have NO idle timeout (ser2net 4.x limitation) — log out of the
  device when done; device-side `exec-timeout` is the backstop.

## Adding / moving a console device

1. Plug the adapter in — any port for FTDI adapters, the labelled port for
   others. **Fleet standard: FTDI-based USB-serial adapters** (unique
   serial → slot follows the adapter anywhere; CP2102/CH340 don't have
   usable serials and are port-bound).
2. Find its identity on the Pi:
   ```
   udevadm info -q property /dev/ttyUSBx | grep -E 'ID_SERIAL_SHORT|ID_PATH='
   ```
3. Add a slot to `/opt/d2-edge/oob-console/ports.yaml` (see
   `ports.yaml.example`): `usb_serial:` for FTDI, `usb_path:` otherwise.
4. `sudo bash /opt/d2-edge/shared/scripts/update.sh` — one run does
   everything (render, udev, restart).

Re-plugging a configured adapter later is picked up automatically
(`oob-hotplug.path` restarts ser2net when the slot set changes). NOTE:
that restart briefly drops live sessions on other slots — cable adapters
at install time, not during someone's break-glass session.

## Conventions

- Slot 2 = the modem's own spare AT port on every OOB Pi (self-test:
  connect, type `AT`, expect `OK` — proves the full path with no external
  device).
- FortiGate consoles: 9600 baud. Aruba CX: 115200.
- Device names in ports.yaml: letters/digits/dot/dash/underscore only.

## Troubleshooting

| Symptom | Meaning |
|---|---|
| `:3000` connects, slot port refused | ser2net dropped that slot — usually its serial device was absent at start; plug it in (hotplug restart is automatic) or check `ports.yaml` identity |
| Slot connects but no banner/output | Adapter present but cabled to nothing / wrong baud |
| You get kicked mid-session | Someone else (or your own reconnect) took the slot — coordinate; check the transcript in Graylog for who |
| `-oob` node not in tailnet | 4G path down: SSH the Pi in-band, `journalctl -t oob-watchdog`, `/usr/local/sbin/oob-at.py 'AT+CEREG?'` (want `0,1`/`0,5`), `vnstat -i wwan0` for data-cap exhaustion |
| Everything dead, site up | `sudo bash shared/scripts/update.sh` re-heals the whole layer; verify block tells you what's broken |

## Per-Pi enablement (recap)

HAT + SIM fitted → `.env`: `DEPLOY_OOB_CONSOLE=enabled`, `OOB_APN`,
`TS_OOB_AUTHKEY` (dedicated tag:oob OAuth client) → write `ports.yaml` →
`update.sh`. Preflight refuses the flag on Pis without the HAT.
Tailnet ACL must allow the admin group → `tag:oob:3000-3016`.
