# OOB 4G modem — hardware findings, d2-lab-pi01 (2026-08-23)

**For:** Jared · **From:** the 08-23 watchdog incident + fault-testing session
**Status:** software side closed (watchdog heals every variant in ≤10 min, merged `a8a9faf`); **hardware side open — the modem is coming up wedged on most of its own boots.**

## Summary

The SIM7600G-H on the pilot Pi enumerates on USB normally but comes up with its
*function side* dead — no AT reply, RNDIS link up but no DHCP — on a large
fraction of its own boots: the cold power-on that started the day, and **5 of
6 soft reboots (`AT+CFUN=1,1`) issued during the session**. It also died
twice while running, minutes after a boot, with no USB event in the kernel
log. Each time a host-side USB port reset brought it back in ~5 s. The Pi's
power, USB and software stack were checked and are clean. This is a modem /
HAT-level problem (power path, seating, or firmware boot bug), not something
the Pi software can fix — it can only keep healing it, which it now does and
counts.

## Unit under test

| | |
|---|---|
| Pi | Raspberry Pi 5 Model B Rev 1.1, 4 GB, Debian trixie, kernel 6.18.39, official 5 A PSU (`usb_max_current_enable=1`) |
| HAT | Waveshare "SIM7600X 4G HAT" (classic), data cable in the socket marked **USB** → Pi USB-2 port (bus 3, port 2, 480 M); `bMaxPower` 500 mA, `bcdDevice` 3.18 |
| Modem | SIMCOM SIM7600G-H, IMEI 862636058442946, `ATI` revision `SIM7600G_V2.0.2`, `AT+CGMR` `LE20B04SIM7600G22`, `AT+CSUB` `B04V03 / MDM9x07_LE20_G-H_22_V1.16_221104` (Nov 2022 build) |
| USB mode | PID `9011` RNDIS composite (NVRAM-pinned): if0/1 rndis, if2 diag, if3 NMEA, **if4 AT** (`/dev/d2-modem`), if5 AT (slot 2 self-test), if6 audio/other |
| SIM / carrier | ALDI (Telstra wholesale), APN `mdata.net.au`, LTE band 7, CSQ 20–21, `+CPSI` RSRP ≈ −108 dBm |
| Modem self-reports when alive | `AT+CBC` 3.838 V (VBAT rail, nominal 3.4–4.2), `AT+CPMUTEMP` 32–36 °C |
| PWRKEY | GPIO 6 pulse (the HAT(B) default) has **never had any visible effect** on this unit — the HAT is either not on the 40-pin header, or this revision maps PWRKEY elsewhere |

## The failure phenotype

- USB enumeration is **normal**: descriptors read, all 7 interfaces bind (`rndis_host` + 5 × `option`), `wwan0` renamed and gains carrier, `/dev/d2-modem` → ttyUSB2 (udev mapping verified correct).
- Function side **dead**: `AT` on if4 *and* if5 gets no reply; no DHCP offer from 192.168.225.1 on wwan0 (networkd retries forever); no data. The `-oob` tailnet node never comes up.
- It **does not recover on its own** — observed dead for 10+ min at cold boot and for the full 409 s of a controlled `CFUN` test with nothing touching USB.
- Control endpoint is half-alive: descriptor reads work, but `SET_CONFIGURATION(1)` returns EPROTO (-71). That is what stranded the old watchdog's `authorized` toggle.

## Occurrences (all on 2026-08-23, AEST)

| Time | Trigger | Outcome | Notes |
|---|---|---|---|
| 12:39 | Cold power-on (Pi off since 08-17) | **dead** from boot; 10+ min | enumerated at t=5 s; `oob-tailscale` crash-looped 42× (no route); healed manually 12:54 |
| 13:24→13:27 | none (running) | **died** | no USB event in dmesg; 10 min after a series of port-reset tests |
| 13:27 | `CFUN=1,1` (setup-oob APN step) | AT still dead 32 s after re-enum | then confounded by the old watchdog |
| 13:32 | `CFUN=1,1` (controlled) | **OK** — AT at 41 s, re-enum at ~20 s | the one good soft reboot |
| 13:33→13:38 | none (running) | **died** | ~4 min after coming up; no USB event |
| 13:40 | `CFUN=1,1`, then host port reset at t+36 s (inside boot window) | **dead** | reset inside the boot window wedges it |
| 13:47 | `CFUN=1,1` (controlled, untouched 409 s) | **dead** the whole 409 s | decisive: no host action at all |
| 14:18 | `CFUN=1,1` | **dead** at 90 s | healed by production watchdog 2nd probe |
| 17:03 | `CFUN=1,1` (watchdog step 4 under fault test) | **dead** 140 s+ | healed by ladder two probes later |

Soft reboots: **1 good / 5 bad**. The pilot's 08-13/14 cold boots and APN-set
`CFUN` resets all came up fine, so this is intermittent or newly worse — not
a constant.

## What recovers it, what doesn't

| Action | Result |
|---|---|
| Wait | never (≥409 s / ≥10 min observed) |
| `echo 0/1 > authorized` (old watchdog) | **makes it worse** — SET_CONFIG(1) → EPROTO, device left unconfigured |
| `AT+CFUN=1,1` | can't — AT is dead |
| **USBDEVFS_RESET port reset** (`usbreset`) | **AT OK ~5 s later, every time** (6 s, 5 s, 5 s, 5 s, 5 s today) — unless issued inside the modem's own boot window, which wedges it |
| + driver `unbind`/`bind` of `3-2` | needed only when the device was left unconfigured (re-issues SET_CONFIG(1)) |
| Power cycle | not needed so far; note a `sudo reboot` does **not** power-cycle the HAT (Pi 5 header 5 V stays up) — only pulling the Pi's power does |

A bus reset restoring full function in 5 s says the application processor
isn't hung — the modem's **USB function layer** is what comes up stuck.

## Ruled out (with evidence)

| Suspect | Evidence |
|---|---|
| Pi power | `vcgencmd get_throttled` = 0x0 all day; 5 A PSU negotiated (`max_current` 5000 mA); `EXT5V_V` 5.11 V; `usb_max_current_enable=1` |
| USB over-current / port power | `over_current_count` = 0 on every root-hub port; zero over-current lines in dmesg; device asks for 500 mA |
| Host USB autosuspend | `power/control=on` on the device; 60-autosuspend.rules doesn't match 1e0e |
| udev / probing the wrong port | if4 is the AT port in RNDIS mode (if5 also answers; if2/3/6 don't); symlink correct at boot and after every re-enumeration |
| ser2net / `oob-console` | restarting the container on a healthy modem → AT and ping clean for 6+ min (Experiment E) |
| NetworkManager / ModemManager | NM unmanaged drop-in in place (no activity on wwan0); ModemManager not installed |
| Pi-side concurrency | fixed separately (AT-port lock) — it caused a spurious APN rewrite, not the wedge |
| Thermal | modem 32–36 °C, Pi 52 °C |
| Cellular side | when alive: registered, CSQ 20–21, data flows; the wedge is pre-registration (no AT at all) |

## Hypotheses, most likely first

1. **Modem supply / power path on the HAT.** Symptoms fit a module whose
   USB PHY stays up while the rest of the chip fails to complete boot or
   browns out under the first TX burst (registration ≈ 20–40 s after boot,
   peak SIM7600 draw up to ~2 A). The two "died while running" events were
   3–5 min after a boot — plausibly the first registration/TAU TX. `AT+CBC`
   3.84 V when alive is fine, but we can't see the rail *during* the failure.
   Key unknown: **how is the HAT powered?** If it's not seated on the 40-pin
   header and only draws VBUS through the micro-USB data cable from a Pi
   USB-2 port, that's a ~1.2 A budget shared with the FTDI adapter — marginal
   for this module. The fact that GPIO 6 PWRKEY has never done anything
   points the same way (HAT not on the header, or a different revision).
2. **Firmware boot bug (LE20B04SIM7600G22, Nov-2022 build).** "AT port dead
   after boot until USB re-plug" is a known SIM7600 community complaint;
   SIMCom has newer LE20 builds. Would explain the intermittency without
   power involvement.
3. **Micro-USB cable / socket.** No USB errors in dmesg, so less likely, but
   a marginal cable can pass enumeration and fail bulk traffic.

## What would settle it (bench, ~30 min)

1. **Check how the HAT is powered and seated.** If it's USB-VBUS-only, seat it
   on the header (or feed the HAT's 5 V pins from the Pi's 5 V) and re-run
   the reboot test below. This is the single most informative check.
2. **Reboot test:** with the watchdog timer stopped
   (`sudo systemctl stop oob-watchdog.timer`), run
   `sudo /usr/local/sbin/oob-at.py 'AT+CFUN=1,1'` five times, waiting 2 min
   between, and note how many come back (`oob-at.py AT` → `OK` within
   ~60 s). Today's baseline: 1 of 6. Restart the timer after
   (`sudo systemctl start oob-watchdog.timer`).
3. If power is fine: **firmware update** via SIMCom's Windows tool (needs
   the diag port, PID 9001 mode) — or simply swap in the second unit / the
   Waveshare **PCIe-TO-4G/5G-M.2-USB3.2 HAT+** already proposed for the Pi 5
   (FFC, no cable, powered from the Pi properly) and compare wedge rate.
4. Confirm the real PWRKEY GPIO for this HAT revision (or that it's not on
   the header) — the watchdog's "modem absent → PWRKEY pulse" branch is
   inert on this unit either way.

## Already in place (so this is a maintenance item, not an outage)

- `oob-watchdog` heals every observed variant: AT dead ×2 probes → port
  reset → (if needed) driver rebind → oob pair restart; data-path failure
  tries the port reset *before* `CFUN` because `CFUN` itself wedges this
  unit. Worst case OOB is dark ~10–15 min after a wedge.
- Counters `oob.status[usb_recoveries]` / `[usb_recovery_failures]` on the
  Zabbix host; trigger **"OOB modem needed USB recovery 3+ times in 24h"**
  (Warning) is the signal that the hardware item is still open, and **"OOB
  modem on USB but AT unresponsive"** (Average) fires if the ladder ever
  stops working. Today: 3 recoveries since boot.
- Manual: `sudo /usr/local/sbin/oob-watchdog.sh --usb-recover`.
- Full mechanism and timeline: `docs/superpowers/specs/2026-08-12-oob-console-design.md` §14.1;
  operator table: `docs/oob-console-runbook.md`.
