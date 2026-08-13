#!/usr/bin/env python3
"""Render ser2net.yaml + udev slot rules from ports.yaml.

Usage: render-ser2net.py <ports.yaml> <ser2net.yaml out> <slots.rules out>
Exits non-zero on duplicate slots, bad slot range, or missing fields.
Requires python3-yaml (installed by setup-oob.sh).

Slot identity — each slot gives exactly ONE of:
  usb_serial: adapter's unique serial (udevadm ... | grep ID_SERIAL_SHORT).
              The slot follows the adapter to ANY port or hub position.
              Fleet standard: FTDI-based adapters (unique serials). CP2102s
              commonly share the non-unique "0001"; CH340s have none.
  usb_path:   physical USB port (ID_PATH). For serial-less adapters; slot
              identity = the labelled port, moving the cable needs an edit.
"""
import re
import sys
import yaml

# device/platform are interpolated into YAML quoted scalars AND a
# filesystem path — restrict to a safe charset so a quote can't break the
# whole config (all slots down) and a '/' can't write transcripts outside
# the audited /var/log/oob-console directory (review finding #10).
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
SERIAL_RE = re.compile(r"^[A-Za-z0-9]{4,32}$")
PATH_RE = re.compile(r"^[A-Za-z0-9:._-]{4,128}$")

# kickolduser: a stale/dead TCP session must not lock the slot until a
# container restart (pilot lockout); the newest connection wins.
# NOTE: ser2net 4.x has no per-connection idle-timeout option ('timeout:'
# is rejected as unknown and KILLS the connection definition — verified on
# the pilot); abandoned-session hygiene relies on kickolduser + device-side
# exec-timeout. mdns off: no resolver in the isolated netns.
CONN_TMPL = """\
connection: &slot{slot:02d}
  accepter: telnet(rfc2217),tcp,{port}
  connector: serialdev,/dev/d2-console/slot{slot:02d},{baud}n81,local
  options:
    banner: "D2 OOB console — {device} ({platform}) slot {slot}\\r\\n"
    trace-both: '/var/log/oob-console/{device}-\\p-\\Y\\M\\D.log'
    trace-timestamp: true
    max-connections: 1
    kickolduser: true
    mdns: false
"""

# Slot directory on :3000 — an engineer who remembers only the hostname
# telnets here and sees what lives on which port. echo connector: prints
# the banner, echoes input, holds no serial device.
DIR_TMPL = """\
connection: &directory
  accepter: telnet,tcp,3000
  connector: echo
  options:
    banner: "{banner}"
    max-connections: 4
    mdns: false
"""

RULE_PATH_TMPL = ('SUBSYSTEM=="tty", ENV{{ID_PATH}}=="{ident}", '
                  'SYMLINK+="d2-console/slot{slot:02d}", ENV{{ID_MM_DEVICE_IGNORE}}="1"\n')
RULE_SERIAL_TMPL = ('SUBSYSTEM=="tty", ENV{{ID_SERIAL_SHORT}}=="{ident}", '
                    'SYMLINK+="d2-console/slot{slot:02d}", ENV{{ID_MM_DEVICE_IGNORE}}="1"\n')


def main():
    ports_f, ser2net_f, rules_f = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(ports_f) as f:
        data = yaml.safe_load(f)
    slots = (data or {}).get("slots") or []
    if not slots:
        sys.exit("render-ser2net: no slots defined in %s" % ports_f)
    seen, seen_ident = set(), set()
    conns, rules, dir_lines = [], [], []
    for s in slots:
        try:
            n = int(s["slot"]); dev = str(s["device"])
            baud = int(s["baud"])
            platform = str(s.get("platform", "unknown"))
        except (KeyError, TypeError, ValueError) as e:
            sys.exit("render-ser2net: bad slot entry %r (%s)" % (s, e))
        if not 1 <= n <= 16:
            sys.exit("render-ser2net: slot %d out of range 1-16" % n)
        if n in seen:
            sys.exit("render-ser2net: duplicate slot %d" % n)
        for label, val in (("device", dev), ("platform", platform)):
            if not NAME_RE.match(val):
                sys.exit("render-ser2net: slot %d %s %r invalid — use letters/"
                         "digits/dot/dash/underscore, max 32 chars" % (n, label, val))
        serial = s.get("usb_serial")
        path = s.get("usb_path")
        if bool(serial) == bool(path):
            sys.exit("render-ser2net: slot %d needs exactly one of usb_serial / usb_path" % n)
        if serial is not None:
            serial = str(serial)
            if not SERIAL_RE.match(serial):
                sys.exit("render-ser2net: slot %d usb_serial %r invalid" % (n, serial))
            ident, tmpl, how = serial, RULE_SERIAL_TMPL, "serial " + serial
        else:
            path = str(path)
            if not PATH_RE.match(path):
                sys.exit("render-ser2net: slot %d usb_path %r invalid" % (n, path))
            ident, tmpl, how = path, RULE_PATH_TMPL, "port-bound"
        if ident in seen_ident:
            sys.exit("render-ser2net: identity %r used by two slots" % ident)
        seen.add(n); seen_ident.add(ident)
        conns.append(CONN_TMPL.format(slot=n, port=3000 + n, baud=baud,
                                      device=dev, platform=platform))
        rules.append(tmpl.format(ident=ident, slot=n))
        dir_lines.append(" :%d  slot %-2d  %-32s %-16s %6d baud  [%s]"
                         % (3000 + n, n, dev, platform, baud, how))
    banner = ("\\r\\nD2 OOB console directory\\r\\n"
              + "\\r\\n".join(dir_lines)
              + "\\r\\n(telnet <this-host> <port>; newest connection wins a busy slot)\\r\\n")
    with open(ser2net_f, "w") as f:
        f.write("%YAML 1.1\n---\n" + DIR_TMPL.format(banner=banner)
                + "\n" + "\n".join(conns))
    with open(rules_f, "w") as f:
        f.write("# Rendered by render-ser2net.py from ports.yaml — do not edit\n"
                + "".join(rules))


if __name__ == "__main__":
    main()
