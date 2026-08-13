#!/usr/bin/env python3
"""Render ser2net.yaml + udev slot rules from ports.yaml.

Usage: render-ser2net.py <ports.yaml> <ser2net.yaml out> <slots.rules out>
Exits non-zero on duplicate slots, bad slot range, or missing fields.
Requires python3-yaml (installed by setup-oob.sh).
"""
import sys
import yaml

CONN_TMPL = """\
connection: &slot{slot:02d}
  accepter: telnet(rfc2217),tcp,{port}
  connector: serialdev,/dev/d2-console/slot{slot:02d},{baud}n81,local
  options:
    banner: "D2 OOB console — {device} ({platform}) slot {slot}\\r\\n"
    trace-both: '/var/log/oob-console/{device}-\\p-\\Y\\M\\D.log'
    trace-timestamp: true
    max-connections: 1
"""

RULE_TMPL = ('SUBSYSTEM=="tty", ENV{{ID_PATH}}=="{usb_path}", '
             'SYMLINK+="d2-console/slot{slot:02d}", ENV{{ID_MM_DEVICE_IGNORE}}="1"\n')


def main():
    ports_f, ser2net_f, rules_f = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(ports_f) as f:
        data = yaml.safe_load(f)
    slots = (data or {}).get("slots") or []
    if not slots:
        sys.exit("render-ser2net: no slots defined in %s" % ports_f)
    seen = set()
    conns, rules = [], []
    for s in slots:
        try:
            n = int(s["slot"]); dev = str(s["device"])
            baud = int(s["baud"]); path = str(s["usb_path"])
            platform = str(s.get("platform", "unknown"))
        except (KeyError, TypeError, ValueError) as e:
            sys.exit("render-ser2net: bad slot entry %r (%s)" % (s, e))
        if not 1 <= n <= 16:
            sys.exit("render-ser2net: slot %d out of range 1-16" % n)
        if n in seen:
            sys.exit("render-ser2net: duplicate slot %d" % n)
        seen.add(n)
        conns.append(CONN_TMPL.format(slot=n, port=3000 + n, baud=baud,
                                      device=dev, platform=platform))
        rules.append(RULE_TMPL.format(usb_path=path, slot=n))
    with open(ser2net_f, "w") as f:
        f.write("%YAML 1.1\n---\n" + "\n".join(conns))
    with open(rules_f, "w") as f:
        f.write("# Rendered by render-ser2net.py from ports.yaml — do not edit\n"
                + "".join(rules))


if __name__ == "__main__":
    main()
