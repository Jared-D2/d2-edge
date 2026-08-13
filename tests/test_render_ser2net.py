#!/usr/bin/env python3
"""Plain-assert tests for oob-console/render-ser2net.py (no pytest dep)."""
import subprocess, sys, tempfile, pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
RENDER = REPO / "oob-console" / "render-ser2net.py"

SAMPLE = """\
slots:
  - slot: 1
    device: ncm-fgt01
    baud: 9600
    platform: fortigate
    usb_path: platform-fd500000.usb-usb-0:1.1:1.0
  - slot: 2
    device: ncm-cx01
    baud: 115200
    platform: aruba-cx
    usb_path: platform-fd500000.usb-usb-0:1.2:1.0
"""

def render(yaml_text):
    with tempfile.TemporaryDirectory() as td:
        ports = pathlib.Path(td, "ports.yaml"); ports.write_text(yaml_text)
        out = pathlib.Path(td, "ser2net.yaml")
        rules = pathlib.Path(td, "slots.rules")
        r = subprocess.run([sys.executable, str(RENDER), str(ports), str(out), str(rules)],
                           capture_output=True, text=True)
        return r, (out.read_text() if out.exists() else ""), \
               (rules.read_text() if rules.exists() else "")

r, ser2net, rules = render(SAMPLE)
assert r.returncode == 0, r.stderr
# ser2net: one connection per slot, port 3000+slot, device symlink, baud
assert "3001" in ser2net and "3002" in ser2net
assert "/dev/d2-console/slot01" in ser2net and "/dev/d2-console/slot02" in ser2net
assert "9600n81" in ser2net and "115200n81" in ser2net
assert "ncm-fgt01" in ser2net  # trace log path carries device name
# udev fragment: ID_PATH-keyed symlink per slot
assert 'ENV{ID_PATH}=="platform-fd500000.usb-usb-0:1.1:1.0"' in rules
assert 'SYMLINK+="d2-console/slot01"' in rules

# duplicate slot numbers must fail loud
r2, _, _ = render(SAMPLE.replace("slot: 2", "slot: 1"))
assert r2.returncode != 0 and "duplicate" in r2.stderr.lower()

# out-of-range slot must fail loud
r3, _, _ = render(SAMPLE.replace("slot: 2", "slot: 17"))
assert r3.returncode != 0 and "range" in r3.stderr.lower()

# device names that would break YAML quoting or escape the log dir must fail
r4, _, _ = render(SAMPLE.replace("ncm-cx01", 'ncm "core" fw'))
assert r4.returncode != 0 and "invalid" in r4.stderr.lower()
r5, _, _ = render(SAMPLE.replace("ncm-cx01", "audit/../fgt01"))
assert r5.returncode != 0 and "invalid" in r5.stderr.lower()

# stale-session and idle-session protections must be present on every slot
assert ser2net.count("kickolduser: true") == 2
assert ser2net.count("mdns: false") == 2

print("OK")
