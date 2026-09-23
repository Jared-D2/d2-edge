# OOB node hardware — printable enclosure

`oob-case.scad` is a **parametric OpenSCAD model** for the OOB console
node stack: Geekworm X1205 UPS (bottom) → Raspberry Pi 5 + active cooler
→ Waveshare PCIe 4G HAT+ (top, FFC). Two printed parts: base tray
(corner bosses + M2.5 stack standoffs at the Pi hole pattern) and a
screw-down vented lid whose inside face is the adhesive zone for the
bundle's PCB LTE antennas (plastic = RF-transparent). Optional SMA
bulkhead holes for external blades at low-signal sites.

## Workflow (do NOT print the defaults)

1. Assemble the bare stack when the hardware arrives.
2. Measure and set in the header: `stack_h`, `stack_l`, `stack_w`, then
   the port-cutout arrays (`front_cuts` / `rear_cuts` — every `[MEASURE]`
   comment). Heights are relative to the cavity floor.
3. Preview with `part = "both"` in the OpenSCAD GUI (F5), sanity-check
   cutouts against the stack.
4. Export:
   ```
   openscad -D part=\"base\" -o oob-case-base.stl docs/hardware/oob-case.scad
   openscad -D part=\"lid\"  -o oob-case-lid.stl  docs/hardware/oob-case.scad
   ```
5. Print in **PETG or ASA** (never PLA — comms cabinets exceed its glass
   temperature in an AU summer), 0.2 mm layers, 3 perimeters, no supports.
6. After first fit: trim clearances, re-export, and commit the tuned
   parameter values back to this repo so the fleet prints one known-good
   case.

Signal check after assembly: `oob.status[csq]` in Zabbix — CSQ ≥ 15 with
internal antennas is fine; below that, fit the SMA bulkheads + external
blades (holes are in the model, `sma_holes = 2`).
