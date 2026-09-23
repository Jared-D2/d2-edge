// ─────────────────────────────────────────────────────────────────────────
// D2 OOB console node — printable enclosure
// Stack (bottom → top): Geekworm X1205 UPS (2×21700) → Raspberry Pi 5
//                       (+ active cooler) → Waveshare PCIe 4G HAT+ (FFC)
//
// PARAMETRIC: every dimension that depends on the physical stack is a
// named parameter below. Defaults are from published specs and are
// deliberately roomy — DO NOT print a final case until the hardware is
// measured; see docs/hardware/README.md for the measure→tweak→export
// workflow. Cutout positions (ports) are the values that WILL move.
//
// Print: PETG or ASA (comms cabinets exceed PLA's glass temp in summer),
// 0.2 mm layers, 3 perimeters, no supports required. Antennas: the
// bundle's adhesive PCB antennas stick to the INSIDE of the lid (plastic
// is RF-transparent); optional SMA bulkhead holes on the right wall for
// external blades at low-signal sites.
//
// Export:  openscad -D part=\"base\" -o oob-case-base.stl oob-case.scad
//          openscad -D part=\"lid\"  -o oob-case-lid.stl  oob-case.scad
//          (or set `part` below and F6/export in the GUI; "both" previews)
// ─────────────────────────────────────────────────────────────────────────

part = "both";              // "base" | "lid" | "both" (preview)

// ── Stack + cavity ───────────────────────────────────────────────────────
// MEASURE ON ARRIVAL — the four numbers that matter most:
stack_h      = 72;          // total sandwich height incl. FFC loop  [MEASURE]
stack_l      = 92;          // longest board in the stack (X1205?)   [MEASURE]
stack_w      = 72;          // widest board (X1205 w/ 21700 holders) [MEASURE]
cable_slack  = 14;          // extra cavity length for console-USB bend radius

clr          = 2.0;         // clearance around the stack, per side
wall         = 2.4;         // wall thickness (3 perimeters @ 0.4 nozzle)
floor_t      = 2.8;
lid_t        = 2.8;

inner_l = stack_l + cable_slack + 2*clr;
inner_w = stack_w + 2*clr;
inner_h = stack_h + 4;      // headroom over the FFC loop

// ── Pi 5 mounting pattern (drives the floor standoffs) ──────────────────
pi_hole_dx   = 58;          // Pi hole grid (fixed, all Pi B boards)
pi_hole_dy   = 49;
// Stack sits with the Pi/HAT+ port edge ~2 mm inside the RIGHT wall
// (ports flush at the cutouts, adapters/dongles hang outside as on any
// Pi case); the leftover space on the LEFT is the cable/pigtail bay.
// Pi mounting holes: 3.5 mm in from the PORT edge pair spacing 58.
pi_off_x     = inner_l - 87;// left edge of Pi board (85 long + 2 mm gap)
pi_off_y     = (inner_w - pi_hole_dy)/2 - 3.5 + 3.5; // centred; tune later
standoff_h   = 4;           // lifts X1205 base off the floor (vent gap)
standoff_od  = 6.5;
standoff_id  = 2.4;         // M2.5 self-tap pilot

// ── Port cutouts ─────────────────────────────────────────────────────────
// Each entry: [x_offset_along_wall, z_bottom_above_floor, width, height]
// z is measured to the CAVITY floor (top of floor_t). ALL PLACEHOLDERS —
// set from the real stack: (heights below assume X1205 ≈ 24 mm tall,
// Pi board plane ≈ 28 mm, HAT+ board plane ≈ 48 mm above cavity floor).
// Port geography (Pi 5): ALL of 4x USB + GbE exit the SHORT end; the
// long side has only USB-C power + 2x micro-HDMI. The HAT+'s own ports
// are assumed to face the same short end as the Pi's — [MEASURE] on the
// real board, they may face elsewhere.
end_cuts = [                         // RIGHT short wall = the port end
    [ 8, 26, 34, 18],                // Pi: 2x USB3 + 2x USB2 stacks
    [44, 26, 16, 15],                // Pi: Gigabit Ethernet
    [ 8, 46, 40, 16],                // HAT+: USB3.2 ports + GbE      [MEASURE]
    [50, 46, 14, 10],                // HAT+: nano-SIM access slot    [MEASURE]
];
front_cuts = [                       // LONG front wall: service access only
    [40, 26, 12,  8],                // Pi: USB-C power (UPS feed loop)
    [56, 26, 24,  9],                // Pi: 2x micro-HDMI service slot
];
rear_cuts = [                        // LONG rear wall
    [ 8,  2, 26, 12],                // X1205: DC in + USB-C           [MEASURE]
];
left_cuts = [                        // LEFT short wall (cable bay end)
    [12, 20, 14, 26],                // console-cable pass-through notch
];
// SMA bulkhead holes — now on the LEFT short wall above the cable notch.
sma_holes    = 2;                    // 0 to omit (internal antennas only)
sma_z        = inner_h - 14;
sma_spacing  = 22;

// ── Ventilation ──────────────────────────────────────────────────────────
// Battery cells need airflow: slot grids low on both long walls + lid.
vent_slot_w  = 2.6;
vent_slot_l  = 22;
vent_pitch   = 6;
vent_rows_z  = [6, 12];              // slot row heights (battery level)
lid_vent_cols = 6;

// ── Lid fastening ────────────────────────────────────────────────────────
boss_od      = 8;
boss_id      = 2.8;                  // M3 self-tap pilot
lid_screw_d  = 3.4;

// ═════════════════════════════════════════════════════════════════════════
outer_l = inner_l + 2*wall;
outer_w = inner_w + 2*wall;
outer_h = inner_h + floor_t;

module vent_row(len_avail, z) {
    n = floor((len_avail - 10) / vent_pitch);
    for (i = [0:n-1])
        translate([5 + i*vent_pitch, -1, z])
            cube([vent_slot_w, wall + 2, 8]);   // 8 mm tall slots
}

module wall_cut(c) {                 // [x, z, w, h] on a wall's local plane
    translate([c[0], -1, floor_t + c[1]])
        cube([c[2], wall + 2, c[3]]);
}

module corner_bosses() {
    for (x = [wall + boss_od/2, outer_l - wall - boss_od/2])
        for (y = [wall + boss_od/2, outer_w - wall - boss_od/2])
            translate([x, y, floor_t])
                difference() {
                    cylinder(h = inner_h, d = boss_od, $fn = 32);
                    translate([0, 0, inner_h - 12])
                        cylinder(h = 13, d = boss_id, $fn = 24);
                }
}

module standoffs() {
    for (dx = [0, pi_hole_dx])
        for (dy = [0, pi_hole_dy])
            translate([wall + clr + pi_off_x + 3.5 + dx,
                       wall + pi_off_y + dy, floor_t])
                difference() {
                    cylinder(h = standoff_h, d = standoff_od, $fn = 32);
                    cylinder(h = standoff_h + 1, d = standoff_id, $fn = 24);
                }
}

module base() {
    difference() {
        cube([outer_l, outer_w, outer_h]);
        // cavity
        translate([wall, wall, floor_t]) cube([inner_l, inner_w, inner_h + 1]);
        // front wall (y = 0) cutouts — long wall, service access
        for (c = front_cuts) translate([wall + c[0], 0, 0]) wall_cut(c);
        // rear wall cutouts — long wall
        for (c = rear_cuts)
            translate([wall + c[0], outer_w - wall, 0]) wall_cut(c);
        // RIGHT short wall = Pi/HAT+ port end
        for (c = end_cuts)
            translate([outer_l - wall - 1, wall + c[0], floor_t + c[1]])
                cube([wall + 2, c[2], c[3]]);
        // LEFT short wall: console-cable notch
        for (c = left_cuts)
            translate([-1, wall + c[0], floor_t + c[1]])
                cube([wall + 2, c[2], c[3]]);
        // SMA bulkhead holes, LEFT short wall (above the cable notch)
        if (sma_holes > 0)
            for (i = [0:sma_holes-1])
                translate([-1,
                           outer_w/2 - ((sma_holes-1)*sma_spacing)/2
                             + i*sma_spacing, floor_t + sma_z])
                    rotate([0, 90, 0])
                        cylinder(h = wall + 2, d = 6.5, $fn = 40);
        // battery-level vents, both long walls
        for (z = vent_rows_z) {
            translate([wall, 0, 0])              vent_row(inner_l, floor_t + z);
            translate([wall, outer_w - wall, 0]) vent_row(inner_l, floor_t + z);
        }
    }
    corner_bosses();
    standoffs();
}

module lid() {
    difference() {
        union() {
            cube([outer_l, outer_w, lid_t]);
            // inner lip so the lid registers in the cavity
            translate([wall + 0.3, wall + 0.3, -3])
                difference() {
                    cube([inner_l - 0.6, inner_w - 0.6, 3]);
                    translate([1.6, 1.6, -1])
                        cube([inner_l - 3.8, inner_w - 3.8, 5]);
                }
        }
        // notch the lip where it would collide with the corner bosses
        for (x = [wall + boss_od/2, outer_l - wall - boss_od/2])
            for (y = [wall + boss_od/2, outer_w - wall - boss_od/2])
                translate([x, y, -4])
                    cylinder(h = 5, d = boss_od + 1.2, $fn = 32);
        // corner screw holes (match bosses)
        for (x = [wall + boss_od/2, outer_l - wall - boss_od/2])
            for (y = [wall + boss_od/2, outer_w - wall - boss_od/2])
                translate([x, y, -4])
                    cylinder(h = lid_t + 8, d = lid_screw_d, $fn = 24);
        // lid vents over the stack
        for (i = [0:lid_vent_cols-1])
            translate([outer_l/2 - (lid_vent_cols*8)/2 + i*8,
                       outer_w/2 - vent_slot_l/2, -1])
                cube([vent_slot_w, vent_slot_l, lid_t + 2]);
    }
    // NOTE: inside face of this lid = adhesive zone for the bundle's PCB
    // LTE antennas — keep them ≥20 mm apart and away from the vent slots.
}

if (part == "base" || part == "both") base();
if (part == "lid" || part == "both")
    translate([0, outer_w + 12, 0]) lid();
