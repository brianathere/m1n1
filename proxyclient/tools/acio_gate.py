#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# acio_gate.py — ACIO error-handler gate exploration + EL1/EL2 comparison probe
#
# Purpose: characterise the per-port EH gate unlocks for ACIO/apciec/acio-cpu
# from m1n1 EL2 proxy, comparing direct EL2 writes against EL1 stub writes (via
# el1_call). Captures SErrors via exc_guard so we never lose the proxy session,
# and produces a structured report mapping EH offset → sub-aperture readability.
#
# Background: project_eh_per_port_mapping_DEFINITIVE_2026-04-26.md established
# the empirical mapping; today's Linux EL1 test rebooted the box, so we need a
# safer harness to figure out whether the failure was EL1-context or
# Linux-mapping. From m1n1 EL2 proxy, el1_call lets us run the same MMIO write
# from EL1 with the same memory attributes m1n1 uses for EL2 — that isolates the
# EL-context axis.
#
# Usage examples (from proxyclient/ dir, M1N1DEVICE=/dev/m1n1):
#     python3 tools/acio_gate.py baseline
#     python3 tools/acio_gate.py el2 0x340 --target 0xb20201000
#     python3 tools/acio_gate.py el1 0x340 --target 0xb20201000
#     python3 tools/acio_gate.py compare --port 1
#     python3 tools/acio_gate.py table

import sys, os, argparse, struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from m1n1.setup import *

EH_BASE   = 0x28e080000
PMGR1_BASE = 0x292280000

# Empirical EH offset → sub-aperture map (project_eh_per_port_mapping_DEFINITIVE)
# (offset, name, sub-aperture_pa or None if unknown, port)
GATES = [
    (0x240, "port0-apciec0",     None,         0),  # state-only seen
    (0x250, "port0-sub-pmgr",    0x700000000,  0),  # hypothesised
    (0x2f8, "port2-sub-pmgr",    0xf00000000,  2),  # confirmed via trace 60525->60527
    (0x338, "port1-acio-prep1",  None,         1),  # sequential pre-acio-cpu1
    (0x340, "port1-apciec1",     0xb20201000,  1),  # confirmed via 72359->72361
    (0x350, "port1-sub-pmgr",    0xb00000000,  1),  # confirmed via 63885->64297
    (0x388, "port1-acio-prep2",  None,         1),
    (0x390, "port1-acio-cpu1",   0xb01100000,  1),  # confirmed via 191373->191697
]

UNLOCK_SEQ_OPEN = 0xf
UNLOCK_SEQ_SEAL = 0x1000000f
UNLOCK_SEQ_RELOCK = 0x3f0


def guarded_read32(p, addr):
    """Read32 with SError guard; returns (value, serror_count)."""
    p.set_exc_guard(GUARD.MARK | GUARD.SILENT)
    pre_count = p.get_exc_count()
    try:
        v = p.read32(addr)
    except Exception as e:
        return None, p.get_exc_count() - pre_count
    return v, p.get_exc_count() - pre_count


def baseline(p):
    """Print the cold/current state of all known EH/PMGR1 sites."""
    print(f"=== EH baseline (base 0x{EH_BASE:x}) ===")
    for off, name, target, port in GATES:
        v, se = guarded_read32(p, EH_BASE + off)
        v_str = f"0x{v:x}" if v is not None else "SError"
        tgt = f" → 0x{target:x}" if target else ""
        print(f"  EH+0x{off:03x} = {v_str:>12s}   ({name}){tgt}")
    print()
    print(f"=== PMGR1 baseline (base 0x{PMGR1_BASE:x}) ===")
    for off in (0x90, 0x98, 0xd8):
        v, se = guarded_read32(p, PMGR1_BASE + off)
        v_str = f"0x{v:x}" if v is not None else "SError"
        print(f"  PMGR1+0x{off:03x} = {v_str:>12s}")


def unlock_eh_gate_el2(p, off):
    """Perform the canonical R/W/W/R gate unlock dance from EL2."""
    pre, _ = guarded_read32(p, EH_BASE + off)
    p.set_exc_guard(GUARD.SKIP | GUARD.SILENT)
    p.write32(EH_BASE + off, UNLOCK_SEQ_OPEN)
    mid, _ = guarded_read32(p, EH_BASE + off)
    p.set_exc_guard(GUARD.SKIP | GUARD.SILENT)
    p.write32(EH_BASE + off, UNLOCK_SEQ_SEAL)
    post, _ = guarded_read32(p, EH_BASE + off)
    return pre, mid, post


def cmd_el2(p, args):
    off = args.offset
    print(f"[EL2] unlocking EH+0x{off:x}")
    pre, mid, post = unlock_eh_gate_el2(p, off)
    print(f"      pre  = {fmt(pre)}")
    print(f"      mid  = {fmt(mid)}  (after W=0xf)")
    print(f"      post = {fmt(post)} (after W=0x1000000f)")
    if args.target is not None:
        v, se = guarded_read32(p, args.target)
        print(f"[EL2] target read 0x{args.target:x} = {fmt(v)} (serror_count delta={se})")


def asm_el1_unlock_stub(buf_va, off, target):
    """
    Build an EL1 stub that performs the same R/W/W/R sequence and target read.
    Returns (asm_text, expected_struct_layout).

    Stub layout:
      [arg0=eh_base]
      ldr w1, [x0, #off]            // pre
      mov w2, #0xf
      str w2, [x0, #off]
      ldr w3, [x0, #off]            // mid
      ldr w4, =0x1000000f
      str w4, [x0, #off]
      ldr w5, [x0, #off]            // post
      // optional target read
      ldr x6, =target_pa
      ldr w7, [x6]
      // pack: store 5 u32s starting at result_addr (x8)
      mov x8, x1                    // we'll repurpose: caller passes result buf via x1
      str w1, [x8, #0]
      str w3, [x8, #4]
      str w5, [x8, #8]
      str w7, [x8, #12]
      mov x0, xzr
      ret
    """
    # Real asm:
    txt = f"""
        // x0 = EH_BASE, x1 = result_buf_va, x2 = target_pa (0 if none)
        ldr w3, [x0, #{off:#x}]
        str w3, [x1, #0]
        mov w4, #0xf
        str w4, [x0, #{off:#x}]
        dsb sy
        ldr w5, [x0, #{off:#x}]
        str w5, [x1, #4]
        movz w6, #{UNLOCK_SEQ_SEAL & 0xffff}
        movk w6, #{(UNLOCK_SEQ_SEAL >> 16) & 0xffff}, lsl #16
        str w6, [x0, #{off:#x}]
        dsb sy
        ldr w7, [x0, #{off:#x}]
        str w7, [x1, #8]
        cbz x2, 1f
        ldr w8, [x2]
        str w8, [x1, #12]
        b 2f
    1:
        mov w8, #-1
        str w8, [x1, #12]
    2:
        mov x0, xzr
        ret
    """
    return txt


def cmd_el1(p, args):
    """Execute the unlock + readback from EL1 via el1_call.

    NOTE: this requires the proxy session to have stayed in m1n1 EL2 mode
    (i.e. naked m1n1 in ESP, not chained to Linux). If the Linux test reboot
    earlier was caused by a SoC-level bus reset rather than EL1 panic, this
    test will *also* reboot the box — but we'll learn whether m1n1's EL1
    context (no Linux yet, m1n1's MAIR) hits the same wall as Linux's.
    """
    from m1n1.asm import ARMAsm

    off = args.offset
    target = args.target if args.target is not None else 0
    print(f"[EL1] preparing stub for EH+0x{off:x}, target=0x{target:x}")

    # Allocate page-aligned buffers
    code_buf = p.memalign(0x4000, 0x4000)
    res_buf  = p.memalign(0x40, 0x40)
    asm_text = asm_el1_unlock_stub(code_buf, off, target)
    a = ARMAsm(asm_text, code_buf)
    iface.writemem(code_buf, a.data)
    p.dc_cvau(code_buf, len(a.data))
    p.ic_ivau(code_buf, len(a.data))

    # Zero result buf
    iface.writemem(res_buf, b"\xff" * 16)
    p.dc_civac(res_buf, 16)

    print(f"[EL1] el1_call code=0x{code_buf:x} res=0x{res_buf:x}")
    rc = p.el1_call(code_buf, EH_BASE, res_buf, target, 0)
    print(f"[EL1] el1_call returned 0x{rc:x}")

    p.dc_civac(res_buf, 16)
    raw = iface.readmem(res_buf, 16)
    pre, mid, post, tgt = struct.unpack("<IIII", raw)
    print(f"[EL1] EH+0x{off:x} pre  = {fmt(pre)}")
    print(f"[EL1] EH+0x{off:x} mid  = {fmt(mid)}  (after W=0xf)")
    print(f"[EL1] EH+0x{off:x} post = {fmt(post)} (after W=0x1000000f)")
    if target:
        print(f"[EL1] target 0x{target:x} = {fmt(tgt)}")


def cmd_compare(p, args):
    """Run BOTH EL2 and EL1 unlock sequences for the gates of a port and report differences.

    Caller chooses port; we iterate the GATES table for that port. EL2 first
    (cheap to recover via reseal), EL1 second (each may cost a power-cycle if
    the bus reacts adversely; recover by re-running with --skip-after).
    """
    port = args.port
    gates = [g for g in GATES if g[3] == port and g[2] is not None]
    if not gates:
        print(f"No known gates with target sub-aperture for port {port}")
        return
    print(f"=== Port {port} gate comparison ===")
    print()
    for off, name, target, _ in gates:
        if args.skip_after and off < args.skip_after:
            continue
        print(f"--- {name} (EH+0x{off:x} → 0x{target:x}) ---")
        try:
            print("  [EL2 path]")
            args.offset = off
            args.target = target
            cmd_el2(p, args)
        except Exception as e:
            print(f"  EL2 path raised: {e}")
        if not args.el2_only:
            try:
                print("  [EL1 path]")
                cmd_el1(p, args)
            except Exception as e:
                print(f"  EL1 path raised: {e}")
                print(f"  *** RESUME WITH: --skip-after 0x{off+1:x} ***")
                return
        print()


def cmd_table(args):
    """Just print the static gate→sub-aperture mapping (no MMIO)."""
    print(f"{'EH off':>8s}  {'name':22s}  {'target':>14s}  port")
    print("-" * 60)
    for off, name, target, port in GATES:
        tgt = f"0x{target:x}" if target else "(unknown)"
        print(f"  0x{off:03x}    {name:22s}  {tgt:>14s}  {port}")


def fmt(v):
    if v is None:
        return "SError"
    return f"0x{v:08x}"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("baseline", help="Read all EH/PMGR1 sites; no writes")
    sub.add_parser("table", help="Print static gate map")
    p_el2 = sub.add_parser("el2", help="Unlock one gate from EL2")
    p_el2.add_argument("offset", type=lambda s: int(s, 0), help="EH offset (e.g. 0x340)")
    p_el2.add_argument("--target", type=lambda s: int(s, 0), default=None,
                       help="PA to read after unlock (e.g. 0xb20201000)")
    p_el1 = sub.add_parser("el1", help="Unlock one gate via el1_call stub")
    p_el1.add_argument("offset", type=lambda s: int(s, 0))
    p_el1.add_argument("--target", type=lambda s: int(s, 0), default=None)
    p_cmp = sub.add_parser("compare", help="EL2-vs-EL1 sweep for one port")
    p_cmp.add_argument("--port", type=int, required=True)
    p_cmp.add_argument("--el2-only", action="store_true",
                       help="Skip EL1 path (safer)")
    p_cmp.add_argument("--skip-after", type=lambda s: int(s, 0), default=None,
                       help="Resume sweep AFTER this offset (recovery)")
    args = ap.parse_args()

    if args.cmd == "table":
        return cmd_table(args)

    if args.cmd == "baseline":
        return baseline(p)
    if args.cmd == "el2":
        return cmd_el2(p, args)
    if args.cmd == "el1":
        return cmd_el1(p, args)
    if args.cmd == "compare":
        return cmd_compare(p, args)


if __name__ == "__main__":
    main()
