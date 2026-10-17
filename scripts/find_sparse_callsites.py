"""Find every call site that goes through the runtime sparse_dll pointer table.

The unpacked image keeps a resolved function-pointer table for sparse_dll.dll at
RVA 0x1BDAF20 (4-byte entries). Code reaches it with
`call dword ptr [0x1FDAF20]` (FF 15) or `jmp dword ptr [...]` (FF 25); the
thunks sit in the jump island at RVA 0x510620-0x510670.

Slot labels are derived from sparse_dll.dll's own export table, so the mapping
is never guessed.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pefile

TINA_DIR = Path(r"C:\Program Files (x86)\DesignSoft\Tina 9 - TI")
DUMP = Path(r"D:\WorkDesigns\3_WorkTools\TINA-RE\targets\tina_unpacked_fixed.exe")
IMAGE_BASE = 0x400000
TABLE_RVA = 0x1BDAF20
SLOT_COUNT = 12


def export_map() -> dict[int, str]:
    pe = pefile.PE(str(TINA_DIR / "sparse_dll.dll"))
    return {
        sym.address: sym.name.decode()
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols
        if sym.name
    }


def main() -> int:
    data = DUMP.read_bytes()
    exports = export_map()

    # dump-time module base: the candidate (value - export RVA) that matches the
    # most table slots.
    from collections import Counter

    votes: Counter[int] = Counter()
    for i in range(SLOT_COUNT):
        val = struct.unpack_from("<I", data, TABLE_RVA + i * 4)[0]
        if val == 0:
            continue
        for rva in exports:
            cand = val - rva
            if cand & 0xFFFF == 0:  # module bases are 64K-aligned
                votes[cand] += 1
    dll_base = votes.most_common(1)[0][0]
    print(f"dump-time sparse_dll base = 0x{dll_base:08x}")

    print("\ntable entries:")
    slots: list[tuple[int, str, int]] = []
    for i in range(SLOT_COUNT):
        off = TABLE_RVA + i * 4
        val = struct.unpack_from("<I", data, off)[0]
        name = exports.get(val - dll_base, f"0x{val:08x}")
        slots.append((off, name, val))
        print(f"  [{i:2d}] RVA 0x{off:08x} -> 0x{val:08x}  {name}")

    print("\nthunks and call sites:")
    for off, name, _ in slots:
        slot_va = IMAGE_BASE + off
        found = []
        for opcode, kind in ((b"\xff\x15", "call"), (b"\xff\x25", "jmp")):
            pat = opcode + struct.pack("<I", slot_va)
            pos = data.find(pat)
            while pos >= 0:
                found.append((pos + IMAGE_BASE, kind))
                pos = data.find(pat, pos + 1)
        for va, kind in found:
            print(f"  {name:<16} {kind} [0x{slot_va:08x}] at VA 0x{va:08x} (RVA 0x{va - IMAGE_BASE:06x})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
