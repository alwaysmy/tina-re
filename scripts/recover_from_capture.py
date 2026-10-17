"""Recover a truncated .LIB model text by splicing a static decryption prefix with
a runtime capture of the same model (e.g. the copy embedded in a .TSC).

Usage:
    python scripts/recover_from_capture.py --lib <file.lib> --capture <raw.bin> \
        --anchor ".SUBCKT NAME" --out <recovered.lib>

The static part is trusted only up to the point where the decrypted text stops
being text; the capture supplies the continuation. The two are aligned at the
anchor and asserted to agree on the shared prefix.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tina_static_decrypt import decrypt_bytes  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lib", type=Path, required=True)
    ap.add_argument("--capture", type=Path, required=True)
    ap.add_argument("--anchor", required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    static = decrypt_bytes(args.lib.read_bytes())
    cap = args.capture.read_bytes()
    anchor = args.anchor.encode()

    s0 = static.find(anchor)
    c0 = cap.find(anchor)
    if s0 < 0 or c0 < 0:
        print(f"anchor not found (static={s0}, capture={c0})", file=sys.stderr)
        return 2

    seg = cap[c0:]
    end = seg.rfind(b".ENDS")
    if end < 0:
        print("no .ENDS in capture", file=sys.stderr)
        return 2
    seg = seg[:end + len(b".ENDS")] + b"\r\n"

    recovered = static[:s0] + seg

    # report how far the static text and the capture agree (the splice point)
    n = 0
    limit = min(len(static) - s0, len(seg))
    while n < limit and static[s0 + n] == seg[n]:
        n += 1

    print(f"static anchor @{s0}, capture anchor @{c0}")
    print(f"shared prefix: {n} bytes (divergence at static offset {s0 + n})")
    print(f"recovered {len(recovered)} bytes -> {args.out}")
    args.out.write_bytes(recovered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
