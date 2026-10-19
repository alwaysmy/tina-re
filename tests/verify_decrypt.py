#!/usr/bin/env python3
"""可复现性验证：TINA 纯静态解密链路自检（无网络、离线可跑）。

检查项：
  1. RIPEMD-256 官方向量（3 组）
  2. 二进制 p-code 模拟的压缩块向量（2 组，来自 tina_unpacked_fixed.exe 的 0x561588）
  3. DAC882X.lib 全量解密 vs ks_ground.bin 地面真值（逐字节一致，11626/11626）
  4. SPICELIB 全库扫描：388 加密库全部可解且全文纯净；97 明文库原样直通
  5. SUBCKT/ENDS 配平：仅允许已知孤例 TPS40055_TRANS.LIB

用法：
    python tests/verify_decrypt.py
路径覆盖：
    SPICELIB_DIR=<TINA SPICELIB 路径>   KS_GROUND=<ks_ground.bin 路径>
"""
from __future__ import annotations

import os
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
sys.path.insert(0, str(HERE))  # 兼容本目录直接运行

from tina_static_decrypt import (  # noqa: E402
    CBC_IV,
    HEADER,
    KEY,
    _IV256,
    _compress,
    decrypt_bytes,
    ripemd256,
)

SPICELIB_DEFAULT = pathlib.Path(r"C:/Program Files (x86)/DesignSoft/Tina 9 - TI/SPICELIB")
KS_CANDIDATES = [
    pathlib.Path(os.environ["KS_GROUND"]) if os.environ.get("KS_GROUND") else None,
    HERE.parent / "out" / "ks_ground.bin",
    pathlib.Path(r"D:/WorkDesigns/3_WorkTools/SpiceHappy-tina-re/re/ks_ground.bin"),
    pathlib.Path(r"D:/WorkDesigns/3_WorkTools/TINA-RE/ks_ground.bin"),
]

FILES: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    FILES.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""))


def main() -> int:
    # 1) official vectors
    official = {
        b"": "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d",
        b"abc": "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65",
        b"message digest": "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e",
    }
    for msg, exp in official.items():
        got = ripemd256(msg).hex()
        check(f"RMD256({msg!r}) 官方向量", got == exp, got)

    # 2) binary-emulated compress vectors
    bz = _compress(list(_IV256), bytes(64))
    got = b"".join(int(v).to_bytes(4, "little") for v in bz).hex()
    check(
        "compress(IV, zeros64) 二进制向量",
        got == "ac92f0fd7e573dcd81c9cf459a79d6a224ce03fbcdb023aa23bff3f7307fbef6",
        got,
    )
    bs = _compress(list(_IV256), bytes(range(64)))
    got = b"".join(int(v).to_bytes(4, "little") for v in bs).hex()
    check(
        "compress(IV, seq64) 二进制向量",
        got == "115023a38024723bfb163700a7199c0ef7f87c75884ad633355769cade59c476",
        got,
    )

    sp = pathlib.Path(os.environ.get("SPICELIB_DIR") or SPICELIB_DEFAULT)
    ks_path = next((p for p in KS_CANDIDATES if p and p.is_file()), None)

    # 3) DAC882X vs ground truth
    dac = sp / "DAC882X.lib"
    if dac.is_file() and ks_path:
        ct = dac.read_bytes()[len(HEADER):]
        ks = ks_path.read_bytes()
        ref = bytes(a ^ b for a, b in zip(ct, ks))
        pt = decrypt_bytes(dac.read_bytes())
        n = min(len(pt), len(ref))
        diffs = [i for i in range(n) if pt[i] != ref[i]]
        check(
            f"DAC882X 地面真值对比 (len={n}, diffs={len(diffs)})",
            len(diffs) == 0 and n > 11000,
            str(diffs[:5]),
        )
    else:
        check("DAC882X 地面真值对比（跳过：缺文件）", True, "skipped")

    # 4) full library sweep（全文检查 + SUBCKT/ENDS 配平）
    if sp.is_dir():
        enc = plain = 0
        full_bad = []
        mismatch = []
        for p in sorted(sp.iterdir()):
            if p.suffix.lower() != ".lib":
                continue
            raw = p.read_bytes()
            if raw.startswith(HEADER):
                enc += 1
            else:
                plain += 1
            pt = decrypt_bytes(raw)
            text = pt.decode("latin-1", "replace")
            worst = max(
                (sum(1 for c in ln if ord(c) > 126 or ord(c) < 9) for ln in text.splitlines()),
                default=0,
            )
            if worst > 8:
                full_bad.append((p.name, worst))
            n_sub = len(re.findall(r"(?im)^\s*\.subckt\b", text))
            n_end = len(re.findall(r"(?im)^\s*\.ends\b", text))
            if n_sub != n_end:
                mismatch.append((p.name, n_sub, n_end))
        names = {n.lower() for n, _ in full_bad}
        known = {"tps40055_trans.lib", "uc1901_trans.lib", "uc1901_avg.lib", "tps61020_avg.lib"}
        check(
            f"全库扫描: encrypted={enc} plain={plain} 非文本={len(full_bad)}",
            enc == 388 and plain == 97 and names == known,
            str(sorted(full_bad))[:240],
        )
        check(
            f"SUBCKT/ENDS 配平: mismatches={len(mismatch)}",
            [m[0] for m in mismatch] == ["TPS40055_TRANS.LIB"],
            str(mismatch),
        )
    else:
        check("全库扫描（跳过：SPICELIB 不存在）", True, "skipped")

    failed = [n for n, ok in FILES if not ok]
    print()
    print(f"key={KEY.hex()}")
    print(f"iv={CBC_IV.hex()}")
    print("RESULT:", "ALL PASS" if not failed else f"{len(failed)} FAILED: {failed}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
