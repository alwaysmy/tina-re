#!/usr/bin/env python3
"""修复 tina_unpacked_static.exe 的节表字段互换 bug（rebuild_pe.py 产生）。

背景：SpiceHappy-tina-re/re/rebuild_pe.py 第 38 行把两个字段写反：
    struct.pack_into('<II', data, sec_off + idx*40 + 16, va, rawsz)
PE 规范： +16 = SizeOfRawData, +20 = PointerToRawData。
脚本把 va 写进了 +16、把对齐后的 VirtualSize 写进了 +20 → 两字段整体互换，
导致 PE 加载器（Ghidra/IDA）把数据放错位置（代码区错位，Ghidra 只识别 8456 个函数）。
修正后：PointerToRawData == VirtualAddress（真正的 raw=virtual 平铺），
Ghidra 识别 18514 个函数，代码区字节与文件偏移一致。

用法：
    python fix-pe.py <原始镜像> <输出镜像>
默认（无参数）：
    输入  D:\\WorkDesigns\\3_WorkTools\\SpiceHappy-tina-re\\re\\tina_unpacked_static.exe
    输出  <本脚本目录>/../targets/tina_unpacked_fixed.exe

建议上游修复：把 rebuild_pe.py 的字段互换改回来（并重新生成镜像），
或在同处加注释说明 +16/+20 的正确含义。
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

DEFAULT_SRC = Path(r"D:\WorkDesigns\3_WorkTools\SpiceHappy-tina-re\re\tina_unpacked_static.exe")
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "targets" / "tina_unpacked_fixed.exe"


def fix_image(src: Path, out: Path) -> None:
    data = bytearray(src.read_bytes())
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise SystemExit("not a PE file")
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec_off = e_lfanew + 4 + 20 + opt_size
    print(f"e_lfanew=0x{e_lfanew:X} sections={nsec} section_table=0x{sec_off:X}")

    for i in range(nsec):
        p = sec_off + i * 40
        size_raw, ptr_raw = struct.unpack_from("<II", data, p + 16)
        # 现状（bug 产物）: +16 槽存的是 VA，+20 槽存的是对齐后的 VirtualSize
        va, rawsz = size_raw, ptr_raw
        # 修正: +16 = SizeOfRawData(VirtualSize 对齐), +20 = PointerToRawData(VA)
        struct.pack_into("<II", data, p + 16, rawsz, va)
        name = bytes(data[p : p + 8]).split(b"\x00")[0].decode(errors="replace")
        print(f"  [{i}] {name:8} VA=0x{va:X} SizeOfRawData=0x{rawsz:X} PointerToRawData=0x{va:X}")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(bytes(data))
    print(f"[out] {out} ({len(data):,} B)")


def main() -> None:
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SRC
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUT
    fix_image(src, out)


if __name__ == "__main__":
    main()
