#!/usr/bin/env python3
"""TINA .TSM（OBSS 宏容器）解析器。

TSM 不是加密格式——它是一个 OBSS 容器，内部按记录存放：
    b"\\x00\\x00\\x00\\x00\\x00" + 1 字节长度(含结尾 0) + 文本 + b"\\x00"
（第一行的结尾 0 与下一条记录的 5 个 0 重叠，所以记录链是连续的。）

本工具提供：
    - 头部元数据：类型（Spice Macro / Schematics Macro …）、版本、日期、创建者、版权
    - 文本记录提取（SPICE 网表行、VHDL 描述、符号注释等）
    - 网表块识别（.SUBCKT … .ENDS）

用法：
    python tsm_parse.py <file.tsm>                  # 摘要
    python tsm_parse.py <file.tsm> --text           # 打印全部文本行
    python tsm_parse.py <file.tsm> --netlist        # 只打印 .SUBCKT…ENDS 块
    python tsm_parse.py <file.tsm> --json           # 结构化输出
    python tsm_parse.py <file.tsm> --netlist --out out.cir
    python tsm_parse.py --dir <MACROLIB 目录>       # 批量摘要

注意：TSM 的“解密”不存在——它本来就是明文容器。本工具只解析，不做解密。
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

MAGIC = b"OBSS"
SEP = b"\x00" * 5
SUBCKT_RE = re.compile(r"(?i)^\s*\.?subckt\b")
ENDS_RE = re.compile(r"(?i)^\s*\.ends\b")


def _printable(data: bytes) -> bool:
    return bool(data) and all(32 <= c < 127 for c in data)


def parse_meta(data: bytes) -> dict:
    """Tolerant header scan: first few printable NUL-terminated strings (skip the magic)."""
    head = data[4:0x400]
    strings: list[str] = []
    i = 0
    while i < len(head) and len(strings) < 12:
        j = i
        while j < len(head) and 32 <= head[j] < 127:
            j += 1
        if j - i >= 3:
            strings.append(head[i:j].decode("ascii", "replace").strip())
            i = j
        else:
            i += 1
    meta = {
        "type": strings[0] if len(strings) > 0 else None,
        "version": strings[1] if len(strings) > 1 else None,
        "date": strings[2] if len(strings) > 2 else None,
        "creator": strings[3] if len(strings) > 3 else None,
        "copyright": strings[4] if len(strings) > 4 else None,
        "strings": strings,
    }
    return meta


def extract_records(data: bytes) -> list[dict]:
    """Extract text records: 5 NULs + len(including NUL) + text + NUL."""
    out: list[dict] = []
    i, n = 0, len(data)
    while i < n - 7:
        if data[i:i + 5] == SEP:
            j = i + 5
            length = data[j]
            if 2 <= length <= 250 and j + length < n and data[j + length] == 0:
                body = data[j + 1:j + length]
                if _printable(body):
                    out.append({
                        "offset": i,
                        "end": j + length,
                        "text": body.decode("ascii"),
                    })
                    i = j + length  # the terminator is the next separator's first NUL
                    continue
        i += 1
    return out


def group_blocks(records: list[dict]) -> list[list[dict]]:
    blocks: list[list[dict]] = []
    cur: list[dict] = []
    prev_end = None
    for r in records:
        if cur and r["offset"] == prev_end:
            cur.append(r)
        else:
            if cur:
                blocks.append(cur)
            cur = [r]
        prev_end = r["end"]
    if cur:
        blocks.append(cur)
    return blocks


def find_netlist(records: list[dict]) -> list[dict]:
    """Find .SUBCKT .. .ENDS in the flat record list (block gaps are irrelevant)."""
    start = next((i for i, r in enumerate(records) if SUBCKT_RE.match(r["text"])), None)
    if start is None:
        return []
    end = next((i for i in range(start, len(records)) if ENDS_RE.match(records[i]["text"])), len(records) - 1)
    return records[start:end + 1]


def summarize(path: Path) -> dict:
    data = path.read_bytes()
    if not data.startswith(MAGIC):
        return {"file": path.name, "error": "not an OBSS container"}
    meta = parse_meta(data)
    records = extract_records(data)
    blocks = group_blocks(records)
    netlist = find_netlist(records)
    return {
        "file": path.name,
        "size": len(data),
        **{k: meta[k] for k in ("type", "version", "date", "creator", "copyright")},
        "records": len(records),
        "blocks": [{"offset": b[0]["offset"], "lines": len(b)} for b in blocks],
        "netlist_lines": len(netlist),
        "netlist_head": netlist[0]["text"][:70] if netlist else None,
        "netlist_tail": netlist[-1]["text"][:70] if netlist else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse TINA .TSM (OBSS) containers")
    ap.add_argument("file", nargs="?", type=Path)
    ap.add_argument("--dir", type=Path, help="summarize every *.tsm in this directory")
    ap.add_argument("--text", action="store_true", help="print all text records")
    ap.add_argument("--netlist", action="store_true", help="print the .SUBCKT..ENDS block")
    ap.add_argument("--json", action="store_true", help="structured output")
    ap.add_argument("--out", type=Path, help="write the selected text to a file")
    args = ap.parse_args()

    if args.dir:
        files = sorted({p.resolve() for p in list(args.dir.glob("*.tsm")) + list(args.dir.glob("*.TSM"))})
        for p in files:
            s = summarize(p)
            if "error" in s:
                print(f"{p.name:36s} {s['error']}")
                continue
            net = f"netlist={s['netlist_lines']:3d}" if s["netlist_lines"] else "netlist=  -"
            print(f"{p.name:36s} {s['size']:7d} B  {str(s['type'])[:20]:20s} {net}  blocks={len(s['blocks'])}")
        return 0

    if not args.file:
        ap.print_help()
        return 2

    data = args.file.read_bytes()
    if not data.startswith(MAGIC):
        raise SystemExit(f"{args.file}: not an OBSS/TSM container")
    meta = parse_meta(data)
    records = extract_records(data)
    blocks = group_blocks(records)
    netlist = find_netlist(records)

    if args.json:
        payload = {
            "file": args.file.name,
            "size": len(data),
            **{k: meta[k] for k in ("type", "version", "date", "creator", "copyright")},
            "blocks": [
                {"offset": b[0]["offset"], "lines": [r["text"] for r in b]} for b in blocks
            ],
            "netlist": [r["text"] for r in netlist],
        }
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        if args.out:
            args.out.write_text(text, encoding="utf-8")
            print(f"written -> {args.out}")
        else:
            print(text)
        return 0

    if args.netlist or args.text:
        if args.netlist:
            lines = [r["text"] for r in netlist]
        else:
            lines = []
            for idx, b in enumerate(blocks):
                if idx:
                    lines.append("")
                lines.extend(r["text"] for r in b)
        text = "\n".join(lines) + ("\n" if lines else "")
        if args.out:
            args.out.write_text(text, encoding="utf-8")
            print(f"written -> {args.out} ({len(lines)} lines)")
        else:
            print(text, end="")
        return 0

    print(f"file      : {args.file.name} ({len(data)} bytes)")
    print(f"type      : {meta['type']}")
    print(f"version   : {meta['version']}")
    print(f"date      : {meta['date']}")
    print(f"creator   : {meta['creator']}")
    print(f"copyright : {meta['copyright']}")
    print(f"records   : {len(records)}  blocks: {len(blocks)}")
    for i, b in enumerate(blocks):
        print(f"  block {i}: offset {b[0]['offset']}, {len(b)} lines")
    if netlist:
        print(f"netlist   : {netlist[0]['text'][:60]} ... {netlist[-1]['text'][:20]} ({len(netlist)} lines)")
    else:
        print("netlist   : (none — schematic/symbol macro)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
