"""Survey the decrypted TINA SPICELIB: origins, syntax, variants, dependencies.

Usage:
    python scripts/survey_spicelib.py [--dir <decrypted-tina>]

Answers: are the bundled SMPS models standard PSpice netlists, TINA-targeted
recompiles, or TINA-proprietary models? Prints header statistics, syntax-token
coverage, proprietary-syntax files, X-instance dependency analysis, and files
whose decrypted text is damaged.
"""
from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

DEFAULT_DIR = Path(r"D:\WorkDesigns\3_WorkTools\SpiceHappy-tina-re\decrypted-tina")

SIM = re.compile(r"(?im)^\s*\*\s*Simulator\s*:\s*(.+)$")
TYPE = re.compile(r"(?im)^\s*\*\s*Model Type\s*:\s*(.+)$")
SUBCKT = re.compile(r"(?im)^\s*\.SUBCKT\s+([^\s]+)")
YDEV = re.compile(r"(?im)^\s*Y\S+\s+")
TINA_MODEL = re.compile(r"(?im)^\s*\.MODEL\s+\S+\s+(AMPLI|AMPLI_GR|COMP|COMP_GR)\b")


def logical_lines(text: str):
    buf = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("*"):
            continue
        if line.startswith("+"):
            buf += " " + line[1:].strip()
            continue
        if buf:
            yield buf
        buf = line
    if buf:
        yield buf


def x_subckt(line: str) -> str | None:
    tokens = line.split()
    if len(tokens) < 3:
        return None
    for i, tok in enumerate(tokens):
        if tok.upper() == "PARAMS:":
            return tokens[i - 1] if i else None
    for tok in reversed(tokens):
        if "=" not in tok and not tok.startswith("{") and not tok.startswith("}"):
            return tok
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path, default=DEFAULT_DIR)
    args = ap.parse_args()

    files = sorted({p.resolve() for p in args.dir.glob("*.[lL][iI][bB]")})
    texts = {f: f.read_text("latin-1", "replace") for f in files}
    print(f"unique libraries: {len(files)}")

    sims: Counter[str] = Counter()
    types: Counter[str] = Counter()
    for t in texts.values():
        head = "\n".join(t.splitlines()[:60])
        m = SIM.search(head)
        if m:
            v = m.group(1).strip()
            sims["PSPICE" if "pspice" in v.lower() else ("TINA" if "tina" in v.lower() else v)] += 1
        else:
            sims["<none>"] += 1
        m = TYPE.search(head)
        types[m.group(1).strip().upper() if m else "<none>"] += 1

    print("Simulator header:", dict(sims))
    print("Model Type header:", dict(types.most_common()))

    tokens = [".SUBCKT", ".MODEL", ".PARAM", "VALUE", "TABLE", "POLY(", "IF ("]
    print("\nsyntax tokens:")
    for tok in tokens:
        n = sum(1 for t in texts.values() if tok.lower() in t.lower())
        print(f"  {n:4d} / {len(files)}  {tok}")

    y_files = [f.name for f, t in texts.items() if YDEV.search(t)]
    m_files = [f.name for f, t in texts.items() if TINA_MODEL.search(t)]
    print(f"\nTINA-proprietary Y devices ({len(y_files)}): {y_files}")
    print(f"TINA AMPLI/COMP model types ({len(m_files)}): {m_files}")

    local = {f: {m.group(1).upper() for m in (SUBCKT.match(x) for x in logical_lines(t)) if m}
             for f, t in texts.items()}
    all_defs = set().union(*local.values()) if local else set()
    cross = Counter()
    missing = Counter()
    for f, t in texts.items():
        for line in logical_lines(t):
            if line[:1] not in ("X", "x"):
                continue
            name = x_subckt(line)
            if not name or not re.match(r"^[A-Z_][A-Z0-9_.$-]*$", name.upper()):
                continue
            name = name.upper()
            if name in local[f]:
                continue
            (cross if name in all_defs else missing)[name] += 1
    print(f"\ncross-library subckt deps: {len(cross)}")
    for k, v in cross.most_common(12):
        print(f"  {k:<22} {v}")
    print(f"subckts defined nowhere (TINA built-ins / missing): {len(missing)}")
    for k, v in missing.most_common(12):
        print(f"  {k:<22} {v}")

    damaged = []
    for f, t in texts.items():
        worst = max((sum(1 for c in ln if ord(c) > 126 or ord(c) < 9) for ln in t.splitlines()), default=0)
        if worst > 8:
            damaged.append((worst, f.name))
    damaged.sort(reverse=True)
    print(f"\ndamaged text (line with >8 non-ASCII bytes): {len(damaged)}")
    for n, name in damaged:
        print(f"  {n:4d}  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
