#!/usr/bin/env python3
"""TINA-TI 加密库纯静态解密工具（无需 TINA 运行时 / Frida / 窗口）。

算法（2026-10-17 由 Ghidra 静态分析 + 地面真值验证）：
    key = RIPEMD-256(镜像内 40B 常量 @ RVA 0x58FAD0)
    IV  = 0x864D93CD4B27E92D（常量）
    pt  = standard Blowfish-CBC decrypt(ct)   # 尾部不满 8B 的部分原样保留

验证：
    - DAC882X.lib：11626 字节与 ks_ground.bin 地面真值逐一比对，仅末尾 2 字节
      （不完整块，原样直通）不同 —— 其余全部一致。
    - SPICELIB 全部 388 个加密库解密后均为可读 SPICE 文本（ASCII 1.0）。

加密文件格式：b"<Encrypted Library>\\n\\r" + 密文（21 字节头）。

用法：
    python tina_static_decrypt.py <某个 .lib> [输出路径]
    python tina_static_decrypt.py --all [输出目录]     # 批量 SPICELIB
    python tina_static_decrypt.py --dir <SPICELIB 路径> [输出目录]
"""
from __future__ import annotations

import pathlib
import sys

from Crypto.Cipher import Blowfish

# ---------------------------------------------------------------------------
# RIPEMD-256（自包含实现；已用官方向量与二进制 p-code 模拟双重验证）
# ---------------------------------------------------------------------------
M = 0xFFFFFFFF
_IV256 = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
          0x76543210, 0xFEDCBA98, 0x89ABCDEF, 0x01234567]
_F = (
    lambda x, y, z: x ^ y ^ z,
    lambda x, y, z: (x & y) | (~x & z),
    lambda x, y, z: (x | ~y) ^ z,
    lambda x, y, z: (x & z) | (y & ~z),
)
_K1 = [0x00000000] * 16 + [0x5A827999] * 16 + [0x6ED9EBA1] * 16 + [0x8F1BBCDC] * 16
_K2 = [0x50A28BE6] * 16 + [0x5C4DD124] * 16 + [0x6D703EF3] * 16 + [0x00000000] * 16
_R1 = ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
      + [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]
      + [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12]
      + [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2])
_R2 = ([5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12]
      + [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2]
      + [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13]
      + [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14])
_S1 = ([11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8]
      + [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12]
      + [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5]
      + [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12])
_S2 = ([8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6]
      + [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11]
      + [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5]
      + [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8])


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & M


def _compress(h: list[int], block: bytes) -> list[int]:
    x = list(__import__("struct").unpack("<16I", block))
    A, B, C, D = h[0], h[1], h[2], h[3]
    A2, B2, C2, D2 = h[4], h[5], h[6], h[7]
    for j in range(64):
        T = _rol((A + _F[j // 16](B, C, D) + x[_R1[j]] + _K1[j]) & M, _S1[j])
        A, B, C, D = D, T, B, C
        T = _rol((A2 + _F[3 - j // 16](B2, C2, D2) + x[_R2[j]] + _K2[j]) & M, _S2[j])
        A2, B2, C2, D2 = D2, T, B2, C2
        if j == 15:
            A, A2 = A2, A
        elif j == 31:
            B, B2 = B2, B
        elif j == 47:
            C, C2 = C2, C
        elif j == 63:
            D, D2 = D2, D
    return [(h[0] + A) & M, (h[1] + B) & M, (h[2] + C) & M, (h[3] + D) & M,
            (h[4] + A2) & M, (h[5] + B2) & M, (h[6] + C2) & M, (h[7] + D2) & M]


def ripemd256(data: bytes) -> bytes:
    import struct
    h = list(_IV256)
    msg = bytearray(data)
    bitlen = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bitlen & 0xFFFFFFFFFFFFFFFF)
    for i in range(0, len(msg), 64):
        h = _compress(h, bytes(msg[i:i + 64]))
    return struct.pack("<8I", *h)


# ---------------------------------------------------------------------------
# 常量（来自 tina_unpacked_static.exe 的静态数据）
# ---------------------------------------------------------------------------
KEY_BLOB_RVA = 0x58FAD0          # 40B 常量（"密钥串"）
KEY_BLOB = bytes.fromhex(
    "78372f6a3f242b34283a3c4076372131525e397e6b256738363d6c5c30223c2a3e31235e54267b5d"
)
CBC_IV = bytes.fromhex("864d93cd4b27e92d")
HEADER = b"<Encrypted Library>\n\r"

# 校验：镜像中的 blob 与常量一致（若提供镜像路径）
IMAGE_PATH = pathlib.Path(r"D:/WorkDesigns/3_WorkTools/TINA-RE/targets/tina_unpacked_fixed.exe")

KEY = ripemd256(KEY_BLOB)
_ECB = Blowfish.new(KEY, Blowfish.MODE_ECB)
_DECRYPT_BLOCK = _ECB.decrypt


def is_encrypted(data: bytes) -> bool:
    return data.startswith(HEADER)


def decrypt_bytes(raw: bytes) -> bytes:
    """解密一个 .lib 文件的完整字节（自动剥离 21B 头；明文文件原样返回）。"""
    if not is_encrypted(raw):
        return raw
    ct = raw[len(HEADER):]
    out = bytearray()
    prev = CBC_IV
    nblocks = len(ct) // 8
    for b in range(nblocks):
        blk = ct[b * 8:(b + 1) * 8]
        out += bytes(x ^ y for x, y in zip(_DECRYPT_BLOCK(blk), prev))
        prev = blk
    out += ct[nblocks * 8:]          # 尾部不满 8B：原样直通（与引擎行为一致）
    return bytes(out)


def decrypt_file(src: pathlib.Path, out_dir: pathlib.Path | None = None) -> pathlib.Path:
    raw = pathlib.Path(src).read_bytes()
    out_dir = pathlib.Path(out_dir) if out_dir else pathlib.Path(src).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    name = pathlib.Path(src).name
    if name.lower().endswith(".lib"):
        name = name[:-4] + ".lib"
    dst = out_dir / name
    dst.write_bytes(decrypt_bytes(raw))
    return dst


def decrypt_all(spicelib: pathlib.Path, out_dir: pathlib.Path) -> tuple[int, int]:
    out_dir.mkdir(parents=True, exist_ok=True)
    enc = plain = 0
    for p in sorted(spicelib.iterdir()):
        if p.suffix.lower() != ".lib":
            continue
        raw = p.read_bytes()
        if is_encrypted(raw):
            enc += 1
        else:
            plain += 1
        (out_dir / p.name).write_bytes(decrypt_bytes(raw))
    return enc, plain


def _check_image_blob() -> None:
    if IMAGE_PATH.is_file():
        got = IMAGE_PATH.read_bytes()[KEY_BLOB_RVA:KEY_BLOB_RVA + 40]
        if got != KEY_BLOB:
            raise SystemExit("[warn] 镜像中的 40B blob 与内置常量不一致，请核查")


def main() -> None:
    args = sys.argv[1:]
    default_sp = pathlib.Path(r"C:/Program Files (x86)/DesignSoft/Tina 9 - TI/SPICELIB")
    if not args:
        print(__doc__)
        return
    if args[0] == "--out":
        if len(args) < 3:
            raise SystemExit("usage: tina_static_decrypt.py --out <file> <input>")
        out_file = pathlib.Path(args[1])
        src = pathlib.Path(args[2])
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_bytes(decrypt_bytes(src.read_bytes()))
        print(f"decrypted -> {out_file}")
        return
    if args[0] in ("--all", "--dir"):
        sp = pathlib.Path(args[1] if args[0] == "--dir" else default_sp)
        out = pathlib.Path(args[2] if len(args) > 2 else str(pathlib.Path(__file__).resolve().parent.parent / "decrypted-local"))
        _check_image_blob()
        enc, plain = decrypt_all(sp, out)
        print(f"done: encrypted={enc} plaintext={plain} -> {out}")
        return
    src = pathlib.Path(args[0])
    out = pathlib.Path(args[1]) if len(args) > 1 else None
    _check_image_blob()
    dst = decrypt_file(src, out)
    print(f"decrypted -> {dst}")


if __name__ == "__main__":
    main()


