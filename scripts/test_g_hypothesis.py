#!/usr/bin/env python3
"""对撞实验：G(x) 是否 = 标准 Blowfish 的 E/D(x)，密钥取自镜像中的两个 40B blob。

oracle 点来自 SpiceHappy-tina-re BATTLELOG 第三十二轮（oracle_tail.py 实测）：
    G(0⁸)             = 7455d14e72cf5821
    G(ff⁸)            = 3979fa134745dbe6
    G(0102030405060708) = 37848bb38b650bb4

假设组合：{K1=0x98FAD0(40B), K2=0x56BD5A(40B)} × {E, D} × {key 原样, dword 字节序交换, 字节反转}
输出比较：hex 顺序 + 反转顺序。
"""
from __future__ import annotations

import pathlib

from Crypto.Cipher import Blowfish

IMG = pathlib.Path(r"D:\WorkDesigns\3_WorkTools\TINA-RE\targets\tina_unpacked_fixed.exe").read_bytes()


def blob(va: int, n: int) -> bytes:
    off = va - 0x400000
    return IMG[off : off + n]


ORACLE = {
    bytes(8): "7455d14e72cf5821",
    b"\xff" * 8: "3979fa134745dbe6",
    bytes(range(1, 9)): "37848bb38b650bb4",
}


def bswap_dwords(k: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(k) - 3, 4):
        out += k[i : i + 4][::-1]
    return bytes(out)


def try_keys(name: str, key: bytes) -> int:
    hits = 0
    variants = {
        "raw": key,
        "rev-bytes": key[::-1],
        "bswap-dwords": bswap_dwords(key),
    }
    for vname, k in variants.items():
        if len(k) < 4:
            continue
        cipher = Blowfish.new(k, Blowfish.MODE_ECB)
        for op, fn in (("E", cipher.encrypt), ("D", cipher.decrypt)):
            for x, expect in ORACLE.items():
                y = fn(x)
                got = y.hex()
                if got == expect or y[::-1].hex() == expect:
                    order = "direct" if got == expect else "reversed"
                    print(f"[MATCH] {name}/{vname}/{op} x={x.hex()} -> {got} ({order})")
                    hits += 1
                else:
                    print(f"  miss {name}/{vname}/{op} x={x.hex()} -> {got} expect {expect}")
    return hits


def main() -> None:
    k1 = blob(0x98FAD0, 40)
    k2 = blob(0x56BD5A, 40)
    print("K1 @0x98FAD0:", k1.hex())
    print("K2 @0x56BD5A:", k2.hex())
    total = try_keys("K1@98FAD0", k1) + try_keys("K2@56BD5A", k2)
    print("MATCHES:", total)


if __name__ == "__main__":
    main()
