#!/usr/bin/env python3
"""RIPEMD-256 参考实现（官方伪代码逐行转录）+ G 候选横扫。

验证门：
  1) 官方向量（Bosselaers 页）: ""、abc、message digest 等
  2) 二进制模拟向量（Ghidra p-code 模拟 tina_unpacked_fixed.exe 的压缩函数 0x561588）:
     compress(IV, zeros64) / compress(IV, seq64) / compress(IV, abc-padded)
oracle 5 点来自 SpiceHappy BATTLELOG 三十二轮。
"""
from __future__ import annotations

import struct

M = 0xFFFFFFFF

F = [
    lambda x, y, z: x ^ y ^ z,
    lambda x, y, z: (x & y) | (~x & z),
    lambda x, y, z: (x | ~y) ^ z,
    lambda x, y, z: (x & z) | (y & ~z),
]
K = [[0x00000000] * 16, [0x5A827999] * 16, [0x6ED9EBA1] * 16, [0x8F1BBCDC] * 16][0]
K1 = [0x00000000] * 16 + [0x5A827999] * 16 + [0x6ED9EBA1] * 16 + [0x8F1BBCDC] * 16
K2 = [0x50A28BE6] * 16 + [0x5C4DD124] * 16 + [0x6D703EF3] * 16 + [0x00000000] * 16
R1 = ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
      + [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8]
      + [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12]
      + [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2])
R2 = ([5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12]
      + [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2]
      + [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13]
      + [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14])
S1 = ([11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8]
      + [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12]
      + [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5]
      + [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12])
S2 = ([8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6]
      + [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11]
      + [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5]
      + [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8])

IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
      0x76543210, 0xFEDCBA98, 0x89ABCDEF, 0x01234567]


def rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & M


def compress(h: list[int], block: bytes) -> list[int]:
    x = list(struct.unpack("<16I", block))
    A, B, C, D = h[0], h[1], h[2], h[3]
    A2, B2, C2, D2 = h[4], h[5], h[6], h[7]
    for j in range(64):
        T = rol((A + F[j // 16](B, C, D) + x[R1[j]] + K1[j]) & M, S1[j])
        A, B, C, D = D, T, B, C
        T = rol((A2 + F[3 - j // 16](B2, C2, D2) + x[R2[j]] + K2[j]) & M, S2[j])
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


def rmd256(data: bytes) -> bytes:
    h = list(IV)
    msg = bytearray(data)
    bitlen = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bitlen & 0xFFFFFFFFFFFFFFFF)
    for i in range(0, len(msg), 64):
        h = compress(h, bytes(msg[i:i + 64]))
    return struct.pack("<8I", *h)


def main() -> None:
    print("== gate 1: official vectors ==")
    official = {
        b"": "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d",
        b"abc": "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65",
        b"message digest": "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e",
    }
    for m, exp in official.items():
        got = rmd256(m).hex()
        print(("OK  " if got == exp else "FAIL") + f" {m!r:20} {got}")

    print("== gate 2: binary-emulated compress vectors ==")
    bz = compress(list(IV), bytes(64))
    print("zero-block:", struct.pack("<8I", *bz).hex(),
          "\n   expect   ac92f0fd7e573dcd81c9cf459a79d6a224ce03fbcdb023aa23bff3f7307fbef6")
    bs = compress(list(IV), bytes(range(64)))
    print("seq-block :", struct.pack("<8I", *bs).hex(),
          "\n   expect   115023a38024723bfb163700a7199c0ef7f87c75884ad633355769cade59c476")

    print("== G candidate sweep ==")
    oracle = {
        bytes(8): "7455d14e72cf5821",
        b"\xff" * 8: "3979fa134745dbe6",
        bytes(range(1, 9)): "37848bb38b650bb4",
        bytes.fromhex("2cfe90b5a81999a6"): "272a69bbc7a0b123",
        bytes.fromhex("f5a4c752dcd3a156"): "bc7a318806a75984",
    }
    hits = 0
    for x, expect in oracle.items():
        d = rmd256(x)
        cands = {
            "rmd[:8]": d[0:8], "rmd[8:16]": d[8:16], "rmd[16:24]": d[16:24], "rmd[24:32]": d[24:32],
            "rmd[:8]^x": bytes(a ^ b for a, b in zip(d[0:8], x)),
            "rmd(rev)": rmd256(x[::-1]),
            "rmd(x^ff)": rmd256(bytes(a ^ 0xFF for a in x)),
        }
        for name, c in cands.items():
            if c.hex() == expect:
                print(f"[HIT] {name} x={x.hex()} -> {c.hex()}")
                hits += 1
        print(f"  x={x.hex()} expect={expect} rmd[:8]={d[0:8].hex()} rmd[8:16]={d[8:16].hex()}")
    print("hits:", hits)


if __name__ == "__main__":
    main()
