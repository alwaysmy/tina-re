"""Benchmark the prototype: matrix factorization reuse and scaling."""
import sys
import time

sys.path.insert(0, r"D:\WorkDesigns\3_WorkTools\TINA-RE\scripts")
from sim_proto import Circuit, Netlist, parse  # noqa: E402


def bench(name, c, fn, repeat=1):
    best = 1e9
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn(c)
        best = min(best, time.perf_counter() - t0)
    print(f"{name:34s} {best*1e3:9.1f} ms")
    return best


rc = parse("V1 in 0 5\nR1 in out 1k\nC1 out 0 1u\n")

c = Circuit(rc); c.cache_enabled = True
cache_on = bench("RC 5ms (500 steps), cache on", c, lambda x: x.solve_tran(5e-3, 1e-5))

c = Circuit(rc); c.cache_enabled = False
cache_off = bench("RC 5ms (500 steps), cache off", c, lambda x: x.solve_tran(5e-3, 1e-5))

print(f"speedup: {cache_off/cache_on:.1f}x")


def ladder(n):
    lines = ["V1 n0 0 5"]
    for i in range(n):
        lines.append(f"R{i+1} n{i} n{i+1} 1k")
        lines.append(f"C{i+1} n{i+1} 0 1n")
    lines.append(f"R{n+1} n{n} 0 1k")
    return "\n".join(lines)


for n in (10, 50, 100):
    c = Circuit(parse(ladder(n)))
    bench(f"ladder n={n} DC solve", c, lambda x: x.solve_dc(), repeat=3)

for n in (10, 50):
    c = Circuit(parse(ladder(n)))
    bench(f"ladder n={n} tran 100 steps", c, lambda x: x.solve_tran(1e-6, 1e-8), repeat=1)
