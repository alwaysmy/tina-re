"""Multi-run cost prediction + LPT scheduling prototype.

Models (least squares, measured on this machine):
  DC   : t = d0 + d1*n
  TRAN : t = c0 + c1*steps + c2*n*steps
Then LPT-schedule a mixed batch on W workers and report the predicted makespan.
"""
import sys
import time

import numpy as np

sys.path.insert(0, r"D:\WorkDesigns\3_WorkTools\TINA-RE\scripts")
from sim_proto import Circuit, parse  # noqa: E402


def ladder(n: int) -> str:
    lines = ["V1 n0 0 5"]
    for i in range(n):
        lines.append(f"R{i+1} n{i} n{i+1} 1k")
        lines.append(f"C{i+1} n{i+1} 0 1n")
    lines.append(f"R{n+1} n{n} 0 1k")
    return "\n".join(lines)


def measure(kind: str, n: int, steps: int) -> float:
    c = Circuit(parse(ladder(n)))
    t0 = time.perf_counter()
    if kind == "dc":
        c.solve_dc()
    else:
        c.solve_tran(steps * 1e-8, 1e-8, method="be")
    return (time.perf_counter() - t0) * 1e3


dc_cal = [(100, 0), (500, 0), (1000, 0)]
tr_cal = [(100, 200), (300, 200), (500, 200), (200, 100)]

dc_meas = {n: measure("dc", n, 0) for n, _ in dc_cal}
tr_meas = {(n, s): measure("tran", n, s) for n, s in tr_cal}

X = np.array([[1.0, n] for n, _ in dc_cal])
y = np.array([dc_meas[n] for n, _ in dc_cal])
d0, d1 = np.linalg.lstsq(X, y, rcond=None)[0]

Xt = np.array([[1.0, s, n * s] for n, s in tr_cal])
yt = np.array([tr_meas[(n, s)] for n, s in tr_cal])
c0, c1, c2 = np.linalg.lstsq(Xt, yt, rcond=None)[0]

print(f"DC model  : t = {d0:.2f} + {d1:.6f}*n")
print(f"TRAN model: t = {c0:.2f} + {c1:.4f}*steps + {c2:.6f}*n*steps")


def predict(job) -> float:
    kind, n, steps = job
    if kind == "dc":
        return max(0.1, d0 + d1 * n)
    return max(0.1, c0 + c1 * steps + c2 * n * steps)


valid = [("dc", 300, 0), ("dc", 700, 0), ("tran", 400, 150), ("tran", 600, 100)]
errs = []
for job in valid:
    p = predict(job)
    a = measure(*job)
    errs.append(abs(p - a) / a)
    print(f"valid {job}: predicted {p:7.2f} ms, actual {a:7.2f} ms, err {100*abs(p-a)/a:5.1f}%")
print(f"mean abs error: {100*np.mean(errs):.1f}%")

batch = [
    ("dc", 200, 0), ("dc", 600, 0), ("dc", 1200, 0),
    ("tran", 100, 300), ("tran", 250, 200), ("tran", 400, 100),
    ("tran", 500, 250), ("tran", 800, 50),
]
workers = 4
loads = [0.0] * workers
assign = [[] for _ in range(workers)]
for job in sorted(batch, key=lambda j: -predict(j)):
    i = loads.index(min(loads))
    loads[i] += predict(job)
    assign[i].append(job)
print(f"\nLPT schedule ({workers} workers): predicted makespan {max(loads):.1f} ms")
for i, (load, js) in enumerate(zip(loads, assign)):
    print(f"  w{i}: {load:7.1f} ms  {js}")
