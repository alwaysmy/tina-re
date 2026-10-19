"""Monte Carlo / multi-run prediction for the native engine.

Features:
  - per-element tolerance (uniform ±tol, or normal with tol = 3σ)
  - plain MC and Latin Hypercube sampling
  - DC or transient measurement (value / max / min at a node)
  - statistics: mean/std/percentiles/yield against a spec
  - multiprocessing across samples; seed-per-sample for reproducibility

Usage:
  python scripts/sim_mc.py
"""
from __future__ import annotations

import math
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass

import numpy as np

from sim_proto import Circuit, parse


@dataclass(frozen=True)
class Measurement:
    kind: str          # "dc" | "tran"
    node: str
    tstop: float = 5e-3
    dt: float = 1e-5
    method: str = "trap"
    mode: str = "value"  # "value" (at tstop) | "max" | "min"


@dataclass(frozen=True)
class Tol:
    frac: float          # relative tolerance
    dist: str = "uniform"  # "uniform" | "normal"


def sample_matrix(names, tols, n, seed, method="mc"):
    """Return (n, d) array of relative deviations in [-tol, tol]."""
    rng = np.random.default_rng(seed)
    d = len(names)
    if method == "lhs":
        u = np.empty((n, d))
        for j in range(d):
            perm = rng.permutation(n)
            u[:, j] = (perm + rng.random(n)) / n  # stratified in [0,1)
        u = u * 2.0 - 1.0
    else:
        u = rng.uniform(-1.0, 1.0, (n, d))
    out = np.empty_like(u)
    for j, name in enumerate(names):
        tol = tols[name]
        if tol.dist == "normal":
            z = rng.standard_normal(n)
            z = np.clip(z, -3.0, 3.0) / 3.0
            out[:, j] = z * tol.frac
        else:
            out[:, j] = u[:, j] * tol.frac
    return out


def _run_one(payload):
    netlist, values, meas = payload
    c = Circuit(parse(netlist))
    for e in c.nl.elements:
        v = values.get(e.name)
        if v is not None:
            e.value = v
    if meas.kind == "dc":
        v, _ = c.solve_dc()
        return float(v[meas.node])
    times, hist, _ = c.solve_tran(meas.tstop, meas.dt, method=meas.method)
    series = [h[meas.node] for h in hist]
    if meas.mode == "max":
        return float(max(series))
    if meas.mode == "min":
        return float(min(series))
    return float(series[-1])


def monte_carlo(netlist, tols, meas, n=1000, seed=1234, workers=1, method="mc", chunk=50):
    names = list(tols)
    samp = sample_matrix(names, tols, n, seed, method)
    base = {e.name: e.value for e in parse(netlist).elements if e.name}
    payloads = []
    for i in range(n):
        vals = {name: base[name] * (1.0 + samp[i, j]) for j, name in enumerate(names) if name in base}
        payloads.append((netlist, vals, meas))
    t0 = time.perf_counter()
    if workers <= 1:
        ys = [_run_one(p) for p in payloads]
    else:
        with ProcessPoolExecutor(max_workers=workers) as ex:
            ys = list(ex.map(_run_one, payloads, chunksize=max(1, chunk)))
    elapsed = time.perf_counter() - t0
    return np.array(ys), samp, elapsed


def stats(ys, lo=None, hi=None):
    out = {
        "n": len(ys),
        "mean": float(np.mean(ys)),
        "std": float(np.std(ys, ddof=1)),
        "min": float(np.min(ys)),
        "max": float(np.max(ys)),
        "p1": float(np.percentile(ys, 1)),
        "p5": float(np.percentile(ys, 5)),
        "p50": float(np.percentile(ys, 50)),
        "p95": float(np.percentile(ys, 95)),
        "p99": float(np.percentile(ys, 99)),
    }
    if lo is not None or hi is not None:
        mask = np.ones(len(ys), dtype=bool)
        if lo is not None:
            mask &= ys >= lo
        if hi is not None:
            mask &= ys <= hi
        out["yield"] = float(mask.mean())
    return out


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""))


def main():
    # 1) DC divider: R1=1k ±1%, R2=2k ±1%, Vin=10 -> Vout ~ 6.6667
    net = "V1 in 0 10\nR1 in out 1k\nR2 out 0 2k\n"
    meas = Measurement("dc", "out")
    tols = {"R1": Tol(0.01), "R2": Tol(0.01)}
    ys, samp, dt1 = monte_carlo(net, tols, meas, n=4000, seed=7, workers=1)
    s = stats(ys, lo=6.64, hi=6.69)
    # analytic (linearized) std for uniform ±1%
    r1, r2, vin = 1e3, 2e3, 10.0
    sr1, sr2 = 0.01 * r1 / math.sqrt(3), 0.01 * r2 / math.sqrt(3)
    d1 = -vin * r2 / (r1 + r2) ** 2
    d2 = vin * r1 / (r1 + r2) ** 2
    ana_std = math.sqrt((d1 * sr1) ** 2 + (d2 * sr2) ** 2)
    check("MC DC divider mean", abs(s["mean"] - 20 / 3) < 2e-3, f"{s['mean']:.5f}")
    check("MC DC divider std vs analytic", abs(s["std"] - ana_std) / ana_std < 0.05,
          f"{s['std']:.5f} vs {ana_std:.5f}")
    print(f"  DC: mean={s['mean']:.5f} std={s['std']:.5f} "
          f"p1={s['p1']:.4f} p99={s['p99']:.4f} yield={s.get('yield', float('nan')):.3f} "
          f"({dt1*1e3:.1f} ms, 4000 samples)")

    # 2) RC transient: R ±1%, C ±5%; Vout at 5ms
    net2 = "V1 in 0 5\nR1 in out 1k\nC1 out 0 1u\n"
    meas2 = Measurement("tran", "out", tstop=5e-3, dt=1e-5, method="trap")
    tols2 = {"R1": Tol(0.01), "C1": Tol(0.05)}
    ys2, _, dt2 = monte_carlo(net2, tols2, meas2, n=1000, seed=11, workers=1)
    s2 = stats(ys2, lo=4.80, hi=5.0)
    check("MC RC mean ~ 4.966", abs(s2["mean"] - 4.96631) < 5e-3, f"{s2['mean']:.5f}")
    print(f"  RC: mean={s2['mean']:.5f} std={s2['std']:.5f} "
          f"p1={s2['p1']:.4f} p99={s2['p99']:.4f} yield={s2.get('yield', float('nan')):.3f} "
          f"({dt2*1e3:.1f} ms, 1000 samples)")

    # 3) parallel scaling (same MC job)
    ys3, _, dt3 = monte_carlo(net2, tols2, meas2, n=1000, seed=11, workers=8)
    check("MC parallel == serial", np.allclose(ys2, ys3, rtol=0, atol=0))
    print(f"  parallel: 8 workers {dt3*1e3:.1f} ms vs 1 worker {dt2*1e3:.1f} ms "
          f"({dt2/dt3:.1f}x)")

    # 4) LHS vs MC at the same n
    ys4, _, _ = monte_carlo(net, tols, meas, n=1000, seed=7, workers=1, method="lhs")
    ys5, _, _ = monte_carlo(net, tols, meas, n=1000, seed=7, workers=1, method="mc")
    print(f"  LHS std={np.std(ys4, ddof=1):.6f} vs MC std={np.std(ys5, ddof=1):.6f} (n=1000)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
