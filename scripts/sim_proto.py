#!/usr/bin/env python3
"""Minimal MNA/SPICE prototype for the C route (reimplement, no TINA, no GUI).

Scope (first milestone):
  - netlist subset: R, V, I, C (DC + backward-Euler transient)
  - modified nodal analysis with numpy/scipy
  - self-tests: voltage divider, current source, RC charge curve vs analytic

This is the seed of the standalone simulator; the sparse LU barrier is replaced
by scipy's SuperLU (see docs/engine-reimplementation.md).
"""
from __future__ import annotations

import math
import sys
from dataclasses import dataclass, field

import numpy as np
from scipy.sparse import lil_matrix
from scipy.sparse.linalg import spsolve

SUFFIX = {"p": 1e-12, "n": 1e-9, "u": 1e-6, "m": 1e-3, "k": 1e3, "meg": 1e6, "g": 1e9}


def parse_value(tok: str) -> float:
    t = tok.strip().lower()
    for suf in ("meg", "g", "k", "m", "u", "n", "p"):
        if t.endswith(suf):
            return float(t[: -len(suf)]) * SUFFIX[suf]
    return float(t)


@dataclass
class Element:
    kind: str
    name: str
    nodes: tuple[str, ...]
    value: float


@dataclass
class Netlist:
    elements: list[Element] = field(default_factory=list)


def parse(text: str) -> Netlist:
    nl = Netlist()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("*") or line.startswith("."):
            continue
        parts = line.replace(",", " ").split()
        name = parts[0]
        kind = name[0].upper()
        if kind in "RVIC" and len(parts) >= 4:
            nl.elements.append(Element(kind, name, (parts[1], parts[2]), parse_value(parts[3])))
    return nl


class Circuit:
    def __init__(self, nl: Netlist):
        nodes: list[str] = []
        for e in nl.elements:
            for n in e.nodes:
                if n not in ("0", "gnd", "GND") and n not in nodes:
                    nodes.append(n)
        self.nodes = nodes
        self.index = {n: i for i, n in enumerate(nodes)}
        self.vsources = [e for e in nl.elements if e.kind == "V"]
        self.size = len(nodes) + len(self.vsources)
        self.nl = nl

    def _n(self, name: str) -> int | None:
        return self.index.get(name)

    def _stamp_g(self, A, i, j, g):
        ii, jj = self._n(i), self._n(j)
        if ii is not None:
            A[ii, ii] += g
        if jj is not None:
            A[jj, jj] += g
        if ii is not None and jj is not None:
            A[ii, jj] -= g
            A[jj, ii] -= g

    def _stamp_i(self, z, i, j, cur):
        """Current source pushing `cur` from node i to node j through the source."""
        ii, jj = self._n(i), self._n(j)
        if ii is not None:
            z[ii] -= cur
        if jj is not None:
            z[jj] += cur

    def _stamp(self, A, z, e: Element, state: dict[str, float] | None, dt: float | None):
        i, j = e.nodes
        if e.kind == "R":
            self._stamp_g(A, i, j, 1.0 / e.value)
        elif e.kind == "I":
            self._stamp_i(z, i, j, e.value)
        elif e.kind == "V":
            k = len(self.nodes) + self.vsources.index(e)
            p, m = self._n(i), self._n(j)
            if p is not None:
                A[p, k] += 1
                A[k, p] += 1
            if m is not None:
                A[m, k] -= 1
                A[k, m] -= 1
            z[k] = e.value
        elif e.kind == "C" and dt is not None and state is not None:
            g = e.value / dt
            self._stamp_g(A, i, j, g)
            vprev = state.get(i, 0.0) - state.get(j, 0.0)
            self._stamp_i(z, i, j, -g * vprev)

    def solve_dc(self) -> np.ndarray:
        A = lil_matrix((self.size, self.size), dtype=float)
        z = np.zeros(self.size)
        for e in self.nl.elements:
            self._stamp(A, z, e, None, None)
        return spsolve(A.tocsr(), z)

    def solve_tran(self, tstop: float, dt: float):
        steps = int(round(tstop / dt))
        state = {n: 0.0 for n in self.nodes}
        times = [0.0]
        hist = [dict(state)]
        for _ in range(steps):
            A = lil_matrix((self.size, self.size), dtype=float)
            z = np.zeros(self.size)
            for e in self.nl.elements:
                self._stamp(A, z, e, state, dt)
            x = spsolve(A.tocsr(), z)
            state = {n: float(x[self.index[n]]) for n in self.nodes}
            times.append(times[-1] + dt)
            hist.append(dict(state))
        return times, hist


def check(name: str, ok: bool, detail: str = "") -> None:
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""))


def main() -> int:
    # 1) DC divider: 10V, R1=1k, R2=2k -> Vout=6.6667V, I=-3.333mA
    c = Circuit(parse("V1 in 0 10\nR1 in out 1k\nR2 out 0 2k\n"))
    x = c.solve_dc()
    vout = x[c.index["out"]]
    check("DC divider Vout", abs(vout - 20 / 3) < 1e-9, f"{vout:.6f}")

    # 2) current source into resistor: 1mA * 1k = 1V
    c2 = Circuit(parse("I1 0 out 1m\nR1 out 0 1k\n"))
    x2 = c2.solve_dc()
    check("current source Vout", abs(x2[c2.index["out"]] - 1.0) < 1e-9, f"{x2[c2.index['out']]:.6f}")

    # 3) RC charge: 5V step, R=1k, C=1u (tau=1ms); BE error O(dt/tau)
    c3 = Circuit(parse("V1 in 0 5\nR1 in out 1k\nC1 out 0 1u\n"))
    tstop, dt = 5e-3, 1e-5
    times, hist = c3.solve_tran(tstop, dt)
    tau = 1e-3
    errs = []
    for idx, t in enumerate(times):
        if t < 1e-9:
            continue
        ana = 5.0 * (1.0 - math.exp(-t / tau))
        errs.append(abs(hist[idx]["out"] - ana))
    maxerr = max(errs)
    check("RC transient vs analytic", maxerr < 0.02, f"maxerr={maxerr:.4f} V")

    # print a few points
    print("  t(ms)  sim(V)   ana(V)")
    for ms in (1, 2, 3, 5):
        idx = min(len(times) - 1, int(round(ms * 1e-3 / dt)))
        ana = 5.0 * (1.0 - math.exp(-times[idx] / tau))
        print(f"  {times[idx]*1e3:5.2f}  {hist[idx]['out']:7.4f}  {ana:7.4f}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
