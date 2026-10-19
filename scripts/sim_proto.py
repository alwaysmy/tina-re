#!/usr/bin/env python3
"""Standalone MNA/SPICE core (C route) — no TINA, no GUI.

Design stance: **surpass TINA, do not copy its flaws.**
  - robust sparse LU (SuperLU, COLAMD + partial pivoting by default)
  - explicit singular-matrix diagnostics instead of TINA's no-pivot/status-102 trap
  - residual check on every solve

Scope now (M2): R, V, I, C, L, E (VCVS), G (VCCS), F (CCCS), H (CCVS);
DC operating point, backward-Euler transient, AC small-signal.
Ideal op-amp = high-gain VCVS.
"""
from __future__ import annotations

import cmath
import math
import sys
from dataclasses import dataclass, field

import numpy as np
from scipy.sparse import lil_matrix
from scipy.sparse.linalg import splu

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
    nodes: tuple[str, str]
    value: float
    ctrl_nodes: tuple[str, str] | None = None
    ctrl_src: str | None = None


@dataclass
class Netlist:
    elements: list[Element] = field(default_factory=list)


def parse(text: str) -> Netlist:
    nl = Netlist()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("*") or line.startswith("."):
            continue
        p = line.replace(",", " ").split()
        name, kind = p[0], p[0][0].upper()
        if kind in "RVICL" and len(p) >= 4:
            nl.elements.append(Element(kind, name, (p[1], p[2]), parse_value(p[3])))
        elif kind in "EG" and len(p) >= 6:
            nl.elements.append(Element(kind, name, (p[1], p[2]), parse_value(p[5]),
                                       ctrl_nodes=(p[3], p[4])))
        elif kind in "FH" and len(p) >= 5:
            nl.elements.append(Element(kind, name, (p[1], p[2]), parse_value(p[4]),
                                       ctrl_src=p[3]))
    return nl


class SingularMatrix(RuntimeError):
    pass


class Circuit:
    def __init__(self, nl: Netlist):
        nodes: list[str] = []
        for e in nl.elements:
            for n in e.nodes + (e.ctrl_nodes or ()):
                if n not in ("0", "gnd", "GND") and n not in nodes:
                    nodes.append(n)
        self.nodes = nodes
        self.index = {n: i for i, n in enumerate(nodes)}
        self.nl = nl

    # -- branch bookkeeping -------------------------------------------------
    def _branches(self, mode: str) -> list[Element]:
        if mode == "ac":
            return [e for e in self.nl.elements if e.kind in "VEH"]
        return [e for e in self.nl.elements if e.kind in "VEHL"]

    # -- stamps -------------------------------------------------------------
    def _n(self, name: str) -> int | None:
        return self.index.get(name)

    def _g(self, A, i, j, y):
        ii, jj = self._n(i), self._n(j)
        if ii is not None:
            A[ii, ii] += y
        if jj is not None:
            A[jj, jj] += y
        if ii is not None and jj is not None:
            A[ii, jj] -= y
            A[jj, ii] -= y

    def _i(self, z, i, j, cur):
        ii, jj = self._n(i), self._n(j)
        if ii is not None:
            z[ii] -= cur
        if jj is not None:
            z[jj] += cur

    def _branch(self, A, z, p, m, k, rhs=0.0):
        pi, mi = self._n(p), self._n(m)
        if pi is not None:
            A[pi, k] += 1
            A[k, pi] += 1
        if mi is not None:
            A[mi, k] -= 1
            A[k, mi] -= 1
        z[k] += rhs

    # -- assembly -----------------------------------------------------------
    def _assemble(self, mode: str, s=None, state_v=None, state_i=None, dt=None):
        dtype = complex if mode == "ac" else float
        branches = self._branches(mode)
        bidx = {e.name: len(self.nodes) + i for i, e in enumerate(branches)}
        A = lil_matrix((len(self.nodes) + len(branches),) * 2, dtype=dtype)
        z = np.zeros(A.shape[0], dtype=dtype)

        for e in self.nl.elements:
            i, j = e.nodes
            if e.kind == "R":
                self._g(A, i, j, 1.0 / e.value)
            elif e.kind == "I":
                self._i(z, i, j, e.value)
            elif e.kind == "C":
                if mode == "ac":
                    self._g(A, i, j, s * e.value)
                elif mode == "tran":
                    y = e.value / dt
                    self._g(A, i, j, y)
                    vprev = (state_v or {}).get(i, 0.0) - (state_v or {}).get(j, 0.0)
                    self._i(z, i, j, -y * vprev)
            elif e.kind == "L":
                if mode == "ac":
                    self._g(A, i, j, 1.0 / (s * e.value))
                elif mode == "dc":
                    k = bidx[e.name]
                    self._branch(A, z, i, j, k, 0.0)
                else:
                    k = bidx[e.name]
                    iprev = (state_i or {}).get(e.name, 0.0)
                    self._branch(A, z, i, j, k, -(e.value / dt) * iprev)
                    A[k, k] -= e.value / dt
            elif e.kind == "V":
                k = bidx[e.name]
                self._branch(A, z, i, j, k, e.value)
            elif e.kind == "E":
                k = bidx[e.name]
                self._branch(A, z, i, j, k, 0.0)
                cp, cm = e.ctrl_nodes  # type: ignore[misc]
                ci, cmi = self._n(cp), self._n(cm)
                if ci is not None:
                    A[k, ci] -= e.value
                if cmi is not None:
                    A[k, cmi] += e.value
            elif e.kind == "G":
                cp, cm = e.ctrl_nodes  # type: ignore[misc]
                ci, cmi = self._n(cp), self._n(cm)
                ii, jj = self._n(i), self._n(j)
                for r, sign_r in ((ii, 1), (jj, -1)):
                    if r is None:
                        continue
                    if ci is not None:
                        A[r, ci] += sign_r * e.value
                    if cmi is not None:
                        A[r, cmi] -= sign_r * e.value
            elif e.kind == "F":
                kv = bidx[e.ctrl_src]  # type: ignore[index]
                ii, jj = self._n(i), self._n(j)
                if ii is not None:
                    A[ii, kv] += e.value
                if jj is not None:
                    A[jj, kv] -= e.value
            elif e.kind == "H":
                k = bidx[e.name]
                kv = bidx[e.ctrl_src]  # type: ignore[index]
                self._branch(A, z, i, j, k, 0.0)
                A[k, kv] -= e.value
        return A.tocsc(), z

    # -- solver -------------------------------------------------------------
    @staticmethod
    def _solve(A, z):
        try:
            lu = splu(A, permc_spec="COLAMD")  # robust defaults: partial pivoting
        except RuntimeError as exc:
            raise SingularMatrix(f"matrix is singular: {exc}") from exc
        x = lu.solve(z)
        res = np.linalg.norm(A @ x - z, np.inf)
        scale = max(1.0, float(np.linalg.norm(z, np.inf)))
        if res > 1e-8 * scale:
            raise RuntimeError(f"residual too large: {res:.3e}")
        return x

    def _state(self, x):
        return (
            {n: float(x[self.index[n]]) for n in self.nodes},
            {},
        )

    # -- analyses -----------------------------------------------------------
    def solve_dc(self):
        A, z = self._assemble("dc")
        x = self._solve(A, z)
        v = {n: float(x[self.index[n]]) for n in self.nodes}
        branches = self._branches("dc")
        i = {e.name: float(x[len(self.nodes) + k]) for k, e in enumerate(branches)}
        return v, i

    def solve_tran(self, tstop: float, dt: float):
        steps = int(round(tstop / dt))
        state_v = {n: 0.0 for n in self.nodes}
        state_i = {e.name: 0.0 for e in self._branches("tran")}
        times = [0.0]
        hist = [dict(state_v)]
        for _ in range(steps):
            A, z = self._assemble("tran", state_v=state_v, state_i=state_i, dt=dt)
            x = self._solve(A, z)
            state_v = {n: float(x[self.index[n]]) for n in self.nodes}
            branches = self._branches("tran")
            state_i = {e.name: float(x[len(self.nodes) + k]) for k, e in enumerate(branches)}
            times.append(times[-1] + dt)
            hist.append(dict(state_v))
        return times, hist, state_i

    def solve_ac(self, freqs):
        out = []
        for f in freqs:
            s = 2j * math.pi * f
            A, z = self._assemble("ac", s=s)
            x = self._solve(A, z)
            out.append((f, {n: complex(x[self.index[n]]) for n in self.nodes}))
        return out


def check(name: str, ok: bool, detail: str = "") -> None:
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""))


def main() -> int:
    # 1) DC divider
    c = Circuit(parse("V1 in 0 10\nR1 in out 1k\nR2 out 0 2k\n"))
    v, _ = c.solve_dc()
    check("DC divider", abs(v["out"] - 20 / 3) < 1e-9, f"{v['out']:.6f}")

    # 2) current source
    c = Circuit(parse("I1 0 out 1m\nR1 out 0 1k\n"))
    v, _ = c.solve_dc()
    check("current source", abs(v["out"] - 1.0) < 1e-9, f"{v['out']:.6f}")

    # 3) RC transient
    c = Circuit(parse("V1 in 0 5\nR1 in out 1k\nC1 out 0 1u\n"))
    times, hist, _ = c.solve_tran(5e-3, 1e-5)
    tau = 1e-3
    err = max(abs(hist[k]["out"] - 5 * (1 - math.exp(-t / tau)))
              for k, t in enumerate(times) if t > 0)
    check("RC transient", err < 0.02, f"maxerr={err:.4f}")

    # 4) RL transient: i_L = 5/1k * (1-exp(-t/tau)), tau = L/R = 1us
    c = Circuit(parse("V1 in 0 5\nR1 in out 1k\nL1 out 0 1m\n"))
    times, hist, iL = c.solve_tran(5e-6, 1e-8)
    tau = 1e-6
    err = max(abs((5 - hist[k]["out"]) / 1e3 - (5 / 1e3) * (1 - math.exp(-t / tau)))
              for k, t in enumerate(times) if t > 0)
    check("RL transient", err < 2e-5, f"maxerr={err:.2e}")

    # 5) inverting op-amp (ideal VCVS, gain 1e5): -R2/R1
    c = Circuit(parse("V1 in 0 1\nR1 in inv 1k\nR2 inv out 10k\nE1 out 0 0 inv 100k\n"))
    v, _ = c.solve_dc()
    check("inverting op-amp", abs(v["out"] + 10.0) < 0.02, f"{v['out']:.4f}")

    # 6) AC RC low-pass at fc: |H| = 1/sqrt(2)
    c = Circuit(parse("V1 in 0 1\nR1 in out 1k\nC1 out 0 1u\n"))
    fc = 1 / (2 * math.pi * 1e3 * 1e-6)
    (_, vac), = c.solve_ac([fc])
    mag = abs(vac["out"])
    check("AC RC low-pass", abs(mag - 1 / math.sqrt(2)) < 1e-6, f"|H|={mag:.6f}")

    # 7) robustness: zero-diagonal system (TINA's no-pivot path would return 102)
    from scipy.sparse import csc_matrix
    x = Circuit._solve(csc_matrix(np.array([[0.0, 1.0], [1.0, 0.0]])), np.array([1.0, 2.0]))
    check("zero-diagonal robustness", np.allclose(x, [2.0, 1.0]), f"{x}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
