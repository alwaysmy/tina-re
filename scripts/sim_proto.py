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
VT = 0.025852          # thermal voltage at ~300 K
DEFAULT_IS = 1e-14
DEFAULT_N = 1.0


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
    ctrl_nodes: tuple[str, str] | None = None
    ctrl_src: str | None = None
    params: dict[str, float] = field(default_factory=dict)


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
        elif kind == "D" and len(p) >= 3:
            params = {}
            for tok in p[3:]:
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    params[k.lower()] = parse_value(v)
            nl.elements.append(Element("D", name, (p[1], p[2]), 0.0, params=params))
        elif kind == "Q" and len(p) >= 4:
            params = {}
            for tok in p[4:]:
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    params[k.lower()] = parse_value(v)
            nl.elements.append(Element("Q", name, (p[1], p[2], p[3]), 0.0, params=params))
        elif kind == "M" and len(p) >= 5:
            params = {}
            for tok in p[5:]:
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    params[k.lower()] = parse_value(v)
            nl.elements.append(Element("M", name, (p[1], p[2], p[3], p[4]), 0.0, params=params))
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

    def _vccs(self, A, op, om, cp, cm, gm):
        oi, omi = self._n(op), self._n(om)
        ci, cmi = self._n(cp), self._n(cm)
        if oi is not None:
            if ci is not None:
                A[oi, ci] += gm
            if cmi is not None:
                A[oi, cmi] -= gm
        if omi is not None:
            if ci is not None:
                A[omi, ci] -= gm
            if cmi is not None:
                A[omi, cmi] += gm

    # -- assembly -----------------------------------------------------------
    def _assemble(self, mode: str, s=None, state_v=None, state_i=None, dt=None, vd=None, vb=None, vm=None,
                  method: str = "be", state_ic=None, state_vl=None):
        dtype = complex if mode == "ac" else float
        branches = self._branches(mode)
        bidx = {e.name: len(self.nodes) + i for i, e in enumerate(branches)}
        A = lil_matrix((len(self.nodes) + len(branches),) * 2, dtype=dtype)
        z = np.zeros(A.shape[0], dtype=dtype)

        for e in self.nl.elements:
            if e.kind == "Q":
                c, b, em = e.nodes
                vbe, vbc = (vb or {}).get(e.name, (0.0, 0.0))
                isat = e.params.get("is", 1e-14)
                bf = e.params.get("bf", 100.0)
                br = e.params.get("br", 1.0)
                vt = VT
                exb = math.exp(max(min(vbe / vt, 40.0), -50.0))
                exc = math.exp(max(min(vbc / vt, 40.0), -50.0))
                ibe = isat / bf * (exb - 1.0)
                ibc = isat / br * (exc - 1.0)
                gbe = isat / bf / vt * exb
                gbc = isat / br / vt * exc
                gm = isat / vt * exb
                gmr = isat / vt * exc
                self._g(A, b, em, gbe)
                self._i(z, b, em, ibe - gbe * vbe)
                self._g(A, b, c, gbc)
                self._i(z, b, c, ibc - gbc * vbc)
                ict0 = isat * (exb - exc)
                self._i(z, c, em, ict0 - gm * vbe + gmr * vbc)
                self._vccs(A, c, em, b, em, gm)
                self._vccs(A, c, em, b, c, -gmr)
                continue
            if e.kind == "M":
                d, g, s, b = e.nodes
                vgs, vds = (vm or {}).get(e.name, (0.0, 0.0))
                vto = e.params.get("vto", 1.0)
                kp = e.params.get("kp", 1e-3)
                lam = e.params.get("lambda", 0.0)
                vov = vgs - vto
                if vov <= 0:
                    idd = gm = gds = 0.0
                elif vds < vov:
                    idd = kp * (vov * vds - 0.5 * vds * vds) * (1 + lam * vds)
                    gm = kp * vds * (1 + lam * vds)
                    gds = kp * (vov - vds) * (1 + lam * vds) + kp * (vov * vds - 0.5 * vds * vds) * lam
                else:
                    idd = 0.5 * kp * vov * vov * (1 + lam * vds)
                    gm = kp * vov * (1 + lam * vds)
                    gds = 0.5 * kp * vov * vov * lam
                ieq = idd - gm * vgs - gds * vds
                self._i(z, d, s, ieq)
                self._vccs(A, d, s, g, s, gm)
                self._vccs(A, d, s, d, s, gds)
                continue
            i, j = e.nodes
            if e.kind == "R":
                self._g(A, i, j, 1.0 / e.value)
            elif e.kind == "I":
                self._i(z, i, j, e.value)
            elif e.kind == "C":
                if mode == "ac":
                    self._g(A, i, j, s * e.value)
                elif mode == "tran":
                    if method == "trap":
                        y = 2.0 * e.value / dt
                        vprev = (state_v or {}).get(i, 0.0) - (state_v or {}).get(j, 0.0)
                        iprev = (state_ic or {}).get(e.name, 0.0)
                        self._g(A, i, j, y)
                        self._i(z, i, j, -(y * vprev + iprev))
                    else:
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
                elif method == "trap":
                    k = bidx[e.name]
                    iprev = (state_i or {}).get(e.name, 0.0)
                    vprev = (state_vl or {}).get(e.name, 0.0)
                    self._branch(A, z, i, j, k, -(2.0 * e.value / dt) * iprev - vprev)
                    A[k, k] -= 2.0 * e.value / dt
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
            elif e.kind == "D":
                vdi = (vd or {}).get(e.name, 0.0)
                isat = e.params.get("is", DEFAULT_IS)
                n = e.params.get("n", DEFAULT_N)
                vt = n * VT
                v = max(min(vdi, 40.0 * vt), -50.0 * vt)
                ex = math.exp(v / vt)
                idd = isat * (ex - 1.0)
                gd = isat / vt * ex
                ieq = idd - gd * v
                self._g(A, i, j, gd)
                self._i(z, i, j, ieq)
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
    @staticmethod
    def _node_v(v: dict[str, float], name: str) -> float:
        return 0.0 if name in ("0", "gnd", "GND") else v[name]

    @staticmethod
    def _limit(new: float, old: float, step: float = 0.2) -> float:
        """Damped Newton update for junction voltages (pnjlim-style)."""
        return old + max(-step, min(step, new - old))

    def solve_dc(self):
        diodes = [e for e in self.nl.elements if e.kind == "D"]
        bjts = [e for e in self.nl.elements if e.kind == "Q"]
        moss = [e for e in self.nl.elements if e.kind == "M"]
        vd = {e.name: 0.0 for e in diodes}
        vb = {e.name: (0.0, 0.0) for e in bjts}
        vm = {e.name: (0.0, 0.0) for e in moss}
        v: dict[str, float] = {}
        x = None
        for _ in range(200):
            A, z = self._assemble("dc", vd=vd, vb=vb, vm=vm)
            x = self._solve(A, z)
            v = {n: float(x[self.index[n]]) for n in self.nodes}
            nvd = {e.name: self._limit(
                self._node_v(v, e.nodes[0]) - self._node_v(v, e.nodes[1]), vd[e.name]
            ) for e in diodes}
            nvb = {e.name: (
                self._limit(self._node_v(v, e.nodes[1]) - self._node_v(v, e.nodes[2]), vb[e.name][0]),
                self._limit(self._node_v(v, e.nodes[1]) - self._node_v(v, e.nodes[0]), vb[e.name][1]),
            ) for e in bjts}
            nvm = {e.name: (
                self._limit(self._node_v(v, e.nodes[1]) - self._node_v(v, e.nodes[2]), vm[e.name][0]),
                self._limit(self._node_v(v, e.nodes[0]) - self._node_v(v, e.nodes[2]), vm[e.name][1]),
            ) for e in moss}
            delta = max(
                [abs(nvd[k] - vd[k]) for k in vd]
                + [abs(nvb[k][0] - vb[k][0]) for k in vb]
                + [abs(nvb[k][1] - vb[k][1]) for k in vb]
                + [abs(nvm[k][0] - vm[k][0]) for k in vm]
                + [abs(nvm[k][1] - vm[k][1]) for k in vm]
                + [0.0]
            )
            vd, vb, vm = nvd, nvb, nvm
            if delta < 1e-8:
                break
        else:
            raise RuntimeError("DC Newton did not converge")
        branches = self._branches("dc")
        i = {e.name: float(x[len(self.nodes) + k]) for k, e in enumerate(branches)}
        return v, i

    def solve_tran(self, tstop: float, dt: float, method: str = "be"):
        steps = int(round(tstop / dt))
        state_v = {n: 0.0 for n in self.nodes}
        branches = self._branches("tran")
        state_i = {e.name: 0.0 for e in branches}
        diodes = [e for e in self.nl.elements if e.kind == "D"]
        bjts = [e for e in self.nl.elements if e.kind == "Q"]
        moss = [e for e in self.nl.elements if e.kind == "M"]
        caps = [e for e in self.nl.elements if e.kind == "C"] if method == "trap" else []
        inds = [e for e in self.nl.elements if e.kind == "L"] if method == "trap" else []
        state_ic = {e.name: 0.0 for e in caps}
        state_vl = {e.name: 0.0 for e in inds}
        state_vd = {e.name: 0.0 for e in diodes}
        state_vb = {e.name: (0.0, 0.0) for e in bjts}
        state_vm = {e.name: (0.0, 0.0) for e in moss}
        times = [0.0]
        hist = [dict(state_v)]
        for step in range(steps):
            step_method = "be" if (method == "trap" and step == 0) else method
            prev_v = dict(state_v)
            vd = dict(state_vd)
            vb = dict(state_vb)
            vm = dict(state_vm)
            for _ in range(100):
                A, z = self._assemble("tran", state_v=state_v, state_i=state_i, dt=dt,
                                      vd=vd, vb=vb, vm=vm, method=step_method,
                                      state_ic=state_ic, state_vl=state_vl)
                x = self._solve(A, z)
                new_v = {n: float(x[self.index[n]]) for n in self.nodes}
                nvd = {e.name: self._limit(
                    self._node_v(new_v, e.nodes[0]) - self._node_v(new_v, e.nodes[1]), vd[e.name]
                ) for e in diodes}
                nvb = {e.name: (
                    self._limit(self._node_v(new_v, e.nodes[1]) - self._node_v(new_v, e.nodes[2]), vb[e.name][0]),
                    self._limit(self._node_v(new_v, e.nodes[1]) - self._node_v(new_v, e.nodes[0]), vb[e.name][1]),
                ) for e in bjts}
                nvm = {e.name: (
                    self._limit(self._node_v(new_v, e.nodes[1]) - self._node_v(new_v, e.nodes[2]), vm[e.name][0]),
                    self._limit(self._node_v(new_v, e.nodes[0]) - self._node_v(new_v, e.nodes[2]), vm[e.name][1]),
                ) for e in moss}
                delta = max(
                    [abs(nvd[k] - vd[k]) for k in vd]
                    + [abs(nvb[k][0] - vb[k][0]) for k in vb]
                    + [abs(nvb[k][1] - vb[k][1]) for k in vb]
                    + [abs(nvm[k][0] - vm[k][0]) for k in vm]
                    + [abs(nvm[k][1] - vm[k][1]) for k in vm]
                    + [0.0]
                )
                vd, vb, vm = nvd, nvb, nvm
                if delta < 1e-8:
                    break
            else:
                raise RuntimeError("transient Newton did not converge")
            state_v = new_v
            state_vd, state_vb, state_vm = nvd, nvb, nvm
            state_i = {e.name: float(x[len(self.nodes) + k]) for k, e in enumerate(branches)}
            if method == "trap":
                if step == 0:
                    # first step uses BE; derive the initial capacitor current from it
                    state_ic = {
                        e.name: (e.value / dt) * (
                            self._node_v(state_v, e.nodes[0]) - self._node_v(state_v, e.nodes[1])
                            - (self._node_v(prev_v, e.nodes[0]) - self._node_v(prev_v, e.nodes[1]))
                        )
                        for e in caps
                    }
                else:
                    state_ic = {
                        e.name: (2.0 * e.value / dt) * (
                            self._node_v(state_v, e.nodes[0]) - self._node_v(state_v, e.nodes[1])
                            - (self._node_v(prev_v, e.nodes[0]) - self._node_v(prev_v, e.nodes[1]))
                        ) - state_ic[e.name]
                        for e in caps
                    }
                state_vl = {
                    e.name: self._node_v(state_v, e.nodes[0]) - self._node_v(state_v, e.nodes[1])
                    for e in inds
                }
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

    def ac_sweep(self, fmin: float, fmax: float, ppd: int = 10):
        """Log sweep, `ppd` points per decade (inclusive endpoints)."""
        decades = math.log10(fmax / fmin)
        n = max(2, int(round(ppd * decades)) + 1)
        freqs = [fmin * (fmax / fmin) ** (i / (n - 1)) for i in range(n)]
        return self.solve_ac(freqs)


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
    check("RC transient (BE)", err < 0.02, f"maxerr={err:.4f}")

    # 3b) RC transient, trapezoidal (second order)
    times, hist, _ = c.solve_tran(5e-3, 1e-5, method="trap")
    err = max(abs(hist[k]["out"] - 5 * (1 - math.exp(-t / tau)))
              for k, t in enumerate(times) if t > 0)
    check("RC transient (trap)", err < 1e-3, f"maxerr={err:.2e}")

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

    # 6b) AC sweep: compare |H| and phase against the analytic RC response
    sweep = c.ac_sweep(1.0, 1e6, ppd=5)
    worst_mag = 0.0
    worst_phase = 0.0
    for f, nodes in sweep:
        h = nodes["out"]
        ana_mag = 1 / math.sqrt(1 + (f / fc) ** 2)
        ana_phase = -math.atan(f / fc)
        worst_mag = max(worst_mag, abs(abs(h) - ana_mag))
        worst_phase = max(worst_phase, abs(cmath.phase(h) - ana_phase))
    check("AC sweep vs analytic", worst_mag < 1e-9 and worst_phase < 1e-9,
          f"dmag={worst_mag:.2e} dphase={worst_phase:.2e}")

    # 7) robustness: zero-diagonal system (TINA's no-pivot path would return 102)
    from scipy.sparse import csc_matrix
    x = Circuit._solve(csc_matrix(np.array([[0.0, 1.0], [1.0, 0.0]])), np.array([1.0, 2.0]))
    check("zero-diagonal robustness", np.allclose(x, [2.0, 1.0]), f"{x}")

    # 8) diode DC vs analytic/brentq reference
    from scipy.optimize import brentq
    c = Circuit(parse("V1 in 0 5\nR1 in d 1k\nD1 d 0\n"))
    v, _ = c.solve_dc()
    ref = brentq(lambda vd: (5 - vd) / 1e3 - 1e-14 * (math.exp(vd / 0.025852) - 1), 0.0, 1.0)
    check("diode DC vs reference", abs(v["d"] - ref) < 1e-6, f"{v['d']:.6f} vs {ref:.6f}")

    # 9) BJT common-emitter bias vs self-consistent reference
    c = Circuit(parse("V1 5 0 5\nRb 5 b 1meg\nRc 5 c 1k\nQ1 c b 0 NPN Is=1e-14 Bf=100\n"))
    v, _ = c.solve_dc()
    vt = 0.025852
    ref = brentq(
        lambda vbe: vbe - vt * math.log(100 * (5 - vbe) / (1e6 * 1e-14)),
        0.0, 0.9,
    )
    check("BJT bias Vbe", abs(v["b"] - ref) < 2e-3, f"{v['b']:.4f} vs {ref:.4f}")
    ic = 100 * (5 - v["b"]) / 1e6
    check("BJT bias Vc", abs(v["c"] - (5 - ic * 1e3)) < 0.02, f"{v['c']:.3f}")

    # 10) MOS common-source saturation: Vg=2, Vto=1, Kp=1m, Rd=1k, Vdd=5 -> Id=0.5mA, Vd=4.5
    c = Circuit(parse("Vdd 5 0 5\nVg g 0 2\nRd 5 d 1k\nM1 d g 0 0 Vto=1 Kp=1m\n"))
    v, _ = c.solve_dc()
    check("MOS saturation Vd", abs(v["d"] - 4.5) < 0.02, f"{v['d']:.3f}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
