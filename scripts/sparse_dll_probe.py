"""Probe sparse_dll.dll from a hidden 32-bit host (wscript.exe + sleep VBS).

No GUI windows: wscript stays alive in the background while Frida loads the DLL
and exercises its exports.

Sequence under test (from the DLL's own preconditions):
    newMatrix -> makeElt (pattern) -> clear -> set values -> preOrder -> cLUfac -> cSolve
Target: solve A = [[2,1,0],[1,3,1],[0,1,2]], b = [1,2,3] -> x = [0.5, 0, 1.5].
"""
import os
import subprocess
import sys
import time

import frida

HOST = r"C:\Windows\SysWOW64\wscript.exe"
DLL = r"C:\Program Files (x86)\DesignSoft\Tina 9 - TI\sparse_dll.dll"
VBS = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "tina_probe", "sleep.vbs")

JS = r"""
'use strict';
setTimeout(() => {
  const DLL = __DLL__;
  const TINA_DIR = 'C:\\\\Program Files (x86)\\\\DesignSoft\\\\Tina 9 - TI';
  const SetDllDirectoryW = new NativeFunction(
    Module.getGlobalExportByName('SetDllDirectoryW'), 'int', ['pointer']);
  SetDllDirectoryW(Memory.allocUtf16String(TINA_DIR));
  const LoadLibraryExW = new NativeFunction(
    Module.getGlobalExportByName('LoadLibraryExW'), 'pointer',
    ['pointer', 'pointer', 'pointer', 'uint']);
  const h = LoadLibraryExW(Memory.allocUtf16String(DLL), ptr(0), ptr(0), 0x8);
  if (h.isNull()) { send({ type: 'abort', reason: 'LoadLibrary failed' }); return; }
  const mod = Process.getModuleByName('sparse_dll.dll');
  const fn = (n, r, a) => new NativeFunction(mod.findExportByName(n), r, a);
  const newMatrix = fn('_SMPnewMatrix', 'int', ['pointer']);
  const makeElt = fn('_SMPmakeElt', 'pointer', ['pointer', 'int', 'int']);
  const clear = fn('_SMPclear', 'void', ['pointer', 'pointer']);
  const preOrder = fn('_SMPpreOrder', 'void', ['pointer']);
  const clufac = fn('_SMPcLUfac', 'void', ['pointer']);
  const csolve = fn('_SMPcSolve', 'void', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
  const solve = fn('_SMPsolve', 'void', ['pointer', 'pointer', 'pointer', 'pointer']);
  const destroy = fn('_SMPdestroy', 'void', ['pointer']);

  function build() {
    const out = Memory.alloc(4);
    const st = newMatrix(out);
    const mat = out.readPointer();
    if (st !== 0 || mat.isNull()) return null;
    const vals = [[1,1,2.0],[2,1,1.0],[1,2,1.0],[2,2,3.0],[3,2,1.0],[2,3,1.0],[3,3,2.0]];
    const els = [];
    for (const [i, j, v] of vals) {
      const el = makeElt(mat, i, j);
      if (!el.isNull()) els.push([el, v]);
    }
    clear(mat, ptr(0));
    for (const [el, v] of els) el.writeDouble(v);
    return mat;
  }

  function vec3(a, b2, c) {
    const p = Memory.alloc(24);
    p.writeDouble(a); p.add(8).writeDouble(b2); p.add(16).writeDouble(c);
    return p;
  }
  const read3 = (p) => [p.readDouble(), p.add(8).readDouble(), p.add(16).readDouble()];

  // 1) cSolve with preOrder + cLUfac
  let mat = build();
  if (mat) {
    preOrder(mat);
    clufac(mat);
    const rowArr = mat.add(0x18).readPointer();
    send({ type: 'rows', rows: [0,1,2,3].map((i) => rowArr.add(i * 4).readPointer().toString()) });
    const b = vec3(1, 2, 3);
    const x = Memory.alloc(24);
    x.writeByteArray(new Uint8Array(24));
    csolve(mat, b, ptr(0), x, ptr(0));
    send({ type: 'csolve-lufac', x: read3(x), b: read3(b) });
    destroy(mat);
  }

  // 2) cSolve with preOrder only
  mat = build();
  if (mat) {
    preOrder(mat);
    const b = vec3(1, 2, 3);
    const x = Memory.alloc(24);
    x.writeByteArray(new Uint8Array(24));
    csolve(mat, b, ptr(0), x, ptr(0));
    send({ type: 'csolve-pre', x: read3(x), b: read3(b) });
    destroy(mat);
  }
  send({ type: 'done' });
}, 50);
""".replace("__DLL__", repr(DLL).replace("'", '"'))


def main() -> int:
    os.makedirs(os.path.dirname(VBS), exist_ok=True)
    with open(VBS, "w", encoding="ascii") as f:
        f.write("WScript.Sleep 60000\n")

    device = frida.get_local_device()
    pid = device.spawn([HOST, VBS])
    session = device.attach(pid)
    script = session.create_script(JS)
    script.on("message", lambda m, d: print("[frida]", m.get("payload", m), flush=True))
    script.load()
    device.resume(pid)
    time.sleep(6)
    try:
        session.detach()
    except Exception:
        pass
    subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
