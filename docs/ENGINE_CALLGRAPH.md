# TINA 引擎调用图 ①：线性求解层（Phase 3 / M2）

> 2026-10-17。证据来自两侧，地址互相印证：
> **运行时**：Frida 探针 `tools/tina-run/tina_sparse_trace.js`（经 `tina_run.py --trace-js` 挂载），
> 在 TINA 自带示例 `EXAMPLES\Filters_Others\2nd Order All-Pass Filter.TSC` 上跑 AC 分析（命令 0xA7），
> 单次扫描捕获 ≥20 次 `_SMPcSolve` 调用。
> **静态**：TINA-RE `scripts/ghidra-headless/Round18-21.java`（输出 `out/round18-21.txt`）+
> `scripts/find_sparse_callsites.py`（从镜像里读指针表）。

## 1. 结论

TINA 的线性求解层就是 `sparse_dll.dll` 的 11 个导出。镜像内有一张**已解析的函数指针表**
（RVA `0x1BDAF20`）和一座**跳板岛**（RVA `0x510620–0x510670`，每条 `jmp dword ptr [表项]`）；
引擎侧由一个"按分析类型分派"的求解驱动（RVA `0x473368`）选择走 sparse 还是另一条路径。

## 2. 运行时抓到的调用栈（单次 AC 求解，模块内偏移 = RVA）

```
tina.exe+0x510c72        ← 直接调用者（条件包装器内）
sparse_dll.dll+0x6cdc    ← _SMPcSolve
tina.exe+0x31630d        ← AC 扫描工作函数（FUN_00715cb0）
tina.exe+0x316ad8        ← 同上（调用点）
tina.exe+0x429726        ← 分析编排（FUN_00829726，54 B）
tina.exe+0x93a38         ← 命令派发
tina.exe+0x936b3
tina.exe+0x2ec26         ← 窗口消息入口
user32.dll+…             ← 消息循环
```

`_SMPcSolve` 的入参在整段扫描中保持不变（矩阵/向量指针），说明 AC 扫描复用同一套矩阵结构，
只更新激励与频率。

## 3. 指针表（dump 时 `sparse_dll` 基址 = `0x04400000`）

| 槽 RVA | 值 | 目标 |
|---|---|---|
| `0x1BDAF20` | `0x04406CDC` | `_SMPcSolve` |
| `0x1BDAF24` | `0x04406C04` | `_SMPcLUfac` |
| `0x1BDAF28` | `0x04406C50` | `_SMPcReorder` |
| `0x1BDAF2C` | `0x04406D00` | `_SMPsolve` |
| `0x1BDAF30` | `0x04406C20` | `_SMPluFac` |
| `0x1BDAF34` | `0x04406C84` | `_SMPreorder` |
| `0x1BDAF38` | `0x04406D68` | `_SMPpreOrder` |
| `0x1BDAF3C` | `0x04406BBC` | `_SMPmakeElt` |
| `0x1BDAF40` | `0x04406BEC` | `_SMPclear` |
| `0x1BDAF44` | `0x04406D58` | `_SMPdestroy` |
| `0x1BDAF48` | `0x04406D38` | `_SMPnewMatrix` |
| `0x1BDAF4C` | 0 | — |

> 对账细节：磁盘上 tina.exe 的静态导入表只列了 `_SMPcSolve` 一条，但 dump 里的表**11 项全满**，
> 且跳板岛逐项引用。说明加载/脱壳阶段重建了完整导入表（ASProtect 常见行为），
> 不能只信磁盘 PE 的导入目录。

## 4. 跳板岛（RVA `0x510620–0x510670`）

| thunk RVA | 目标 |
|---|---|
| `0x510620` | `_SMPnewMatrix` |
| `0x510628` | `_SMPdestroy` |
| `0x510630` | `_SMPclear` |
| `0x510638` | `_SMPmakeElt` |
| `0x510640` | `_SMPpreOrder` |
| `0x510648` | `_SMPreorder` |
| `0x510650` | `_SMPluFac` |
| `0x510658` | `_SMPsolve` |
| `0x510660` | `_SMPcReorder` |
| `0x510668` | `_SMPcLUfac` |
| `0x510670` | `_SMPcSolve` |

## 5. 引擎侧调用链（静态反编译）

```c
// RVA 0x510C58：条件包装器（30 B）
void solve_if_nonscalar(int m) {
  if (1 < *(ushort *)(m + 4)) {       // 矩阵阶数 > 1 才走 sparse
    _SMPcSolve_thunk();               // RVA 0x510670
  }
}
```

```c
// RVA 0x1888EC：6 字节转发器（跳板岛的另一份入口）
void fwd() { solve_if_nonscalar(); }
```

```c
// RVA 0x473368：求解驱动（98 B）——按分析类型分派
void solve_driver(a, type, c, d, e) {
  if ((char)type == 8) {              // type 8 → sparse 路径
    FUN_0058885c(a, type, c, d, e);
    fwd(a, *PTR_DAT_00a640d8, *PTR_DAT_00a65278);
  } else {                            // 其它类型 → 另一条路径
    FUN_005888f4(a, type, c, d, e);
    FUN_00588984(a, *PTR_DAT_00a640d8);
  }
  FUN_009107f0(a, 1);
  (*PTR_DAT_00a64e18)++;              // 求解次数计数
}
```

```c
// RVA 0x315CB0：AC 扫描（2170 B）——x87 double 频率循环
while (freq <= stop && !aborted) {
  switch (kind) { ... }               // 每种扫描类型一组刷新 + 求解
}
```

对应关系：`FUN_00715CB0`(AC 扫描) → `solve_if_nonscalar`(0x510C58) → `_SMPcSolve`。
另一条入口 `FUN_0089FA3C`（RVA 0x49FA3C，2290 B）也直接调用包装器，推测是 DC/工作点路径
（待用 DC 命令 0xA2 的探针确认）。

## 6. 复现

```powershell
# 运行时探针（捕获调用栈；会自动点掉启动警告和 AC 对话框）
python D:\WorkDesigns\3_WorkTools\SpiceHappy-tina-re\tools\tina-run\tina_run.py `
  --tsc "C:\Program Files (x86)\DesignSoft\Tina 9 - TI\EXAMPLES\Filters_Others\2nd Order All-Pass Filter.TSC" `
  --export "$env:TEMP\tina_probe\probe.net" --analysis 0xA7 --export-cmd 0x19 `
  --trace-js D:\WorkDesigns\3_WorkTools\SpiceHappy-tina-re\tools\tina-run\tina_sparse_trace.js `
  --timeout 150

# 静态对账（需要 TINA 镜像 + sparse_dll）
python D:\WorkDesigns\3_WorkTools\TINA-RE\scripts\find_sparse_callsites.py
```

## 7. 下一步

1. 用 DC 工作点（0xA2）探针确认 `FUN_0089FA3C` 路径，补齐第二条链。
2. 抓 `_SMPmakeElt` / `_SMPnewMatrix` 的调用栈 → 定位 **MNA 矩阵装配**（器件 stamping）代码。
3. 抓 `_SMPcLUfac` → 确认分解调用点，建立"装配 → 分解 → 求解"三段的完整地图。

## 8. 全导出探针：装配 / 分解 / 求解三段（已补）

脚本 `tools/tina-run/tina_sparse_trace_all.js`（挂 11 个导出，每个函数记前 3 条栈 + 计数），
同一 AC 场景一次运行的实测结果：

| 导出 | 次数 | 引擎侧进入点（RVA） | 上层 |
|---|---|---|---|
| `_SMPnewMatrix` | 1 | `0x50372C`（包装器 `FUN_0090372c`，间接经 `FUN_00910678`） | `0x31662C`（AC 工作函数） |
| `_SMPmakeElt` | **1014** | `0x5110EB/0x511101/0x511118`（第二层跳板）→ 返回 `0x185EA0`（`FUN_00585ea0`，装配循环） | `0x185EA0` |
| `_SMPclear` | 每步 | `0x51096D` → 返回 `0x188926` | `0x4733A6`（求解驱动） |
| `_SMPpreOrder` | 每步 | `0x51073C` | `0x4733A6` |
| `_SMPreorder` | 每步 | `0x510AB7` | `0x4733A6` |
| `_SMPsolve` | 每步 | `0x510BAD` | `0x473DBF`（分析派发 `FUN_00873638`，4186 B） |
| `_SMPcSolve` | 每步 | `0x510C72`（条件包装器） | `0x31630D`（AC 扫描） |
| `_SMPcLUfac` / `_SMPluFac` / `_SMPcReorder` | 0（本次样本） | — | 小矩阵可能走 `_SMPsolve` 内部 |

结论：

1. **求解器区 RVA 0x177000–0x186000 的归属被证实**——装配循环 `0x185EA0` 就在其中，
   每次扫描向稀疏矩阵写入 1014 个元素。
2. 完整链路（AC）：`FUN_00715cb0`(AC 扫描) → `FUN_0090372c`(建矩阵) →
   `FUN_00585ea0`(装配, 1014×makeElt) → `FUN_00873638`(分析派发) →
   `FUN_00873368`(求解驱动) → `0x510c58`(条件包装) → `_SMPcSolve`。
3. 第二层跳板（RVA `0x5110xx`）是 Delphi 包装类的方法入口，和第一层（`0x5106xx`，导入跳板）
   分成两个层次——后续命名时不要混。
