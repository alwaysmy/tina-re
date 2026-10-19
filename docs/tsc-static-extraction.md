# .TSC 静态提取可行性 spike（2026-10-19）

> 问题：能否不经过 TINA GUI，把 `.tsc` 电路静态恢复成完整网表（含顶层连接与分析卡）？
> 方法：`.tsc` 与 `.tsm` 同属 OBSS 容器；复用 `tsm_parse.extract_records` 提取文本记录，
> 再按“器件行/分析卡”分类。

## 1. 样本与结果

| 文件 | 大小 | 文本记录 | 器件行 | 分析卡 |
|---|---|---|---|---|
| `RTD3.TSC` | 9.3 KB | 80 | 0（1 条误判） | 0 |
| `Buck Converter.TSC` | 10.5 KB | 2 | 0 | 0 |
| `2nd Order All-Pass Filter.TSC` | 大 | 145 | 37 | 0 |

All-Pass 的 37 条“器件行”是 **INA121 宏内部**的器件（`CIN/C4/CC1/CC2/R1/R2/I1…`），
不是顶层电路；三个样本都**没有** `.ac/.tran/.op` 分析卡。

## 2. 结论（2026-10-19 修订）

- `.tsc` 的**文本记录**只包含：注释、符号标签、宏模型内部网表；顶层器件连接与分析设置
  **不在文本记录里**（在二进制记录中）。
- 但二进制记录**可以被解码**：`feat/tsc-static` 线程已经实现了组件/导线/引脚记录解析，
  并对 `Precise Active Voltage Divider`、`All-Pass Filter` 达到**拓扑 MATCH**（对照 TINA 导出）。
- 因此正确结论是：**纯静态 `.tsc → 网表是可行的，但当前只覆盖子集，仍是 beta**；
  不是“不可行”。本文档早先的“不可行”结论已作废。

当前边界（以 `SpiceHappy/docs/tsc-static-design.md` 为准）：

- 器件覆盖：V/R/C/L/D/子电路/地/标签；BJT/MOS/受控源/数字未做；
- 2 引脚器件的引脚方向目前靠几何打分（启发式），需要符号引脚表替代；
- 分析卡尚未从二进制属性解码，需外部 `--analysis`；
- 模型依赖（如 INA132E → A3_132E）需要库内联，正在补；
- oracle 抽样 15 个：4 MATCH / 10 DIFF / 1 失败。

## 3. 选项

| 方案 | 状态 |
|---|---|
| A. 解码 OBSS 二进制原理图记录 | ✅ **已落地原型**（`feat/tsc-static`），覆盖子集，beta |
| B. 先导出网表（TINA GUI 一次） | ✅ 保底方案；未覆盖的 `.tsc` 仍走这里 |
| C. v1 只接受网表/用户提供电路 | ✅ 兜底；不是唯一选项了 |

**建议**：把 A 作为主路线继续完善（符号表、分析解码、模型内联、回归门禁），
B/C 作为未覆盖文件的明确回退；任何不确定都 fail-closed，不静默生成错网表。

## 4. 复现

```powershell
# 纯静态导出（不需要 TINA）
npx tsx src/cli/index.ts tsc-export "circuit.TSC" -o out --analysis ".op"

# 与 TINA oracle 做拓扑差分（开发期）
npx tsx tests/probes/tsc-diff.ts out/circuit.cir oracle/circuit.cir
```

## 5. 仿真级验证（2026-10-19，ngspice-47+）

`Precise Active Voltage Divider` 样例：

| 网表 | ngspice `v(vout)` |
|---|---|
| 纯静态 `tsc-export --analysis .op` | **1.024004 V** |
| TINA oracle（固定版 `tina_run` 导出） | **1.024004 V** |

`All-Pass Filter 455kHz` 样例：

| 网表 | ngspice `v(vout)` |
|---|---|
| 纯静态 `tsc-export --analysis .op` | **2.501503 V** |
| TINA oracle | **2.501503 V** |

两个样例均逐位一致；`XU1` 引脚映射也一致（Divider：`n2 Vout n1…` ↔ `1 Vout 3…`；
All-Pass：`Vout 0 n4 n2 n1 n1` ↔ `Vout 0 2 3 4 4`）。

附带发现：

- oracle 依赖 `.LIB`（TSPICE.LIB / Operational Amplifiers.LIB），ngspice 读不了；
  静态导出把 `A3_132E` 内联进网表，反而更自包含——model-resolver 方向正确；
- oracle 导出必须用带启动警告/AC 对话框修复的 `tina_run.py`；`feat/tsc-static`
  分支里的旧版会直接失败（exit 2），需要 cherry-pick `8f21ec3`。

