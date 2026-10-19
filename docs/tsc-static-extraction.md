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

## 2. 结论

- `.tsc` 的文本记录只包含：注释、符号标签、宏模型内部网表；
- **顶层器件连接与分析设置不在文本记录里**（应在二进制记录中）；
- 因此“纯静态 `.tsc → 完整网表”当前不可行，与 `sim-api-design.md §2.3` 的结论一致。

## 3. 选项

| 方案 | 成本 | 风险 |
|---|---|---|
| A. 解码 OBSS 二进制原理图记录 | 高（格式未知，需大量样本逆向） | 高（可能依赖 TINA 内部对象模型） |
| B. 要求先导出网表（TINA GUI 一次） | 低 | 产品运行时不依赖 GUI，但准备阶段需要一次导出 |
| C. v1 只接受网表/用户提供电路 | 零 | 无法直接吃 `.tsc` |

**建议**：v1 走 B/C；把 A 作为独立研究项，不在主线上等待。
`sim` 的产品链路仍然无 GUI；`.tsc` 只是“输入准备”阶段的一次性动作。

## 4. 复现

```powershell
python $env:TEMP\tina_probe\tsc_scan.py "C:\...\EXAMPLES\Filters_Others\2nd Order All-Pass Filter.TSC"
```
（脚本为临时探针；核心逻辑就是 `tsm_parse.extract_records` + 正则分类。）
