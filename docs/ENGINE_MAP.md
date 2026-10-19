# TINA SPICE 引擎地图（基于脱壳镜像 tina_unpacked_static.exe）

> 镜像：`re/tina_unpacked_static.exe`（31.5MB，节表 raw=virtual 修正，
> dump 时 IAT 已解析——IDA/Ghidra 直接载入分析）。RVA = 文件偏移。

## 引擎核心区定位（字符串地标聚类）

| 地标 | RVA | 区 |
|---|---|---|
| GMIN（选项解析） | 0x1779d9, 0x17cceb, 0x183591, 0x184415, 0x184769 | 求解器区 |
| RELTOL | 0x17cd0d, 0x2e216c | 求解器区 |
| TEMP | 0x1779cd, 0x179abd, 0x17cd1f | 求解器区 |
| TRA（瞬态） | 0x17cd55 | 求解器区 |
| pole（极点分析） | 0x4ec58c, 0x59292f | 后处理区 |
| operating point | 0x33f75a, 0x3448ca | 分析编排区 |
| Jacobian | 0x1da45fc（.data 资源） | 数据 |
| ' LU ' | 0x2e77b2 | 线性代数区 |

**结论**：数值求解器核心 ≈ **RVA 0x177000–0x185000**；
分析编排 ≈ 0x330000–0x350000；线性代数 ≈ 0x2e7000（另有 sparse_dll.dll 提供 LU 原语，见最早研究）。

## 关键背景事实（历轮实证）

- 引擎整体在 tina.exe 主代码区（0x1000–0x666000，v1 dump 已全部解密，熵 8.0→6.6）
- 22MB 虚拟区（0x666000+）非壳的代码缓存——501 页非零为运行时数据；引擎不在此
- LU 分解：内置（' LU ' 区）+ sparse_dll.dll（导出 LU 原语，独立可调用）
- 密码模块：0x159000–0x16f000（TProtection 体系，详见 BATTLELOG）

## 剥离路线评估（Phase 3）

> 2026-10-17：测绘与路线已独立成文 → 路线见 TINA-RE `docs/findings.md` §14/§15。
> 本次 Ghidra 实测修正两处归属：`0x58F851` 实为签名/更新/库加载模块（非网表编译）；
> "线性代数 0x2E7000" 最大函数形似绘图渲染（LU 更可能来自 sparse_dll.dll）。
> 近期路线定为 B（调用点复用），M2 = 用 sparse_dll 运行时 hook 反查求解调用链。

完全静态剥离（独立可执行）难度：ASProtect 虚拟化外壳 + Delphi 运行时深度耦合
（对象/VCL/字符串），工程量数周。
**务实替代**：
1. **harness 路线**——`sparse_dll.dll` 已是独立 LU 原语库可直接链接；
   引擎调用链已实测定位（见下节），可由 0x473368 求解驱动 / 0x510c58 包装器切入
2. **调用点复用**——解密 CLI（tina_export.py）的触发管线同样能驱动仿真，
   以"进程内引擎"形态提供能力（已在 tina-run 工具验证）

## 运行时实测（2026-10-17，M2 步骤 1）

Frida 探针 `tools/tina-run/tina_sparse_trace.js` + Ghidra 对账，详见
[ENGINE_CALLGRAPH.md](ENGINE_CALLGRAPH.md)。要点：

- AC 扫描每次求解都进 `sparse_dll.dll!_SMPcSolve`（单次扫描 ≥20 次调用）
- 调用链：`FUN_00715cb0`(AC 扫描, RVA 0x315cb0) → `0x510c58`(条件包装器) →
  `0x510670`(跳板) → `_SMPcSolve`
- 镜像内有完整 sparse 指针表：RVA `0x1BDAF20`，dump 时基址 `0x04400000`；
  跳板岛 RVA `0x510620–0x510670`
- 求解驱动 `0x473368`：`type==8` 走 sparse，其它走另一条路径（待确认）
- 结论修正：`0x58F851` 不是网表编译入口（实为签名/更新/库加载模块）；
  LU/求解的主路径确认是 `sparse_dll.dll`，不是 0x2E7000 的"线性代数区"
