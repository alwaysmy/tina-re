# 引擎重实现路线（C 目标）：不从 DLL 调用，自己写

> 2026-10-19。结论先行：**放弃调用 `sparse_dll.dll`，改用自己的 MNA/求解器实现。**
> 本文记录 DLL 逆向结论、放弃理由、原型现状与 C 路线里程碑。

## 1. 为什么不再走 DLL 调用

`sparse_dll.dll`（43 KB，11 个导出）逆向结论：

| 项 | 结论 |
|---|---|
| 本质 | 标准**稀疏 LU**（SuperLU 风格；panic 字符串指向 `SRC\LIB\SPARSE\SPSOLVE.C`） |
| 矩阵对象 | 0xE8 字节，魔数 `0x772773`；维度 `+0xA4`，行指针数组 `+0x18`，列链 `+0x40`，解向量 `+0x4C`，置换数组 `+0x54/+0x58` |
| 元素对象 | `+0` double 值，`+0x14` 行/列号，`+0x18` 链指针（约 0x20 字节/元素） |
| 导出 | `newMatrix / makeElt / clear / preOrder / reorder / luFac / solve / destroy`（另有 c 变体） |
| 依赖 | Delphi 6 运行时 `rtl60.bpl` + `BORLNDMM` + `CC3260MT`，**32 位** |
| 调用约束 | 顺序敏感（`clear` 会清零元素值；`luFac` 设置“已分解”标志；`cSolve` 的解向量是第 4 参） |

放弃理由：

1. **没有私有算法**——就是标准稀疏 LU，用 SuperLU/UMFPACK/Eigen 完全等价；
2. 32 位 Delphi DLL 的调用面（结构体、顺序、置换数组）维护成本高，且必须依赖 32 位宿主；
3. C 目标真正的工作量在 **MNA 装配 + 器件模型 + 分析循环**，不在 LU 库；
4. 自研实现可以直接做成 TS/原生，不拖 Delphi 运行时，也不依赖 TINA。

## 2. 原型现状（已跑通）

`scripts/sim_proto.py`（Python + numpy/scipy，无 GUI）：

- 网表子集：R / V / I / C / L / E（VCVS）/ G（VCCS）/ F（CCCS）/ H（CCVS）/ D（二极管）/
  Q（BJT，Ebers-Moll）/ M（MOS Level 1）；理想运放 = 高增益 VCVS；
- 分析：DC 工作点（含 Newton 非线性）、后向欧拉瞬态、AC 小信号；
- 求解：SuperLU（COLAMD + 默认部分选主元），每次求解做残差检查，奇异矩阵给出明确错误；
- 自测（13 项全 PASS）：

```
PASS DC divider
PASS current source
PASS RC transient (BE)
PASS RC transient (trap)        ← 梯形积分，误差 2.46e-4（BE 9.16e-3）
PASS RL transient
PASS inverting op-amp
PASS AC RC low-pass
PASS AC sweep vs analytic       ← 对数扫频，幅值/相位与解析式一致
PASS zero-diagonal robustness   ← TINA 的不选主元路径会在此返回 102
PASS diode DC vs reference      ← Newton-Raphson + brentq 对拍
PASS BJT bias Vbe / Vc          ← Ebers-Moll 共射偏置
PASS MOS saturation Vd          ← Level 1 饱和区
```

**设计原则：全面超越 TINA，不复制它的缺陷。**

| TINA 的问题 | 我们的做法 |
|---|---|
| 分解不选主元，零对角直接报 102 | 默认部分选主元；零对角可正常求解 |
| 排序/阈值是隐式约定 | 显式参数（COLAMD、阈值），可诊断 |
| 奇异只返回状态码 | 抛 `SingularMatrix`，附明确信息 |
| 对角存倒数、置换数组隐式 | 标准 L/U，内部实现透明 |

## 3. C 路线里程碑

| 阶段 | 内容 | 验收 |
|---|---|---|
| M1 ✅ | MNA 核心 + DC + BE 瞬态（R/V/I/C） | 自测通过 |
| M2 ✅（本轮） | L、受控源（E/G/F/H）、理想运放、AC 小信号 | 7 项自测通过（含零对角鲁棒性） |
| M3a ✅（本轮） | 二极管 + Newton-Raphson（含指数限幅） | 与 brentq 解析参考对拍，误差 < 1e-6 V |
| M3b ✅（本轮） | BJT（Ebers-Moll）、MOS Level 1 | 共射偏置 / MOS 饱和与解析参考对拍；11 项自测全 PASS |
| M4（部分 ✅ 本轮） | 梯形积分、节点电压限幅、ngspice 对拍 | RC 5ms：4.966310 V vs ngspice 4.966312 V；步长控制/AC 扫频输出待做 |
| M5 | 网表兼容层：TINA/PSpice 子集 + 解密后的 `.lib` 模型 | 能跑通 SPICELIB 基础子电路 |
| M6 | 产品化：TS 端口（或 WASM/C++），按 `docs/sim-api-design.md` 接入 `SimRequest/SimResult` | `spicehappy sim` 无 TINA、无 GUI |

## 4. 与 TINA 结果的关系

- 不追求与 TINA **逐位一致**：LU 的 pivoting/ordering 不同会带来浮点差异，电路仿真通常可接受；
- 需要“TINA 语义”的部分是**器件模型/分析定义**，不是线性代数；
- 校验策略：标准电路用 ngspice/LTspice 对拍；TINA 专有模型用已解密文本 + 现有 tina-run 导出结果做**离线样本**（仅作基准，不进产品链路）。

## 5. 资产

- DLL 逆向：`out/sparse_exports.txt`、`out/round27_sparse.txt`、`out/round28_sparse.txt`
- 探针（已停用，仅存档）：`scripts/sparse_dll_probe.py`
- 原型：`scripts/sim_proto.py`
- 基准：`scripts/sim_bench.py`

## 6. 性能设计（2026-10-19）

原型基准（Python/SciPy，单线程）：

| 场景 | 优化前 | 优化后 | 加速 |
|---|---|---|---|
| RC 5ms（500 步，BE） | 63.0 ms | 3.5 ms | **17.9×** |
| 50 节点 RC 梯形网络，100 步 | 65.2 ms | 4.8 ms | **13.6×** |

优化点：

1. **线性瞬态复用 LU 分解**：A 只与 dt/元件值有关、与状态无关；首步分解后，后续只重建 RHS
   （`_assemble_z`），不再构造矩阵/分解。
2. **分解缓存键**：矩阵 CSC 的 `indptr/indices/data` 字节比较；非线性 Newton 改变 A 时自动重新分解。
3. **梯形积分首步特殊处理**：首步 BE，第二步重建 trap 矩阵（`2C/dt`），之后复用。
4. **残差检查**：每次求解一次稀疏 matvec，成本可接受；生产环境可降频或采样。
5. **节点限幅**：二极管/BJT/MOS 的 Newton 步长限制在 0.2 V，改善收敛（不增加线性求解次数上限）。

多核 / GPU 立场：

- **多核**：按**任务级**并行（分析 × 求解器、AC 频点、Monte Carlo/参数扫描），与
  `sim-api-design.md §3.3` 一致；单次瞬态内部是串行时间步，不做线程并行
  （时间依赖链 + Python/GIL）。
- **GPU**：电路矩阵规模小、稀疏且 LU 有强依赖；kernel 启动/传输开销大于收益，
  SuperLU GPU 只在超大矩阵有意义。**暂不投入**（与调研结论一致）。
- **下一步性能项**：稀疏模式预构建（只更新 `data`）、自适应步长（LTE 控制）、
  TS/原生端口（消除 Python 逐元素开销），以及 AC 频点的进程池并行。

### 6.1 TS 纯实现 vs Python/SciPy（2026-10-19 实测）

同规模梯形网络（n 个 R/C 节点）：

| n | TS 装配 | TS 稠密 LU（替身） | Python/SciPy 稀疏（装配+LU+求解） |
|---|---|---|---|
| 100 | ~0.0 ms | 6.3 ms | 1.54 ms |
| 400 | ~0.1 ms | 23.7 ms | 3.78 ms |
| 1000 | ~0.1 ms | ~300 ms（外推 O(n³)） | 10.64 ms |

结论：

- **TS 做解析/装配完全够用**（1000 节点 0.1 ms 级）；
- **纯 JS 的 LU 是瓶颈**（稠密替身已慢 4–30×，稀疏纯 JS 更不划算）；
- 产品若坚持 TS 前端：求解器用 **WASM（SuiteSparse/Eigen）** 或原生 addon，
  纯 JS 只适合极小电路；当前原型用 Python/SciPy 是合理的中间态。

### 6.2 多任务预测与调度（原型）

`scripts/sim_schedule.py`：用少量实测点拟合成本模型，再用 LPT 做多任务排程。

```
DC   : t = -0.63 + 0.014931 * n
TRAN : t =  3.52 + 0.0116 * steps + 0.001097 * n * steps
```

留出样本验证误差：DC 7.8–10.3%，TRAN 6.6–6.7%（平均 7.9%）。
混合批量（8 个分析）在 4 worker 上的预测 makespan **143.6 ms**；
最大作业决定下界，LPT 已把它单独放一个 worker。

下一步：接进程池/任务池，把预测 makespan 与实测对比；
若目标是 Monte Carlo/良率预测，同一调度器可直接复用（每个随机样本一个 job）。
