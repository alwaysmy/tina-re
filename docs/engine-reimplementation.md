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

- 网表子集：R / V / I / C / L / E（VCVS）/ G（VCCS）/ F（CCCS）/ H（CCVS）/ D（二极管）；
  理想运放 = 高增益 VCVS；
- 分析：DC 工作点（含 Newton 非线性）、后向欧拉瞬态、AC 小信号；
- 求解：SuperLU（COLAMD + 默认部分选主元），每次求解做残差检查，奇异矩阵给出明确错误；
- 自测（8 项全 PASS）：

```
PASS DC divider
PASS current source
PASS RC transient
PASS RL transient
PASS inverting op-amp
PASS AC RC low-pass
PASS zero-diagonal robustness   ← TINA 的不选主元路径会在此返回 102
PASS diode DC vs reference      ← Newton-Raphson + brentq 对拍（误差 < 1e-6 V）
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
| M3b | BJT（Ebers-Moll）、MOS Level 1 + 收敛增强 | 与 ngspice 对拍整流/共射/共源 |
| M4 | 瞬态步长控制、AC 扫频输出、噪声（可选） | 与 ngspice `.ac/.tran` 对拍 |
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
