# SPICELIB 模型来源与兼容性分层（2026-10-17）

> 问题：TINA 捆绑的这些 SMPS 模型，是 TINA 专用模型，还是标准 PSpice 模型加少量调整？
> 方法：对 485 个静态解密后的 `.lib` 做全量扫描（头部声明、语法记号、私有器件、子电路依赖、文本完整性）。
> 复现：`python D:\WorkDesigns\3_WorkTools\TINA-RE\scripts\survey_spicelib.py`

## 1. 结论

**绝大多数是"标准 PSpice 语法（行为级 ABM）的网表，但由 TI 针对 TINA 生成/验证"**，
不是一种独立的 TINA 模型格式；真正的 TINA 私有模型只占少数（约 6 个文件 + DesignSoft 自带的
`TINA_SMPSM.lib`）。

可以分成三层：

| 层 | 特征 | 规模（实测） | 能否离开 TINA |
|---|---|---|---|
| **A. 自包含 PSpice 风格** | `.SUBCKT`/`.MODEL` + E/G 行为源（`VALUE={IF/TABLE/POLY}`），数字原语在文件内用 ABM 定义 | 485 个库中绝大多数；13 个控制器库完全自包含 | 原则上可移植（需处理 ABM/VSWITCH 语法差异） |
| **B. 依赖 TINA 全局 SMPS 库** | 实例化 `COMP2INPAND`/`COMPGNDREF`/`STDOPAMP`/`AMPLIGNDREF`/`RSFFLOP_P` 等，定义在 `TINA_SMPSM.lib` | 交叉库依赖 9 个名字、约 30 处实例 | 需连同 `TINA_SMPSM.lib` 一起用；跨引擎仍受 C 类限制 |
| **C. TINA 私有器件** | `Y` 器件 + `.MODEL _Comp COMP` / `AMPLI` 等 TINA 引擎专有模型 | 6 个文件 | ❌ 只能由 TINA 引擎执行 |

## 2. 实测数据

### 2.1 头部声明（485 个唯一库）

| Simulator 字段 | 数量 |
|---|---|
| TINA / TINA-TI 系（含版本号变体） | ≈ 440 |
| **PSPICE**（原样收录的 PSpice 模型） | 10 |
| 无声明 | 35 |

Model Type：`TRANSIENT` 272、`ALL IN ONE` 87、`AVERAGE` 50、`TINA` 28、`PSPICE` 3、
`TRANSIENT & AVERAGE` / `LINE/LOAD TRANSIENT` / `PFM` 等少量。

### 2.2 语法记号覆盖率（PSpice 风格）

| 记号 | 覆盖 |
|---|---|
| `.SUBCKT` | 484 / 485 |
| `.MODEL` | 457 / 485 |
| `VALUE`（行为源） | 453 / 485 |
| `IF (` | 219 / 485 |
| `TABLE` | 126 / 485 |
| `POLY(` | 91 / 485 |
| `.PARAM` | 213 / 485 |

### 2.3 数字原语是"内联 + 标准行为源"，不是 TINA 器件

`TPS40140.LIB` 自带 80 个子电路，例如：

```spice
.SUBCKT NAND2_BASIC A B Y
E_ABMGATE YINT 0 VALUE {{IF(V(A) > 2.5 & V(B) > 2.5, 0, 5)}}
RINT YINT Y 1
CINT Y 0 1n
.ENDS
```

即：TI 用 PSpice 的 E 源 + VALUE 表达式实现门电路，文件自包含，不依赖 TINA 内置数字库。

### 2.4 子电路依赖（27,639 个 X 实例）

- 本地解析：绝大多数；
- 跨库依赖（9 个名字）：`COMP2INPAND`、`SW`、`COMPGNDREF`、`STDOPAMP`、`AMPLIGNDREF`、
  `RSFFLOP_P`、`FFLOPX1`、`COMP3INPAND`、`COMP4INPAND`；
- 任何库中都没有定义的 12 个名字：`_COMP`、`VCO_`、`SINVCO`、`_CNTN`、`MUXES`、`CHANNELS`、
  `DB`、`DT`、`BC`、`MIN`、`IDOPAMP`、`LM2852_BUCK_BLOCK_COUT` —— 前几个正是 TINA 内置的
  COMP/VCO/数字原语，只能由 TINA 引擎解析。

### 2.5 TINA 私有语法的文件（C 类）

`Y` 器件（第 2 个字符起为节点，模型名以 `_` 开头）：

```spice
Y1 In1+ In1- In2+ In2- Out Gnd  _Comp
.Model _Comp COMP (GAIN={GAIN} RIN={RIN} ...)
```

出现文件（6 个）：`TINA_SMPSM.lib`（DesignSoft 1996-2006 自有 SMPS 库）、
`TPS61000.lib`、`TPS61020_AVG.lib`、`TPS61020_TRANS.lib`、`TPS61025_TRANS.lib`、
`TPS40055_TRANS.LIB`。

### 2.6 变体命名

`*_TRANS` 250 个、`*_AVG` 51 个、`ALL IN ONE` 87 个；另有 TINA 专属命名
`LM10504_TINA_TRANS_LINE/LOAD/PFM`。说明 TI 针对不同分析类型打包了不同模型变体，
而不是"每个器件只有一个模型"。

### 2.7 文本完整性

解密后 481/485 文本干净；另外 3 个"非 ASCII"文件其实是版权注释里的 NBSP（0xA0），不是解密错误。

唯一真实异常：`TPS40055_TRANS.LIB`——明文前 4120 字节正常（与 TINA 运行时文本逐字节一致），
第 515 块（字节 4120）之后是 2863 字节高熵数据。Ghidra 已确认库加载器（`FUN_0098f420`）
对整文件只做一次 BlowFish-CBC 解密、无分段/二次密钥，故该尾部就是文件自身的非文本内容
（损坏或随机填充），不是解密算法差异。完整模型文本已从示例 `.TSC` 内嵌副本恢复为
`decrypted-tina/TPS40055_TRANS.recovered.lib`（6982 B / 202 行）。详见 TINA-RE `docs/findings.md` §17/§18。

## 3. "调整点"具体是什么

1. **生成目标**：头部 `Simulator: TINA` + `Simulator Version: x.y.z SF-TI`（TI 用 TINA 流程生成/验证）。
2. **模型变体**：同一器件提供 TRANSIENT / AVERAGE / ALL-IN-ONE / LINE / LOAD / PFM 等版本，
   默认参数按 TINA 仿真场景调过。
3. **封装方式**：数字/行为块内联为子电路（A 类），或改为调用 TINA 的 `COMP`/`VCO` 原语（C 类）。
4. **接口**：`.SUBCKT` 引脚顺序与 TINA 符号一一绑定，直接拿到别的引擎要重排引脚。
5. **少数原样收录**：10 个 `Simulator: PSPICE` 的库（如 `UCC28C42_STARTUP.lib`、`LM3886.lib`、
   `LMP8480` 系列、`TPS7A4501_TRANS.LIB`）就是 TI/厂商的 PSpice 模型，未做 TINA 化。

## 4. 对 SpiceHappy 的意义

- 不能把 `decrypted-tina/` 整体当作"标准 PSpice 库"直接喂 ngspice/LTspice：
  A 类需要 ABM 语法转换（`VALUE={IF(...)}`、`VSWITCH`/`SW` 模型），B 类要带 `TINA_SMPSM.lib`，
  C 类无法转换。
- 做跨引擎对比时，SMPS 模型应优先用**原厂 PSpice 模型**（TI 官网提供）或直接用 TINA 引擎
  （`tina-run`），不要把 TINA 版模型当作"标准答案"。
- 反过来，A 类模型的拓扑与行为级结构可读、可复用，是理解 TI 控制器行为的好材料。
