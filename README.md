# TINA-RE — TINA-TI 二进制静态分析工作区

TINA-TI（DesignSoft TINA 9 - TI）脱壳镜像的独立静态分析成果。与 SpiceHappy 主仓库分离，
方便集中归档；分析结论成熟后由人工挑选并入 SpiceHappy。

- 上游目标：`D:\WorkDesigns\3_WorkTools\SpiceHappy-tina-re\re\tina_unpacked_static.exe`
  （ASProtect 脱壳镜像，工作树 `feat/tina-static-extract`）
- 工具链：Ghidra 12.1.4（headless，无 GUI）+ 本机 `ghidra-mcp` 后端
- 本仓库不复制模型/密文等资产，只放分析产物与脚本

## 目录

```
TINA-RE/
├── README.md                 ← 本文（索引 + 状态）
├── docs/
│   ├── findings.md           ← 汇总发现（当前主文档）
│   └── legacy-first-pass.md  ← 2026-10-16 首轮快照（已被 findings.md 覆盖）
├── out/                      ← Ghidra headless 原始输出（证据）
│   ├── gap_decompile_output.txt   (round 1: TEA 加解密/分发器）
│   ├── round2b.txt                (round 2: 编排/SetKey/模式引擎/类块)
│   └── scan_classes.txt           (round 3: 类扫描，脚本修复后重跑)
├── scripts/
│   ├── fix-pe.py             ← 修复 rebuild_pe.py 节表字段互换 bug（生成可分析镜像）
│   └── ghidra-headless/      ← Ghidra headless 脚本
│       ├── GapDecompile.java
│       ├── CleanupDecomp.java
│       └── ScanClasses.java
└── targets/                  ← 修正版镜像（*.exe 已 gitignore，用 fix-pe.py 生成）
```

## 状态速览（2026-10-16）

| 项 | 状态 |
|---|---|
| 镜像加载修复（rebuild_pe.py bug） | ✅ 已修，Ghidra 函数识别 8456 → 18514 |
| TEA 变体加解密转录验证 | ✅ 逐位吻合（tea_variant_test.py 证实） |
| 解密入口/工厂/创建链/SetKey/init | ✅ 反编译完成（docs/findings.md §4） |
| 模式引擎（case0/1/2 链） | ✅ 结构已明确，`pt=ct^ct_prev^G(ct)` 的 `ct^ct_prev` 项来源确认 |
| 0x17112c「直调」方向 | ❌ 作废（Delphi 单元初始化桩） |
| 类族全表（TCipher_* / THash_*） | ✅ 19 + 21 个类，VMT 布局与槽位映射完成 |
| TCipher_Blowfish 实现 | ✅ 加密/解密/InitKey/π 常数全部落实（§8.2） |
| HAVAL 系列（G 候选层） | ✅ Init/Update/Final/填充/版本字节/摘要长度全解（§8.3） |
| mode 引擎全 8 模式 + 哈希递推生成器 | ✅ 完整 C（§9.1/§9.2）；LCG 定位（§9.6） |
| G 假设对撞（标准 Blowfish） | ✅ 已排除（0 命中，含字节序变体，§9.6） |
| Ghidra 项目符号命名（44 个） | ✅ 持久化，可直接按名导航（§10） |
| 管线接线图（全局变量/调用链） | ✅ 综合成图（§10） |
| 管线类/VMT 定案（Blowfish + 委托链） | ✅ 实例 VMT=0x569E88；委托(obj+0xC)→THash_RipeMD256（§11） |
| RIPE MD-256 实证 | ✅ 二进制 p-code 模拟 + 官方向量 + Python 参考实现三重验证（§11） |
| G 对撞 | ✅ **已破解：标准 Blowfish-CBC**（key=RMD256(40B blob)，IV 常量）——"G(x)=D(x)^x" 是其等价变形 |
| 全库静态解密 | ✅ 388/388 加密库解密成功（485 库=388 加密+97 明文；对 ks_ground 地面真值逐字节验证） |
| 工具 | ✅ `scripts/tina_static_decrypt.py`（单文件/`--all` 批量） |
| Z3 路线文档 | ✅ docs/z3-route.md（G 已解决，作为方法论存档） |
| Phase 3 引擎测绘（round 15-17） | ✅ 区域函数清点（18594）+ 两处归属修正（§14）；路线见 SpiceHappy `docs/engine-extraction.md` |
| Phase 3 M2 求解调用链（round 18-22） | ✅ 运行时栈 + 静态对账：AC 全链路 + 装配段（§15）；指针表 RVA 0x1BDAF20 |
| SPICELIB 模型来源分层 | ✅ 485 库扫描：PSpice 语法为主、TINA 私有仅 6 个文件（§16） |
| 解密算法核验（TPS40055_TRANS 异常） | ✅ 再加密恒等 + 与 TINA 文本前 4120B 一致；尾部为文件自身不透明区（§17） |

## 快速验证（回归自检，离线）

依赖：Python 3.10+、`pip install pycryptodome`；TINA-TI 安装在默认路径（读取 SPICELIB）。

```powershell
python tests/verify_decrypt.py
```

预期输出：7 项全部 PASS（RMD256 官方向量 ×3、二进制压缩块向量 ×2、DAC882X 地面真值对比、
全库 388 加密 + 97 明文扫描），末尾打印 `RESULT: ALL PASS`。

> 维护副本：`tina_static_decrypt.py` / 验证脚本的**正式维护位置在 SpiceHappy 仓库 `re/`**
> （`SpiceHappy-tina-re` 工作树，分支 `feat/tina-static-extract`）；本仓库保留分析档案与同一份脚本以便复现。

## 复现

> **运维注意（2026-10-17 实锤）**：`ghidra-mcp.cmd stop` 用 taskkill 强杀后端时，JVM 内的自动分析
> 结果**不会保存**（项目只剩手工创建的函数，如本例 18514 → 76）。需要分析覆盖时，用 headless
> 补跑一次（会自动保存）：
>
> ```powershell
> & "D:\MyPrograms\ghidra_12.1.4_PUBLIC\support\analyzeHeadless.bat" `
>     "D:\MyPrograms\ghidra-mcp\projects" "tina_unpacked_fixed_ghidra_mcp" `
>     -process "tina_unpacked_fixed.exe"
> ```
>
> 或对 ghidra-mcp 后端优雅关闭（避免 taskkill /F）。

```powershell
# 1) 生成修正版镜像
python scripts/fix-pe.py
#    -> targets/tina_unpacked_fixed.exe

# 2) 导入 Ghidra 并分析（analyzeHeadless，或经 ghidra-mcp 后端）
$env:JAVA_HOME = "D:\MyPrograms\jdk-21.0.12.1"
& "D:\MyPrograms\ghidra_12.1.4_PUBLIC\support\analyzeHeadless.bat" `
    "D:\MyPrograms\ghidra-mcp\projects" "tina_unpacked_fixed_ghidra_mcp" `
    -import "targets\tina_unpacked_fixed.exe"

# 3) 在已分析项目上跑脚本（-noanalysis 秒开）
& "D:\MyPrograms\ghidra_12.1.4_PUBLIC\support\analyzeHeadless.bat" `
    "D:\MyPrograms\ghidra-mcp\projects" "tina_unpacked_fixed_ghidra_mcp" `
    -process "tina_unpacked_fixed.exe" -noanalysis `
    -scriptPath "scripts\ghidra-headless" -postScript "ScanClasses.java"
```
