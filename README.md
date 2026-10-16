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
| 管线串联方式（Blowfish×Haval 组合） | 🔄 下一步 |

## 复现

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
