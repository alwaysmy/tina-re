# TINA 加密模型库解密 —— 使用说明

> 工具：`scripts/tina_static_decrypt.py`（纯静态，离线，不需要 TINA 运行）
> 分析依据：`docs/findings.md` §11–§18（算法、验证、加载器实证）

## 1. 支持什么、不支持什么

| 文件类型 | 是否加密 | 本工具 |
|---|---|---|
| `.lib`，前 21 字节为 `<Encrypted Library>\n\r` | ✅ 加密 | **解密**（这就是 TINA/SPICELIB 的加密模型库） |
| `.lib`，无该头 | ❌ 明文 | 原样复制（提示 `[plain]`） |
| `.TSM`（宏容器，OBSS 格式） | ❌ 不加密 | **不需要解密**；用 `scripts/tsm_parse.py` 解析（见 `docs/tsm-format.md`） |
| `.TSC`（原理图） | ❌ 不加密 | 不处理 |
| `.IND` / `.TLD`（库索引/元数据） | ❌ 明文 | 不处理 |

一句话：**只有带 `<Encrypted Library>` 头的 `.lib` 需要解密**。新拿到的宏模型如果本身是 `.TSM`，
它已经是明文容器，不存在“解密”这一步。

> 算法补充：尾部不满 8 字节的块按 DEC 引擎的 **CFB8 收尾**
> （`P* = C* XOR E(上一密文块)`）。不能“原样直通”——那会毁掉部分库尾部的 `.ENDS`
> （2026-10-19 修正，DAC882X 地面真值因此从“差 2B”变为逐字节一致）。

## 2. 先判断一个文件要不要解

```powershell
python scripts/tina_static_decrypt.py --check "C:\...\SPICELIB\TPS40140.LIB"
```

输出示例：

```
...\TPS40140.LIB: 57258 bytes, encrypted=True
  first line: b'*$'
```

`encrypted=False` 就说明不用解（明文或其它容器）。

## 3. 单个文件

```powershell
# 默认输出到同目录（同名）
python scripts/tina_static_decrypt.py "C:\...\SPICELIB\TPS40140.LIB"

# 指定输出文件
python scripts/tina_static_decrypt.py --out "D:\Models\TPS40140.lib" "C:\...\SPICELIB\TPS40140.LIB"
```

## 4. 批量

```powershell
# 默认扫 SPICELIB，输出到仓库的 decrypted-local/
python scripts/tina_static_decrypt.py --all

# 指定输出目录
python scripts/tina_static_decrypt.py --all "D:\Models\decrypted"

# 指定库目录
python scripts/tina_static_decrypt.py --dir "C:\...\SPICELIB" "D:\Models\decrypted"
```

批量模式会输出 `done: encrypted=N plaintext=M -> 目录`。

## 5. 自检 / 验证

```powershell
python tests/verify_decrypt.py
```

预期：

- 8 项全部 `PASS`，末尾 `RESULT: ALL PASS`；
- 全库扫描行：`encrypted=388 plain=97 非文本=4`；
- 配平行：`SUBCKT/ENDS 配平: mismatches=1`（仅 `TPS40055_TRANS.LIB` 孤例）。

“非文本=4”是已知例外：3 个是版权注释里的 NBSP（0xA0），1 个是
`TPS40055_TRANS.LIB`（文件尾部损坏，模型文本已从示例 `.TSC` 内嵌副本恢复，
见 `scripts/recover_from_capture.py`）。

## 6. 新模型怎么处理

- **TI/DesignSoft 给的 `.lib`（带加密头）** → 直接按第 3/4 节跑，秒级完成。
- **`.TSM` 宏** → 不需要解密；它是 TINA 的宏容器，里面是明文。
  用 `scripts/tsm_parse.py` 解析：`--netlist` 导出 `.SUBCKT … .ENDS`，
  `--json` 输出结构化结果，详见 `docs/tsm-format.md`。
- **PSpice/LTspice 的加密模型**（头不是 `<Encrypted Library>`）→ 本工具不处理，
  走 SpiceHappy 的统一入口 `decrypt`（自动识别格式并路由到对应 provider）。

## 7. 依赖

- Python 3.10+
- `pip install pycryptodome`
- Windows / Linux 均可；不需要安装 TINA，不需要 Frida

## 8. 已知边界

- **文件损坏**：`TPS40055_TRANS.LIB` 第 515 块（明文 4120 字节）之后是随机数据。
  这不是解密算法问题（Ghidra 已证实加载器就是单密钥 CBC、整文件一次解密），
  是该文件自身损坏/填充。模型文本可用 `scripts/recover_from_capture.py` 从运行时副本恢复。
- **未来版本**：如果 TINA 换了算法，`--check` 仍会识别头，但 `verify_decrypt.py` 的
  官方向量/地面真值会失败——那时需要重新做一次密钥/算法分析
  （密钥常量 RVA 0x58FAD0、加载器 `FUN_0098f420`）。
- **`.TSM` 解析**：已由 `scripts/tsm_parse.py` 支持（`--netlist/--text/--json`）；
  但只解析文本记录，符号图形/坐标等二进制段不解析（见 `docs/tsm-format.md`）。

## 9. SpiceHappy CLI（集成入口）

```powershell
# 统一入口：自动识别 TINA / PSpice / LTspice 格式
npx tsx src/cli/index.ts decrypt "C:\...\TPS40140.LIB" -o "D:\Models\TPS40140.lib"

# TINA 专用：按型号（在 SPICELIB 里找）
npx tsx src/cli/index.ts tina-decrypt TPS40140 -o "D:\Models\decrypted"

# TINA 专用：直接给 .lib 路径（不需要 TINA 安装）
npx tsx src/cli/index.ts tina-decrypt "C:\...\LM4755.LIB" -o "D:\Models\decrypted"

# 批量：一次 Python 调用处理整个 SPICELIB（约 6 秒）
npx tsx src/cli/index.ts tina-decrypt all -o "D:\Models\decrypted"
```
