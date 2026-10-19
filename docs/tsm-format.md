# TSM（OBSS 宏容器）格式与解析工具

> 工具：`scripts/tsm_parse.py`（纯静态，离线）
> 结论先说：**TSM 不是加密格式**，它是明文 OBSS 容器；不需要解密，只需要解析。

## 1. 容器结构（实测）

### 1.1 文件头

```
0x00  "OBSS"                4 字节魔数
0x04  1a 01                 版本字节
0x06  ...                   头部字段（混合 1/2/4 字节整数）
      "Spice Macro"         类型：Spice Macro / Schematics Macro …
      "V1.00"               版本
      "98/01/15"            日期
      "*TINA Device Editor …"  创建者（旧版本带前导 *）
      "Copyright 1997 DesignSoft, Inc."
```

字段多为“1 字节长度（含结尾 0）+ 文本 + 0x00”。类型字符串常见两种：

- `Spice Macro`：含 SPICE 网表文本（如 UA741、CAPM1、LAPLACE、XUJT）；
- `Schematics Macro`：原理图/符号宏（多数没有网表，如 Barrel Jack、HC4046）。

### 1.2 文本记录格式

```
00 00 00 00 00 | len（含结尾 0）| text（len-1 字节 ASCII）| 00
```

要点：**第一条记录的结尾 0 与下一条记录开头的 5 个 0 重叠**（即记录是连续链）。
例：

```
...\x00 \x00\x00\x00\x00 | 1b | ".subckt UA741    1 2 3 4 5" | \x00 ...
```

解析器按这个规则逐条取文本；记录之外的字节是符号图形/坐标等二进制数据，本工具不解。

## 2. 用法

```powershell
# 摘要（类型/版本/日期/创建者/文本块/是否含网表）
python scripts/tsm_parse.py "C:\...\MACROLIB\UA741.TSM"

# 打印全部文本记录
python scripts/tsm_parse.py ...\UA741.TSM --text

# 只打印 .SUBCKT … .ENDS 网表块
python scripts/tsm_parse.py ...\UA741.TSM --netlist

# 导出网表
python scripts/tsm_parse.py ...\UA741.TSM --netlist --out UA741.cir

# 结构化输出
python scripts/tsm_parse.py ...\UA741.TSM --json

# 批量摘要一个目录
python scripts/tsm_parse.py --dir "C:\...\MACROLIB"
```

## 3. 实测覆盖（安装目录 34 个 TSM）

| 文件 | 类型 | 可提取网表行数 |
|---|---|---|
| UA741.TSM | Spice Macro | 32 |
| HC4046.TSM | Schematics Macro | 16 |
| XUJT.TSM | Spice Macro | 11 |
| CAPM1.TSM | Spice Macro | 9 |
| LAPLACE.TSM | Spice Macro | 3 |

其余 29 个是原理图/符号宏（没有 `.SUBCKT`），解析器仍会报告文本块
（注释、引脚名、VHDL 描述等）。

## 4. 边界

- 只解析**文本记录**；符号图形/坐标等二进制段不解析。
- 文本长度字段为 1 字节（≤250），现有 34 个文件均未超出。
- 不做解密（TSM 没有加密）；加密的只有 `.lib`（见 `docs/decrypt-usage.md`）。
- 若未来版本改变容器结构，先跑 `--dir` 看 `blocks=0` 是否异常，再对照本文档排查。
