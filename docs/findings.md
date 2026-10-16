# TINA 镜像 Ghidra 静态分析发现（汇总）

> 2026-10-16 · Ghidra 12.1.4 headless（无 GUI）+ GhidraMCP
> 镜像：`tina_unpacked_static.exe`（经 §1 修复后分析）
> 地址约定：RVA（= 文件偏移，镜像基址 0x400000）；Ghidra 地址 = RVA + 0x400000
> 原始证据：`../out/gap_decompile_output.txt`（round 1）、`../out/round2b.txt`（round 2）

---

## 1. 镜像加载修复：rebuild_pe.py 节表字段互换 bug【重要】

**症状**：`tina_unpacked_static.exe` 用标准 PE 加载器（Ghidra/IDA）加载后代码区错位——
RVA 0x17112c 读出全零、entry 读到指针表；Ghidra 仅识别 **8456** 个函数。

**根因**：`SpiceHappy-tina-re/re/rebuild_pe.py` 第 38 行：

```python
struct.pack_into('<II', data, sec_off + idx*40 + 16, va, rawsz)  # 注释同样写反
```

PE 规范为 `+16 = SizeOfRawData`、`+20 = PointerToRawData`；脚本把 `va` 写进 +16、
把对齐后的 `VirtualSize` 写进 +20，**两个字段整体互换**。脚本末尾的验证只用 capstone
按文件偏移反汇编、不经过节表，因此从未暴露。文档中"IDA/Ghidra 可直接载入"的说法不成立。

**修复**：交换每节 +16/+20 两个 dword（其余字段本来就正确）。
→ `scripts/fix-pe.py`，生成 `targets/tina_unpacked_fixed.exe`。

**修复后**：10 个节 `PointerToRawData == VirtualAddress`（真正的平铺镜像），
Ghidra 识别 **18514** 个函数，RVA 0x17112c 读到 `55 8B EC 33 C0...`（与文件一致），
自动识别 Delphi 编译器规格（borlanddelphi）。

**建议**：上游修复 rebuild_pe.py 并重新生成；本仓库修正副本可直接授权用于分析。

---

## 2. 对既有笔记的修订

| # | 既有说法 | 实测结论 |
|---|---|---|
| 1 | "函数头在 0x17112c，可直调解密函数" | ❌ **作废**。0x57112c 是 Delphi 单元初始化桩：SEH 框架 + `INC [0xA6B128]` 计数器 + `PUSH 0x571158; RET` 尾跳转；唯一引用来自初始化表（RVA 0x609FD8）。当时"栈上返回地址"是 Delphi 无帧指针回溯的伪帧 |
| 2 | "call [密码器 vtable+0xc]（TEA 解密）" | +0xc 是**流编排** `FUN_005597f8`（见 §4.7），不是 TEA 本体；加密/解密在 +0x10/+0x14（0x16cf5c / 0x16cfb4） |
| 3 | "解密调用 3 参数（流数据/Result槽/剩余长度）" | 实际 5 参数：`(self, 源流, 目标流, 方向=1, 总长度)`，与 `FUN_005597f8` 签名吻合 |
| 4 | "0x15c6f4 起 = 密钥扩展，待逆向" | `0x55c6f4` 只是 6 字节全局 getter（`MOV EAX,[0xA1A0BC]; RET`）。密钥处理在 SetKey 的 **THash 子对象**链（§4.5） |
| 5 | "算法=Blowfish 命名 / 库真身=DEC" | 类名实证：`TCipher_TEA`、`THash`（DEC 系列早期命名风格一致）。.lib 管线实际用哪个类待 round 3 扫描确认 |

---

## 3. TEA 变体：转录验证通过 ✅

`tea_variant_test.py` 的转录与 Ghidra 反编译**逐位吻合**（含与标准 TEA 的差异点）：

```c
// RVA 0x16cf5c  加密（v = param_2[0..1]; k = [obj+0x38]; rounds = [obj+0x40]）
do {
    sum += 0x9E3779B9;                                   // iVar5 - 0x61c88647
    v0 += ((((v1 << 4) + k0) ^ v1) + sum) ^ ((v1 >> 5) + k1);
    v1 += ((((v0 << 4) + k2) ^ v0) + sum) ^ ((v0 >> 5) + k3);
} while (--rounds);

// RVA 0x16cfb4  解密（sum 从 δ*rounds 递减，镜像逆运算）
```

- δ = 0x9E3779B9；块 8B；密钥 16B @ obj+0x38；rounds @ obj+0x40（clamp[16,32]，`FUN_0056cef8`）。
- 相关槽位（TCipher_TEA 块 +0x08）`FUN_0056cf18` = 参数查询（块=8 / 轮=16..32）。

---

## 4. 解密链条（真实 C 反编译摘要）

### 4.1 解密入口 `FUN_00571084`（RVA 0x171084）

```c
void FUN_00571084(int container, undefined4 src, undefined4 dst, undefined4 size)
{
    seed = PTR_DAT_00a64318;                       // 全局 8B 种子缓冲（指针）
    *(u32*)seed       = *(u32*)(container + 0x40); // [容器+0x40] dword0
    *(u32*)(seed + 4) = *(u32*)(container + 0x44); // [容器+0x44] dword1
    ...
    cipher = FUN_00570bfc(container);              // 工厂（惰性）
    (**(code**)(*cipher + 0xc))(cipher, src, dst, 1, size);  // 流编排，方向=1
    ...
    *(u32*)seed = 0; *(u32*)(seed + 4) = 0;        // 种子用完清零
}
```

### 4.2 工厂 `FUN_00570bfc`（0x170bfc）+ 邻居 `FUN_00570c2c`（0x170c2c）

- `[容器+0x38]` 惰性创建密码器（经 `FUN_00570c2c` → `FUN_0056a8b0` 的对象 → `FUN_0056acd8` 创建链）。
- 工厂把 **模式字节 `[容器+0x3c]` → `[密码器+0x14]`**。

### 4.3 创建链 `FUN_0056acd8`（0x16acd8）

- 基类构造 `FUN_00559c78` → `FUN_00559698`（存引用到 `obj+0xc`）。
- `FUN_0055c6f4()` = 全局 getter → `obj+0x1C`。
- 虚调用 `vt+0x24` 取尺寸 → `obj+0x20`（密钥尺寸）/`obj+0x24`（块尺寸）。
- 分配 4 条缓冲：`obj+0x30`、`obj+0x34`、`obj+0x2C`（块尺寸）、`obj+0x38`（密钥缓冲，键尺寸）。
- 虚调用 `vt+0x3c`（初始化，**析构里同槽位被调用**）；`param_3 != 0` 时 `SetKey`。

### 4.4 SetKey `FUN_0056adfc`（0x16adfc）— 密钥处理链

```
密钥 Delphi 串 → FUN_0056afc4(密码器) 取 THash 子对象（obj+0x18，惰性创建）
   → [THash.vt+0x20]()                 // 复位/开始（stub: FUN_0055c9ac → FUN_0055c9b8(x,1)）
   → [THash.vt+0x24](ptr, len)         // 喂入密钥（THash 基类实现为空 stub → 实际类应覆盖！）
   → [THash.vt+0x28]()                 // 结束
   → [THash.vt+0x30]() → 摘要长度      // 实际 stub 返回 0（基类）
   → 摘要指针 [THash.vt+0x2c]()        // stub → FUN_0055b320
   → 密码器 [vt+0x34](密钥指针, 长度)  // 装订密钥
   → FUN_0056b034（模式引擎初始化）
   → [vt+0x38]() / [vt+0x1c](0, 1)
```

> ⚠️ 导出：THash 基类槽位多为空 stub，**具体哈希类（覆盖 +0x20..+0x30）尚待定位**
> —— round 3 类扫描目标；这层即"密钥扩展/摘要 → 装订"的落点。

### 4.5 init `FUN_0056d010`（0x16d010）

```c
FUN_0056ab78(obj, &len);
FUN_004032b8(src, obj[0xe], len);   // memcpy(密钥 → [obj+0x38], len)   ✓ 与笔记一致
FUN_0056cef8(obj, obj[0x10]);       // setRounds(clamp[16,32])          ✓ rounds=[obj+0x40]
(**(code**)(*obj + 0x20))(obj, param_4);
```

### 4.6 模式引擎 `FUN_0056b034`（0x56b034）★

```c
switch ((char)obj[5]) {          // [obj+0x14] = 模式（来自 [容器+0x3c]）
case 0:  // out = in ^ feedback;  [obj.vt+0x2c](out);  feedback ^= out   ← 累积异或链！
case 1:  // out = in ^ feedback;  [obj.vt+0x2c](out);  feedback = out
case 2:  // 逐字节 / CFB 风格
}
```

- 组合原语 `FUN_0055a854` = **纯内存 XOR**（56 字节，DWORD 对齐）。
- **case 0 的 `feedback ^= out`（相邻密文块累积异或）即第 32 轮经验模型
  `pt_b = ct_b ^ ct_{b-1} ^ G(ct_b)` 中 `ct_b ^ ct_{b-1}` 项的来源结构**；
  块变换 `[vt+0x2c]`（解密方向等价 `ct ^ G(ct)`）→ G 的构造应在此槽位的实现里。

### 4.7 流编排 `FUN_005597f8`（0x1597f8，vt+0xc）— 5 参数签名来源

```c
void FUN_005597f8(self, inStream, outStream, char dir, int size) {
    if (size < 0) size = [inStream.vt+0]();       // 取流长度
    [self.vt+0x00](self, dir);                    // Begin（= SetFlag 风格）
    buf = malloc(0x1000);
    if (dir == 3) {                               // 顺序流：只读+处理
        while (size > 0) { n = [inStream.vt+0xc](inStream, buf, min(size,0x1000));
                           [self.vt+0x08](self, buf, n, 3); size -= n; }
    } else {                                      // 定位读 + 定位写（双流模式）
        while (size > 0) { n = [inStream.vt+0xc](inStream, buf, chunk, pos);
                           [self.vt+0x08](self, buf, n, dir);
                           [outStream.vt+0x10](outStream, buf, n, pos); ... }
    }
    [self.vt+0x04](self, dir);                    // End
}
```

- 配套：`FUN_005599c0`（vt+0x10，流对象包装并转调 +0xc）、
  `FUN_00559b58`（vt+0x14，**Delphi 字符串版本**：`func_0055aa48`/`0055a92c` 处理字符串）、
  `FUN_00559af0`（vt+0x18，单缓冲：Begin→Process(+8)→End）。
- 4KB 分块（0x1000）——与 tina_export 侧"分块释放"现象一致。

### 4.8 其他已证实的槽位

| 地址 | 槽位/角色 | 语义 |
|---|---|---|
| 0x16ab5c | vt+0x00 | `SetFlag(i, bool)`：`[obj+0x3C]` 位操作 |
| 0x16ac68 | vt+0x04 | 块/IV 装载：拷贝到 `obj+0x30` → 复制到 `obj+0x34`（链反馈缓冲）→ SetFlag(1,1)；含 `[vt+0x2c]` 调用 |
| 0x16aeb4 | vt+0x1c | 比较/复制块缓冲（`FUN_0055a838` + memcpy） |
| 0x16aee8 | vt+0x20 | 用 0xAA/0x55/0xFF/0x00 清除全部缓冲（安全清零） |
| 0x16ad74 | （VMT 尾部） | 析构：释放 obj+0x30/+0x34/+0x2C/+0x38 |
| 0x16cf18 | vt+0x08 | 参数查询（块/轮） |
| 0x16cf34 | （块 +0x0c） | `return 0x56cf3a;` —— 返回 32B 静态 blob 指针（"密钥源候选"） |
| 0x16a8b0/0x16a8b8 | — | 工厂链辅助（返回/存储对象） |

---

## 5. 类块（VMT）解析

### 5.1 `TCipher_TEA` 块 @ VA 0x56a43c（RVA 0x16a43c）

```
+0x00 0056ab5c SetFlag      +0x04 0056ac68 SetBlock     +0x08 0056cf18 GetParams
+0x0c 0056cf34 GetBlobPtr   +0x10 0056cf5c TEA-Encrypt  +0x14 0056cfb4 TEA-Decrypt
+0x18 0056d010 Init         +0x1c 0056aeb4 CmpCopy      +0x20 0056aee8 ClearBuffers
+0x24 0b "TCipher_TEA"（长度前缀短串）
+0x30 0056a4b8（数据/RTTI 指针，非函数）
+0x50 0056a4f8  +0x54 0x44(实例尺寸68)  +0x58 0056a3d4（RTTI/字段表，数据）
+0x5c..+0x74 Delphi 运行时指针（NewInstance/FreeInstance/Dispatch 等，0x404xxx/0x407fxx）
+0x78 0056ad74（析构）  +0x7c..+0x84 0056b844 / 0056b924 / 0056b95c（方法表/RTTI）
+0x88 005597f8  +0x8c 005599c0  +0x90 00559b58  +0x94 00559af0   ← 4 个共享"编排"方法
+0x98 0056ab5c  +0x9c 0056ac68                                    ← 与 +0x00/+0x04 重复（VMT 尾部惯例）
```

### 5.2 `THash` 块 @ VA 0x55b5b8

```
+0x00 0055cbf0  +0x04 0055cc28  +0x08 0055cc50
+0x0c 005597f8  +0x10 005599c0  +0x14 00559b58  +0x18 00559af0   ← 共享编排（与 §5.1 同）
+0x1c 0055ca40
+0x20 0055c9ac(→0055c9b8(x,1))  +0x24 0055c9b4(空)  +0x28 0055ca24(→0055c9b8(x,0))
+0x2c 0055ca2c(→0055b320)       +0x30 0055ca3c(return 0)
+0x34.. 名称 "THash"（长度=5）+ VMT 尾部
```

> THash 基类槽 +0x20..+0x30 皆为 stub/转发——**实际参与解密管线的应是派生哈希类**
> （覆盖这些槽位实现 Update/Final/摘要）。round 3 扫描 `TCipher_*`/`THash*` 名称以定位全部类。

---

## 6. 对象字段图（综合）

| 对象 | 偏移 | 含义 | 出处 |
|---|---|---|---|
| 容器 | +0x34 | 辅助对象（`FUN_00570c2c` 惰性创建） | 0x170c2c |
| 容器 | +0x38 | 密码器指针（惰性） | 0x170bfc |
| 容器 | +0x3C | 模式字节 → 密码器 +0x14 | 0x170bfc |
| 容器 | +0x40/+0x44 | 8B 种子（解密入口拷到全局） | 0x171084 |
| 密码器 | +0x14 | 模式（0=累积异或链 / 1 / 2） | 0x56b034 |
| 密码器 | +0x18 | THash 子对象（惰性创建） | 0x56afc4 |
| 密码器 | +0x1C | 全局对象（[0xA1A0BC]） | 0x55c6f4 |
| 密码器 | +0x20/+0x24 | 密钥尺寸 / 块尺寸 | 0x56acd8 |
| 密码器 | +0x2C/+0x30/+0x34 | 三条块缓冲（+0x34=链反馈） | 0x56acd8 / 0x56ac68 |
| 密码器 | +0x38 | 密钥缓冲（16B） | 0x56d010 |
| 密码器 | +0x3C | 位标志（`1<<n`） | 0x56ab5c / 0x56ab4c |
| 密码器 | +0x40 | rounds（clamp 后） | 0x56d010 |

---

## 7. 未决问题 / 下一步

1. **类族扫描**（进行中）：内存扫描 `TCipher_*` / `THash*` 名称 → 枚举全部 VMT →
   定位 (a) .lib 管线实际使用的密码器类（若为 `TCipher_Blowfish`：其块函数 = G 的直接候选）；
   (b) 覆盖 THash 槽 +0x20..+0x30 的具体哈希类（Haval?）→ "密钥扩展"实现。
2. `[vt+0x2c]` 槽位归属未定（模式引擎的块变换；`0x56ac68` 也调用它）——
   待实例 VMT 确定后核对。
3. 模式引擎 case 1/2 的完整语义核对（与 to-be-found 派生类协作）。
4. 工程集成：上游修 `rebuild_pe.py`；把本仓库结论并入 SpiceHappy 时注意其文档更新机制。

---

## 8. 复现命令（本机）

```powershell
$env:JAVA_HOME = "D:\MyPrograms\jdk-21.0.12.1"
$H = "D:\MyPrograms\ghidra_12.1.4_PUBLIC\support\analyzeHeadless.bat"
$PROJ = "D:\MyPrograms\ghidra-mcp\projects"; $NAME = "tina_unpacked_fixed_ghidra_mcp"

# 生成修正镜像（首次）
python D:\WorkDesigns\3_WorkTools\TINA-RE\scripts\fix-pe.py

# 导入 + 全量分析（首次，耗时数分钟）
& $H $PROJ $NAME -import "D:\WorkDesigns\3_WorkTools\TINA-RE\targets\tina_unpacked_fixed.exe"

# 在已分析项目上跑脚本（秒级）
& $H $PROJ $NAME -process "tina_unpacked_fixed.exe" -noanalysis `
    -scriptPath "D:\WorkDesigns\3_WorkTools\TINA-RE\scripts\ghidra-headless" `
    -postScript "ScanClasses.java"
```
