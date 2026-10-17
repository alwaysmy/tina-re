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

## 8. 类族全表与核心算法实现（round 3-5）

> 注：本节的类普查、Blowfish 识别、Haval 槽位语义与 BATTLELOG 第三十二轮**部分重合**——
> 此处提供的是**独立复核**（Ghidra 反编译级）与完整 C 代码、系统化 VMT 表；§9 给出增量部分。

### 8.1 类族扫描结果（DCPcrypt 风格家族，2026-10-16）

- `TCipher_*`（19 个）：Gost、**Blowfish**、IDEA、SAFER（+K40/SK40/K64/SK64/K128/SK128）、TEA、TEAN、SCOP、Q128、3Way、Twofish、Shark、Square
- `THash_*`（21 个）：MD4、MD5、RipeMD128/160/256/320、SHA、SHA1、**Haval256/224/192/160/128**、Snefru、Tiger、Sapphire320..128、Square、XOR16/32
- 每类 VMT 布局（已实证）：[共享方法若干] + [类专属方法] + [长度前缀类名] + [元数据（RTL 指针/析构/实例大小）]
- 关键字符串：`<Encrypted Library>` 与 `"BlowFish"`（注意大写 F）同在 RVA 0x58FAxx 数据区——.lib 管线的算法选择来源

### 8.2 TCipher_Blowfish（.lib 管线目标算法）

类专属方法（与 TEA 槽位一一对应）：

| 槽 | RVA | 语义 |
|---|---|---|
| 参数 | 0x16bd38 | 块=8，密钥上限 0x38（56B），上下文=0x1048 |
| 取指针 | 0x16bd54 | 返回 0x56BD5A（变体 blob） |
| 加密 | 0x16be80 | 见下 |
| 解密 | 0x16bef0 | 镜像逆运算 |
| InitKey | 0x16bf5c | 见下 |

**上下文布局**（密码器 obj+0x38，共 0x1048 B）：

- +0x0000..+0x0FFF：S 盒 4×256 dwords ← 全局 **0xA1B0DC**
- +0x1000..+0x1047：P 数组 18 dwords ← 全局 **0xA1C0DC**
- 两个全局均验证为**标准 π 常数**（P[0]=0x243F6A88、S0[0]=0xD1310BA6，小端存储）

**加密 0x16be80**：块大端序（bswap）；`v0 ^= P[0]`；16 轮 `v0 = F(v0) ^ v1 ^ P[i]`（F = ((S0[x0]+S1[x1]) ^ S2[x2]) + S3[x3]，标准 Blowfish F）；收尾 `^= P[17]` + bswap。结构上是标准 Blowfish 的等价展开（此前"自定义轮函数"疑为展开形式误读）。

**InitKey 0x16bf5c**：`P[i] ^= 密钥字节循环（按大端组成 dword）`；随后表生成：以零块反复调用本类加密，输出 bswap 后依次填充 P[0..17] 与四个 S 盒。

### 8.3 HAVAL 系列（"G"的最可能所在层）

- **IV = 标准 HAVAL 常数**（π 前 8 值，写于 obj+0x98）：`243F6A88 85A308D3 13198A2E 03707344 A4093822 299F31D0 082EFA98 EC4E6C89`
- 摘要长度（[vt+0x30]）：0x167084=**32**（Haval256）/ 0x167644=**28**（Haval224）/ …
- Init（0x16708c）：清 128B 缓冲（obj+0x18）、计数清零（obj+0x14）、写 IV，并按变体设置压缩函数绑定
- **Update（0x16755c）＝ 此前笔记中的"数据泵"**：128B 缓冲；满块经**绑定方法（obj+0xC0=代码指针、obj+0xC4=对象，Delphi 方法引用）**压缩
- **Final（0x16710c）**：HAVAL 填充（含 0x76 溢出特例）；按摘要大小（0x80/0xa0/0xc0/0xe0 位）打包位长与版本字节 `(passes<<3)|1`（passes=obj+0xB8）；压缩后逐字经 FUN_0055a798 反转取出
- 槽位（与 SetKey 调用吻合）：+0x20=Init、+0x24=Update、+0x28=Final、+0x2c=摘要指针(obj+0x98)、+0x30=摘要长度

> 结论：G 的构造 = **HAVAL（pass 3/4/5，obj+0xB8）× 标准 IV × 本实现特有填充/取出顺序**。static_g.py 已有压缩核心转录；本轮补齐了**变体绑定、填充、版本字节、输出反序**四块拼图。与 Blowfish 的串联方式（管线如何组合两者）为下一步。

---

## 9. round 6：mode 引擎全模式 + 哈希驱动（"G 生成器"）+ Haval v3 反编译

> 说明：本节与 BATTLELOG 第三十二轮存在部分重合（类普查、Blowfish 标准实现、Haval 槽位语义他们已记录）。
> 本节的**独立增量**：mode 引擎全部 8 个 case 的完整 C、FUN_0055cc50 的"哈希递推生成器"结构、
> 版本选择器阈值实证、Haval v3 压缩函数源码级反编译（可与其 static_g.py 对拍）。

### 9.1 模式引擎 FUN_0056b034 全模式（完整 C 见 out/round6.txt）

`switch ((char)obj[5])`，`obj[5]=(byte)obj+0x14`=mode；`obj[9]`=块尺寸；缓冲：obj+0x2C(0xb)/obj+0x30(0xc)/obj+0x34(0xd)

| mode | 语义 |
|---|---|
| 0 | `out = in ^ state; E(out); state ^= out`（反馈累积，见 §4.6） |
| 1 | `out = in ^ prev; E(out); prev = out`（CFB 式） |
| 2 | 逐字节：`blk = state; E(blk); out = in ^ blk[0]; state = (state<<8)|out` |
| 3 | 逐字节：同上但 state 新字节取 blk[0]（OFB 式） |
| 4 | 就地 ECB：`copy; E(块); copy 回` |
| **5** | **状态泵**：`tmp = in ^ state; E(tmp); state ^= tmp` —— **不写输出**（= 笔记中的 "mode5"） |
| 6 | 类似 5 但 `state = E(in ^ state)`（直接覆盖） |
| 7 | 逐字节 CFB：输出写回且 state 更新用输出字节 |

### 9.2 哈希驱动三件套（mode 驱动的哈希层 —— "G 生成器"关键）

- **Begin `FUN_0055cbf0(self, mode)`**：`[vt+0x20]()`（Reset）；若 mode==4：取摘要指针/长度存入全局暂存（`FUN_0055ac58/0055ac38`）；后接 `FUN_0055972c`。
- **Process `FUN_0055cc50(self, buf, len, mode)`** ★：
  - 能力位测试：`self+0x10` 起 8 字节位图（mode n → bit n）——即笔记中的"[链尾+0x10] 能力位" ✓
  - mode==3：`[vt+0x24](self, buf, len)`（仅吸收 Update）
  - mode==2/4：循环 digestLen：`Update(chunk); Finalize; digest=[vt+0x2c](); memcpy(digest → buf)`（摘要回写缓冲）
  - **其他 mode（含 5）**：循环 digestLen：`digest=[vt+0x2c](); [vt+0x24](self, digest, digestLen); [vt+0x28](); memxor(digest, buf, chunk)`
    → **递推哈希生成器：`d_{n+1} = H(d_n)`，密钥流 = d_{n+1}，与输入异或**（= 笔记"hash→流→hash 递归"的代码实体）
- **End `FUN_0055cc28(self, mode)`**：mode==3 → `[vt+0x28]()`（Finalize）；否则 `[vt+0x20]()`（Reset）。
- 槽位映射（哈希层）：+0x20=Reset、+0x24=Update、+0x28=Finalize、+0x2c=摘要指针、+0x30=摘要长度（与 SetKey 的调用序列一致 ✓）

### 9.3 Haval 版本选择器 FUN_00566650（实证）

```c
if (passes<3 || passes>5) passes = digestLen<0x15 ? 3 : (digestLen<0x1d ? 4 : 5);
obj[0xB8] = passes;
passes==3 → obj[0xC0]=0x5666d0, obj[0xC4]=obj（绑定方法：v3 压缩）
passes==4 → obj[0xC0]=0x566960 …（v4）
passes==5 → obj[0xC0]=0x566c9c …（v5）
```

- 阈值：摘要 < 21B → v3；21..28B → v4；≥29B → v5 ✓（笔记"摘要≤20B→v3"一致）
- 压缩入口（供 static_g.py 对拍）：**v3=0x1666d0 / v4=0x166960 / v5=0x166c9c**

### 9.4 Haval v3 压缩 FUN_005666d0（源码级）

- 常量表直接硬编码为指针：**CST @ VA 0xA1293C（RVA 0x61293C）**、**IDX @ VA 0xA12B3C（RVA 0x612B3C）** ✓（与笔记一致——该区域同时承载 Blowfish P[8..17]+S 盒，即 π 派生表共用）
- 结构：3 pass × 32 步；pass0 仅用消息表，pass1/2 用 `msg[IDX[i]] + CST[i]`；轮函数含 `(a>>7|a<<25) + (b>>11|b<<21) + …`（ROTR7/ROTR11 加法）与 8 状态字馈给更新（标准 HAVAL 骨架）
- 篇幅所限全文见 `out/round6.txt`，可直接与其 Python 转录对拍

### 9.5 其他核对

- RVA 0x61293C（48B）dump 证实 = P[8..17]（0x452821E6…0x8979FB1B）+ S 盒起始 ✓ 笔记无误差
- 'BlowFish'/'<Encrypted Library>' 字符串在 Ghidra 静态 xref 为空（Delphi 字符串引用未在分析区内恢复）；其三个检查点见 tina-research 记录（0x58f851/0x174248/0x171a95）
- 0x55B326（"静态 keystream 暂存"）静态镜像中为代码字节——运行时写入的 scratch 区（与笔记的运行时观测一致）

---

### 9.6 round 7 增量（LCG 定位 + G 假设对撞）

- **FUN_0055ac38 = 32 位 Delphi LCG**（`seed = ((byte)seed ^ *p) * 0x08088405 + 1; *p = seed >> 24`）
  ——即此前笔记中"0x15ac39 候选生成器"（0x15ac39 正是本函数体内一字节之差）。实际用途：
  **mode 4 的 Begin（FUN_0055cbf0）用随机种子（FUN_0055ac58）对摘要区做 LCG 掩码填充**（不是 .lib 主链路密钥流）。
- 'BlowFish'('0x98FABC') / '<Encrypted Library>'(0x98FAA0) / 40B 串(0x98FAD0) 的**立即数装载扫描为空**
  （B8/68 编码全代码区无命中）→ 其引用应以运行时/计算方式构造，静态 xref 不可得（符合既有判断：属 .TSC 或 InitKey 子系统）。
- **G 假设对撞（scripts/test_g_hypothesis.py）**：以三组 oracle 点（`G(0⁸)=7455d14e72cf5821` 等）
  对撞 {K=0x98FAD0 40B, K=0x56BD5A 40B} × {E/D} × {原样/dword 换序/整串反序} 全部 **0 命中** ——
  以正确的字节序与标准 Blowfish 实现独立复核了"标准 Blowfish × raw40 死"的既有结论。
- 40B 串 @0x98FAD0（可打印值域）：`78372f6a3f242b34283a3c4076372131525e397e6b256738363d6c5c30223c2a3e31235e54267b5d`
- 0x56BD5A（Blowfish 类 blob getter 指向）同样为 40B：`1971cacd2b9c8529da8147b7ebce16c6910e1dc840123e3570edbc964c13d0b8c39057565355528b`

---

## 10. 管线接线图（.lib 解密路径综合，round 6-9）

```
TSC_DecryptEntry (0x171084)
  ├─ 8B 种子 [容器+0x40/44] → 全局缓冲（指针变量 0xA64318 → 静态缓冲 0xA12928，π 表区近旁）
  ├─ TSC_CipherFactory (0x170bfc)
  │    └─ TSC_GetAuxObject (0x170c2c) → FUN_0056a8b0 → 全局 0xA28B64 = 0x00569E88
  │         （指向 Blowfish 类注册区 → 管线类极可能 = TCipher_Blowfish）
  │    └─ DEC_CipherCreate (0x56acd8)（异常帧 + 4 缓冲分配 + 钩子）
  │    └─ 模式字节 [容器+0x3c] → 管线对象 +0x14
  └─ [vt+0x0C] DEC_DoStream(0x5597f8)（self, in, out, dir=1, size）
        └─ 4KB 分块 → [vt+0x08] Process(buf, len, mode)
              ├─ mode3: 纯吸收（哈希 Update）
              ├─ mode2/4: Update+Final，摘要回写
              └─ 其他(含 5): d_{n+1}=H(d_n); buf ^= d_{n+1}（递推哈希流）
     DEC_ModeEngine(0x56b034) 8 模式（case5 = 状态泵 state ^= E(in^state)）
     SetKey 链: DEC_CipherSetKey(0x56adfc) → THash 子对象(+0x18)
        → [0x20]Init/[0x24]Update/[0x28]Final/[0x2c]摘要指针/[0x30]摘要长度
        → 密码器 [0x34] 装订 → DEC_ModeEngine 初始化
     Haval 系: SetPasses(0x566650, 阈值21/29→v3/v4/v5); Init 写标准 IV(π);
        Update(0x56755c)/Final(0x56710c, 0x76 溢出填充 + 版本字节)
```

**全局变量表**（本轮 dump 实证）：

| 全局 | 初值 | 含义 |
|---|---|---|
| 0xA64318 | → 0xA12928 | 种子缓冲指针变量（静态缓冲，π 表区近旁；入口写、退出清） |
| 0xA28B64 | 0x00569E88 | `FUN_0056a8b0` 返回；指向 Blowfish 类注册区（工厂创建链使用） |
| 0xA1A0BC | 0x0055B910 | `FUN_0055c6f4` 返回；指向 THash 类注册区（哈希子对象来源） |
| 0xA65164 | → 0xA12920 | 指向静态区（字节序转换/暂存相关） |

**Ghidra 项目已命名**（44 个符号，持久保存在 `tina_unpacked_fixed_ghidra_mcp` 项目）：
`TSC_DecryptEntry / TSC_CipherFactory / DEC_DoStream / DEC_HashDriver_Process / DEC_ModeEngine /
TCipher_Blowfish_* / THash_Haval_* / Haval_v3|v4|v5_Compress / memxor / LCG32_Keystream …`
—— 后续任何 Ghidra（含 MCP）会话可直接按名字导航。

**保留问题**：
1. 管线实际类确认（0xA28B64 → 0x569E88 属 Blowfish 区，但非标准 VMT 起点；建议运行时对象捕获交叉验证）
2. 密钥来源（种子是否参与 InitKey：既有运行时证据=不进链；静态工厂链未见 SetKey 调用点参数）
3. G 的精确构造（oracle 对撞已排除标准 Blowfish×两个 40B blob；递推哈希生成器为最强候选）

---

## 11. round 10-14：接线定案 + RIPEMD-256 实证

### 11.1 类与 VMT 定案

- **0xA28B64 = 0x00569E88 = TCipher_Blowfish 的实例 VMT**（工厂创建链所用）——管线密码器 = Blowfish 类**实锤**。
  槽位（base=0x569E88）：+0x00=0x56B844 / +0x04=0x56B924 / +0x08=0x56B95C（Begin/End/Process 三件套）、
  +0x0C=DoStream、+0x10..+0x18=0x5599C0/0x559B58/0x559AF0、+0x1C=SetFlag、+0x20=SetBlock、
  +0x24..+0x28=GetParams/GetBlob、+0x2C=EncryptBlock、+0x30=DecryptBlock、+0x34=InitKey、+0x38=CmpCopy、+0x3C=ClearBuffers
- **委托对象在 obj+0xC**（getter FUN_00559634；构造时由 FUN_00559698 设置；类校验引用 _DAT_005592EC）。
- **委托哈希类 = THash_RipeMD256**（0xA1A0BC → 0x55B910；VMT 名串 "THash_RipeMD256" 实锤）。
  其槽位：+0x20=Init(0x562A04)、+0x24=Update(0x55D6BC)、+0x28=Final(0x55D624)、+0x2C=状态指针(→obj+0x58)、
  +0x30=摘要长度、+0x34=压缩(0x561588)；状态区 obj+0x58（8×32bit）。

### 11.2 处理链（最终形态）

```
DoStream(4KB 分块) → Cipher.Process(buf,len,API-mode)
  ├─ API-mode==1: 解密引擎 FUN_0056B490[self+0x14 分支]
  │     cases 0-4: 专用解密（用 DecryptBlock）;case 5/6/7 → 转调 FUN_0056B034
  │     （.TSC 运行时观测的 "mode5" = self+0x14 = 5 → 最终走 FUN_0056B034 case 5）
  └─ 委托(哈希层).Process(buf,len,mode)：mode3=纯吸收;2/4=摘要回写;其它(含1/5)=自哈希链:
        S_{n+1} = Finalize(Update(S_n))（状态回灌）;buf ^= S_{n+1}
  Cipher.Begin/End 同样转发委托（mode4 时 LCG 随机掩码：FUN_0055ac38 即"0x15ac39"）
```

### 11.3 RIPEMD-256 = 标准实现（三重验证）

1. **Ghidra p-code 模拟**二进制压缩函数（0x561588）三组块向量：
   - compress(IV, 0⁶⁴) = `ac92f0fd7e573dcd81c9cf459a79d6a224ce03fbcdb023aa23bff3f7307fbef6`
   - compress(IV, 0..63) = `115023a38024723bfb163700a7199c0ef7f87c75884ad633355769cade59c476`
   - abc-padded 块 = **与官方 RMD256("abc") 逐字节一致** `afbd6e22…457b65`
2. 官方向量（Bosselaers 页）：""、abc、message digest 全中
3. Python 参考实现（`scripts/test_g_rmd256.py`）双门全过

**结论**：管线哈希 = 标准 RIPEMD-256（32B 摘要）；此前围绕 Haval 的 G 候选方向应转向 RMD256 骨架。
（0x98FAD0 / 0x56BD5A 两个 40B blob 与 RMD256 的 32B 不符——其为暂存密钥材料，来源待定。）

### 11.4 G 对撞进展

- 标准 Blowfish×密钥候选：排除（§9.6）
- 纯 RMD256 切片 / 自哈希链首三态：0 命中
- **下一步（已具备全部素材）**：全管线模拟器（Blowfish+RMD256+双引擎+委托链）对
  `ks_ground.bin`（11626B 地面真值）+ oracle 5 点做参数搜索 {密钥来源×初始态×模式×委托门控}。
  Ghidra p-code 模拟器可随时为任意中间函数生成金向量（Round14 模式）。

---

## 13. ★ G 破解：标准 CBC + 全库静态解密（2026-10-17）

**结论：加密库解密 = 标准 Blowfish-CBC。所谓 "G" 只是该 CBC 的等价改写。**

```
文件格式 : b"<Encrypted Library>\n\r"（21B 头）+ 密文
key     = RIPEMD-256( 镜像内 40B 常量 @ RVA 0x58FAD0 )
IV      = 0x864D93CD4B27E92D（常量；尾部不满 8B 的部分原样直通）
pt      = Blowfish-CBC-decrypt(ct)
```

对既有两个疑点的解释：

- 老模型 `pt_b = ct_b ^ ct_{b-1} ^ G(ct_b)` 与标准 CBC 等价：`G(x) = D_k(x) ^ x`
  （`pt_b = D(ct_b) ^ ct_{b-1}`，两边同乘 `ct_b` 即得）。oracle 三点验证：
  `G(0)=D_k(0)=7455d14e72cf5821` ✓；`G(2cfe90…) = D^ct = 272a69bbc7a0b123` ✓；`G(f5a4c7…) = bc7a318806a75984` ✓
- 旧假设 "IV=0" 是块 0 永远不对的原因；真实 IV = 常量 0x864D93CD4B27E92D。
- 密钥派生 = **RMD256(40B 密钥串)**（正是笔记里"密钥串已定位 40B"的那段数据）。
  此前"标准 Blowfish 死"的失败源于：派生方式（RMD256 而非直用）与 CBC/IV 假设。

**验证证据**：

| 项 | 结果 |
|---|---|
| DAC882X.lib 全量对比 `ks_ground.bin` | 11626 字节仅末尾 2 字节不同（不完整块，原样直通） |
| SPICELIB 全库 | 485 个 .lib = **388 加密（全部解密成功，ASCII 1.0）+ 97 明文** |
| 抽样文本 | `*ADC161S626`、`* AFE5803`、`* DAC882X (PSpice format)`、`* TL431`，`.SUBCKT` 名与文件名一致 |

**工具**：`scripts/tina_static_decrypt.py`

```
python scripts/tina_static_decrypt.py <file.lib> [out]
python scripts/tina_static_decrypt.py --all        # 全量 → decrypted-local/（gitignore）
```

**意义**：加密库解密不再需要 TINA 运行时 / Frida / 窗口（原 tina_export.py 链路可退役）；
剩余工作回到 SPICE 引擎剥离（Phase 3）与已解密模型的整理。

---

## 14. Phase 3 引擎测绘（round 15-17，2026-10-17）

> 数据来源：修复版镜像全量分析 **18594** 函数（已保存）；原始输出 `out/round15-17*.txt`，
> 脚本 `scripts/ghidra-headless/Round1{5,5b,6,7}.java`。路线与里程碑见 SpiceHappy
> `docs/engine-extraction.md`。

### 14.1 区域函数清点（VA = RVA + 0x400000）

| 区（历史字符串聚类） | RVA | 函数数 | 函数体 | 最大函数 / 判读 |
|---|---|---|---|---|
| 密码/保护 | 0x159000–0x16F000 | 181 | 67.7 KB | 0x162A9C(10.5KB) 保护调度；0x161588(5.2KB)=RIPEMD-256 压缩 |
| 求解器区 | 0x177000–0x186000 | 110 | 39.7 KB | 0x183624(3.4KB)=参数/符号求值器（switch 表达式，含 π）；0x17BE8C(3.4KB) 待判 |
| "线性代数"区 | 0x2E7000–0x2EA000 | 6 | 5.0 KB | 0x2E7F5C(4.2KB) 形似绘图/波形渲染，非 LU |
| 分析编排区 | 0x330000–0x350000 | 44 | 17.7 KB | 0x348580(5.7KB) 待判 |
| 库加载/签名 | 0x58F000–0x592000 | 20 | 9.1 KB | 含 `<Encrypted Library>` 字符串 + 40B 密钥常量（0x58FAD0） |

### 14.2 两处归属修正

1. **0x58F851 不是网表编译入口**：所在函数引用 `sign`/`silent`/`update.exe`/`Message_Digest_5`，
   属签名/更新/库加载模块；密钥常量就在同模块数据区 → 与 .lib 解密链路一致。
2. **"线性代数 0x2E7000" 的最大函数形似绘图渲染**；`' LU '` 字符串可能只是界面文案。
   LU 实际来源更可能是 `sparse_dll.dll`（11 导出，早期结论）。

### 14.3 结论

按字符串聚类得到的"求解器区"仅 110 函数/40KB，与完整 SPICE 引擎规模不符（可能分散或经虚调用）。
下一步不是继续按字符串猜区域，而是**运行时联查**：hook `sparse_dll.dll` 的
`_SMPcLUfac`/`_SMPcSolve` 导出抓调用栈 → 反查静态地址 → 在 Ghidra 内持久命名。

### 14.4 运维教训

`ghidra-mcp.cmd stop` 用 taskkill 强杀后端会导致 JVM 内自动分析**不保存**（本例 18594 → 76）。
补跑 `analyzeHeadless -process <proj> <name> <file>`（不带 `-noanalysis`）可恢复并保存（本次 252 s）。

---

## 15. M2：线性求解层调用图（运行时 + 静态，2026-10-17）

> 方法：Frida 探针（SpiceHappy `tools/tina-run/tina_sparse_trace.js`）抓 `_SMPcSolve` 调用栈，
> 再用 Ghidra 对账（`Round18-21.java`，输出 `out/round18-21.txt`）。
> 运行对象：TINA 自带示例 `2nd Order All-Pass Filter.TSC`，AC 分析 0xA7。

### 15.1 运行时调用栈（模块内偏移 = RVA）

```
tina.exe+0x510c72   ← 条件包装器内部（直接调用者）
sparse_dll.dll+0x6cdc   ← _SMPcSolve
tina.exe+0x31630d   ← AC 扫描工作函数 FUN_00715cb0
tina.exe+0x316ad8
tina.exe+0x429726   ← 分析编排 FUN_00829726
tina.exe+0x93a38 / 0x936b3   ← 命令派发
tina.exe+0x2ec26    ← 窗口消息入口
```

单次 AC 扫描捕获 ≥20 次 `_SMPcSolve`，入参指针恒定（复用矩阵，只换激励/频率）。

### 15.2 sparse 指针表（dump 时基址 0x04400000）

RVA `0x1BDAF20` 起 11 项，依次为 `_SMPcSolve / _SMPcLUfac / _SMPcReorder / _SMPsolve /
_SMPluFac / _SMPreorder / _SMPpreOrder / _SMPmakeElt / _SMPclear / _SMPdestroy / _SMPnewMatrix`。
跳板岛 RVA `0x510620–0x510670`，每条 `jmp dword ptr [0x1FDAF2x]`（0x510670 = `_SMPcSolve`）。
脚本：`scripts/find_sparse_callsites.py`（从镜像读表 + 反查导出名 + 列调用点）。

> 注意：磁盘 PE 的静态导入表只列 `_SMPcSolve` 一条，但 dump 里 11 项全满 →
> 加载/脱壳阶段重建了导入表，不能只信磁盘导入目录。

### 15.3 静态结构

| RVA | 作用 |
|---|---|
| `0x510C58` | 条件包装器（30 B）：`if (*(ushort*)(m+4) > 1) _SMPcSolve(...)` |
| `0x1888EC` | 6 B 转发器 → 包装器 |
| `0x473368` | 求解驱动（98 B）：`type==8` 走 sparse 路径，其它走另一条；末尾自增求解计数 |
| `0x315CB0` | AC 扫描（2170 B，x87 double 频率循环） |
| `0x49FA3C` | 另一条调用包装器的路径（2290 B，疑 DC/工作点） |

### 15.4 复现

```powershell
python D:\WorkDesigns\3_WorkTools\SpiceHappy-tina-re\tools\tina-run\tina_run.py `
  --tsc "C:\Program Files (x86)\DesignSoft\Tina 9 - TI\EXAMPLES\Filters_Others\2nd Order All-Pass Filter.TSC" `
  --export "$env:TEMP\tina_probe\probe.net" --analysis 0xA7 --export-cmd 0x19 `
  --trace-js D:\WorkDesigns\3_WorkTools\SpiceHappy-tina-re\tools\tina-run\tina_sparse_trace.js
```

### 15.5 运维修复（同日）

- TINA 启动警告（库数据库不一致）需点『忽略』，否则编辑器不出现；
- AC 分析对话框类名是 `TACTransferDlg`（不是 `TACAnalDlg`）；
- 导出会自动追加扩展名（网表 → `.CIR`），检查路径要兜底。
  以上均已修进 `tina_run.py`。

---

## 12. 复现命令（本机）

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
    -postScript "Round4.java"
```
