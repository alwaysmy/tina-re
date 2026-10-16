# TINA 镜像 Ghidra 分析发现（2026-10-16）

> 分析工具：Ghidra 12.1.4 + GhidraMCP 2.0（headless，无 GUI）
> 镜像：`re/tina_unpacked_static.exe`（在本会话中先修正节表，见 §1）
> 地址约定：RVA（=文件偏移，基址 0x400000）；Ghidra 地址 = RVA + 0x400000

---

## 1. 【重要】rebuild_pe.py 节表字段写反 bug —— 已修正

**症状**：`tina_unpacked_static.exe` 用 Ghidra/PE 加载器加载后，代码区全部错位（RVA 0x17112c 读到全零；
entry 0x401000 读到的是指针表而不是代码）。Ghidra 只识别出 8456 个函数。

**根因**：`re/rebuild_pe.py` 第 38 行

```python
struct.pack_into('<II', data, sec_off + idx*40 + 16, va, rawsz)  # 16=PtrRawData, 20=SizeRawData
```

注释里把两个字段弄反了。PE 规范实际是 `+16 = SizeOfRawData`、`+20 = PointerToRawData`，
所以写入结果为 `SizeOfRawData = VA`、`PointerToRawData = VirtualSize(对齐后)`——两个字段整体互换。
脚本末尾的"验证"只用 capstone 按**文件偏移**反汇编，不经过节表，所以这个错误从未暴露。
（此前文档中"节表 raw=virtual 修正，IDA/Ghidra 可直接载入"的说法，实际加载是坏的。）

**修正**（把两个 dword 换回来即可，其余字段本来就对）：

```python
size_raw, ptr_raw = struct.unpack_from('<II', data, p+16)   # 当前: size_raw=VA, ptr_raw=VSize
struct.pack_into('<II', data, p+16, ptr_raw, size_raw)      # 修正后: SizeOfRawData=VSize, PtrRaw=VA
```

**修正后效果**：全部 10 个节 `PointerToRawData == VirtualAddress`（真正的 raw=virtual 平铺），
Ghidra 识别函数 **18514 个**（修正前 8456），`RVA 0x17112c` 读到 `55 8B EC 33 C0...` 与文件一致，
Delphi 编译器规格（borlanddelphi）自动识别 ✓

**修正版镜像**（本机分析用副本，未改动仓库文件）：
`D:\MyPrograms\ghidra-mcp\targets\tina_unpacked_fixed.exe`
（建议：修 rebuild_pe.py 后重新生成仓库内的正版；本副本可直接拿去做 Ghidra/IDA 分析）

---

## 2. `0x17112c` 不是解密函数 —— 原"直调"方向可排除

Ghidra 反汇编 + 数据引用证明它是**Delphi 单元初始化桩**：

```
0057112c  PUSH EBP / MOV EBP,ESP / XOR EAX,EAX
00571132  PUSH 0x571151          ; SEH handler
00571137  PUSH FS:[0] / MOV FS:[0],ESP
0057113d  INC dword ptr [0xA6B128]   ; 全局初始化计数器 +1
0057114b  PUSH 0x571158 / RET        ; 尾跳转到下一段初始化代码
```

- 对 `0x57112c` 的引用只有 **1 处数据引用**（来自 `RVA 0x609FD8`，即初始化表/函数指针表）。
- 结论：编译器生成的初始化代码，与解密无关。tina-automation.md 中"函数头在 0x17112c"的判断应作废
  （当时基于帧指针外推的栈帧，Delphi 无帧指针，栈回溯易产生伪帧）。
- tina-issues.md #12（直调解密函数）的真正入口是既有的 `0x171084` 全链。

---

## 3. 解密链条的真实 C 反编译（Ghidra 输出，未加工）

### 3.1 解密入口 `FUN_00571084`（RVA 0x171084）—— 与笔记完全吻合

```c
void FUN_00571084(int param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4)
{
  puVar1 = PTR_DAT_00a64318;                                        // 全局种子缓冲（指针）
  *(undefined4 *)PTR_DAT_00a64318 = *(undefined4 *)(param_1 + 0x40);      // [容器+0x40] → 种子 dword0
  *(undefined4 *)(puVar1 + 4)      = *(undefined4 *)(param_1 + 0x44);     // [容器+0x44] → 种子 dword1
  ...
  piVar2 = (int *)FUN_00570bfc(param_1);                            // 工厂：取/建密码器
  (**(code **)(*piVar2 + 0xc))(piVar2, param_2, param_3, 1, param_4);  // vtable+0xc 调用（5 参数！）
  ...
  *PTR_DAT_00a64318 = 0;  *(puVar1 + 4) = 0;                        // 种子用完清零
}
```

**新信息**：vtable+0xc 的调用是 **5 个参数**（第 4 参数为常量 1）。
现有笔记记的是"流数据/Result槽/剩余长度"3 参数——真实的第 4/5 参数（1, param_4）需要纳入模型。

### 3.2 工厂 `FUN_00570bfc`（RVA 0x170bfc）

```c
undefined4 FUN_00570bfc(int param_1, undefined1 param_2, undefined4 param_3)
{
  if (*(int *)(param_1 + 0x38) == 0) {                        // 惰性创建
    uVar1 = FUN_00570c2c(param_1, param_2, param_3, 0);
    iVar2 = FUN_0056acd8(uVar1, 1, 0, uVar3 /*=0*/);          // 创建链
    *(int *)(param_1 + 0x38) = iVar2;                         // 密码器存 [容器+0x38] ✓
    *(undefined1 *)(iVar2 + 0x14) = *(undefined1 *)(param_1 + 0x3c);  // 模式字节: [容器+0x3c] → [密码器+0x14]
  }
  return *(undefined4 *)(param_1 + 0x38);
}
```

### 3.3 vtable 解码：`RVA 0x16a43c`（TCipher_TEA 描述块）

```
+0x00 0x0056ab5c   +0x04 0x0056ac68   +0x08 0x0056cf18 (GetParam: 块=8/轮=16..32)
+0x0c 0x0056cf34（入口实际调用的目标，未反编译——见 §5）
+0x10 0x0056cf5c (TEA 加密)          +0x14 0x0056cfb4 (TEA 解密)
+0x18 0x0056d010 (Init: 拷贝密钥)
+0x1c 0x0056aeb4   +0x20 0x0056aee8
+0x24 0b "TCipher_TEA"（长度前缀短串）  +0x30 0x0056a4b8（类引用）
```

**修正**：笔记中"call [密码器vtable+0xc]（TEA 解密）"——+0xc 实际指向 `0x16cf34`（分发器/包装），
真正的加密/解密在 +0x10/+0x14（0x16cf5c / 0x16cfb4），与地址账本一致。

### 3.4 创建链 `FUN_0056acd8`（RVA 0x16acd8）

```c
int * FUN_0056acd8(int *param_1, char param_2, int param_3, undefined4 param_4)
{
  ...
  FUN_00559c78(param_1, 0, param_4);                 // 基类构造
  iVar1 = FUN_0055c6f4();                            // ★ 6 字节全局 getter：MOV EAX,[0xA1A0BC]; RET
  param_1[7] = iVar1;                                // → [obj+0x1C]
  (**(code **)(*param_1 + 0x24))(*param_1, param_1 + 9, param_1 + 8);  // 取尺寸 → obj+0x24/obj+0x20
  param_1[0xc] = FUN_00402ee8(param_1[9]);           // 分配缓冲（obj+0x30）
  param_1[0xd] = FUN_00402ee8(param_1[9]);           // obj+0x34
  param_1[0xb] = FUN_00402ee8(param_1[9]);           // obj+0x2C
  param_1[0xe] = FUN_00402ee8(param_1[10]);          // obj+0x38（密钥缓冲，尺寸 obj+0x28）
  (**(code **)(*param_1 + 0x3c))();                  // 虚调用（初始化）
  if (param_3 != 0) FUN_0056adfc(param_1, param_3, 0);   // SetKey
  return param_1;
}
```

**修正**：笔记认为 "0x15c6f4 起 = 密钥扩展（待逆向）"——实际 `0x55c6f4` 只是 6 字节全局取数
（`MOV EAX,[0xA1A0BC]`），不承载密钥扩展逻辑。密钥扩展在 SetKey→调度器对象链里（见 §4）。

### 3.5 SetKey `FUN_0056adfc`（RVA 0x16adfc）

```c
void FUN_0056adfc(int *param_1, undefined4 param_2, undefined4 param_3)   // param_2 = 密钥串
{
  piVar1 = FUN_0056afc4(param_1);              // ★ 取出"调度器/散列"子对象（obj+0x18）
  (**(code **)(*piVar1 + 0x20))();             // 调度器虚接口 Start/Reset
  uVar2 = FUN_00405fb8(param_2);               // Delphi 串长度
  uVar3 = FUN_004061b8(param_2);               // Delphi 串指針
  (**(code **)(*piVar1 + 0x24))(piVar1, uVar3, uVar2);      // Update(ptr, len)  ← 喂密钥
  (**(code **)(*piVar1 + 0x28))();             // Final/Finish
  iVar4 = (**(*piVar1 + 0x30))();              // 摘要长度
  if (param_1[8] < iVar4) iVar4 = param_1[8];  // 截断到 obj+0x20
  uVar2 = (**(*piVar1 + 0x2c))();              // 摘要缓冲指针
  (**(code **)(*param_1 + 0x34))(param_1, uVar2, iVar4, param_3);  // 密码器 +0x34：装订密钥
  ... FUN_0056b034(param_1, ...) ...
  (**(code **)(*param_1 + 0x38))();            // 收尾
  (**(code **)(*param_1 + 0x1c))(param_1, 0, 1);
}
```

**这是"密钥扩展"真实所在**：密钥串 → **调度器对象**（`obj+0x18`，经 `FUN_0056afc4` 惰性创建，
类校验引用 `PTR_PTR_0055b56c → 0x55b5b8`）→ 一个 Update/Final/摘要 接口（极可能就是你们
static_g.py 里转录的 Haval 家族）→ 摘要截断后装订进密码器。**8B→16B 的"扩展"应在此层**。

### 3.6 init `FUN_0056d010`（RVA 0x16d010）—— 与笔记吻合

```c
void FUN_0056d010(int *param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4)
{
  local_8 = param_3;
  FUN_0056ab78(param_1, &local_8);
  FUN_004032b8(param_2, param_1[0xe], local_8);   // memcpy(密钥, [obj+0x38], len) ✓
  FUN_0056cef8(param_1, param_1[0x10]);           // setRounds(clamp) ✓ rounds=obj+0x40 ✓
  (**(code **)(*param_1 + 0x20))(param_1, param_4);
}
```

### 3.7 ★ 模式引擎 `FUN_0056b034` —— 与第 32 轮经验模型直接相关

```c
switch ((char)param_1[5]) {          // [obj+0x14] = 模式（由 [容器+0x3c] 带入）
case 0:   // 逐块：out = in ^ feedback; 调用 [obj.vt+0x2c](out); feedback ^= out
case 1:   // 逐块：out = in ^ feedback; 调用 [obj.vt+0x2c](out); feedback = out
case 2:   // 逐字节/CFB-like
}
```

- 组合运算 `FUN_0055a854` = **纯内存 XOR**（56 字节，DWORD 对齐）。
- **重要**：case 0 的反馈更新是 `feedback = feedback ^ out`（不是标准 CBC 的 `feedback = out`），
  即链值本身是相邻密文块的累积异或——这正是你们经验模型
  `pt_b = ct_b ^ ct_{b-1} ^ G(ct_b)` 中 `ct_b ^ ct_{b-1}` 项的来源结构
  （`vt+0x2c` 的块变换在解密方向上等价于 `ct ^ G(ct)`，G 的构造即该块变换链）。
- 入口调用第 4 参数 = 1 与这里 `FUN_0056ab4c(param_1, 1)`（位 1 of [obj+0x3C]）的语义可以对照看。

---

## 4. 对象字段图（来自反编译，符号化整理）

| 对象 | 偏移 | 含义 |
|---|---|---|
| 容器 | +0x38 | 密码器指针（惰性创建） |
| 容器 | +0x3C | 模式字节（byte，拷入密码器 +0x14） |
| 容器 | +0x40/+0x44 | 8B 种子（解密入口拷入全局） |
| 密码器 | +0x14 | 模式（0=CBC 变体[反馈异或累积] / 1 / 2） |
| 密码器 | +0x18 | 调度器子对象（惰性创建，类引用 0x55b5b8） |
| 密码器 | +0x1C | 全局对象（`[0xA1A0BC]`，来自 FUN_0055c6f4） |
| 密码器 | +0x20/+0x24 | 块尺寸 / 密钥尺寸（来自 vt+0x24 查询） |
| 密码器 | +0x2C/+0x30/+0x34 | 三条缓冲（块尺寸） |
| 密码器 | +0x38 | 密钥缓冲（尺寸 [obj+0x28]） |
| 密码器 | +0x3C | 位标志（`1<<n` 测试） |
| 密码器 | +0x40 | rounds（clamp 后） |

---

## 5. 未完成 / 下一步（需要"创建函数"能力）

Ghidra 自动分析漏掉了仅被**间接调用**（vtable）的函数。以下仍在"函数未定义"状态，
MCP 工具集无反编译入口（需要 pyghidra 或 GUI 里手工创建函数后即可）：

- `0x16cf34` —— 解密入口实际调用的目标（疑似加解密分发器；热路径劫持的关键函数）
- `0x16cf5c` / `0x16cfb4` —— TEA 变体加密/解密本体（可用于**验证 tea_variant_test.py 的转录**）
- `0x16cef8` / `0x16cf18` —— setRounds / 参数查询（在函数列表里，但可与 0x16cf34 一并核对）

方法：停后端 → 复制 Ghidra 项目副本 → 用 pyghidra 脚本 CreateFunction + DecompileFunction，
批量导出上述函数伪代码。另可把本报告中的符号命名写回项目（rename_function 等，会持久保存）。

---

## 6. 复核要点（对既有笔记的修订）

1. "0x17112c = 解密函数头，可热路径劫持" → **作废**（Delphi 单元初始化桩）。
2. "vtable+0xc = TEA 解密" → +0xc 是 0x16cf34（未反编译）；+0x14 才是 0x16cfb4 解密本体。
3. "0x15c6f4 起 = 密钥扩展待逆向" → 0x55c6f4 仅为 6 字节全局 getter；密钥扩展
   在 SetKey 的**调度器子对象**链（Update/Final/摘要→截断→装订），即 0x55b5b8 类。
4. "解密调用 3 参数" → 实际 5 参数（第 4 参 = 1）。
5. 镜像加载：修正节表后 Ghidra 可正常分析（18514 函数），本报告全部结论基于修正版。
