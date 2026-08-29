# Mali kbase 逆向结论（2026-08-23 补记）

## 0. 环境与方法
- 分析对象：kernel 镜像 `/home/tkz/ghostlock/analysis/kernel`（文件偏移 = 运行时 VA - 0x10000000）
- kbase_ioctl 文件偏移 0x20a38bc（VA 0x120a38bc），kbase_mmap 文件偏移 0x20a6d08
- 自研反汇编器 `a64dis.py`（对照 rb_erase.asm 等地面真值校验，命中率 ~90%）
- kbase_ioctl.elf 是空壳（kbase_ioctl2.elf 才是真代码 0x600 字节）

## 1. kbase_ioctl 分发结构（0x20a38bc 入口）
- `ldr x21, [x0, #0xd0]` = filp->private_data = kbase_context *kctx
- 字段：`[kctx+0x00]`=kbdev, `[kctx+0x10]`=内部上下文(init 后), `[kctx+0x18]`=flags/版本,
  `[kctx+0x20]`=**state 状态机字段**（ldar 读）
- 早处理 ioctl（不查 state）：0xc0048000 VERSION_CHECK、0xc0048034(nr=52)、
  0xc0108037(nr=55)、0xc0108038(nr=56)、0x40048001 SET_FLAGS
- 主分发 0x20a3ab8：**`ldar w10,[kctx+0x20]; cmp w10,#4; b.ne → 返回 -1 (EPERM)`**

## 2. 【核心】EPERM 来源 = kctx->state(0x20) != 4（驱动内部状态机，非 SELinux/capable）
- VERSION_CHECK (0xc0048000)：copy 4 字节(major/minor) → 校验 major==11, minor==38
  → 构造版本字 0xb00000|(minor<<8)=0xb02600 → CAS state 0→1 (0x20a3e80)
  → 0x20a404c: state 1→2，存 0xb02600 到 [kctx+0x18]，检查 [0x18] vs 0xb00eff：
    - **0xb02600 > 0xb00eff → 提前返回版本 OK，state 停在 2，不建上下文**
    - 若 ≤ 0xb00eff 才继续 2→3 → kbase_create_context → state=4 (0x20a4100)
- SET_FLAGS (0x40048001, 4 字节 create_flags)：state>=2 时 0x20a3dc0：
  - flags 必须是 0x7a 子集（bit1,3,4,6）
  - [kctx+0x18]=0xb02600 > 0xb00eff → CAS 2→3 → 建上下文 → state=4 (0x20a3e54) → 0
  - 若 [kctx+0x18] <= 0xb00eff → 0x20a3f08 → 要求 state==4 否则 EPERM
- **结论：新 fd 正确序列 = VERSION_CHECK → SET_FLAGS → state=4 → 才能 MEM_ALLOC**

## 3. 【重大发现】probe 的 MEM_ALLOC ioctl 号是错的
- mali_mem.c 用 `_IOWR(0x80,6,16)` = **0xc0108006** → 分发到 0x20a3b4c →
  **kbase_mem_query (0x2097d98)**，根本不是 mem_alloc！
- **真正的 MEM_ALLOC = 0xc0208005（nr=5，32 字节结构）**：
  0x20a5398 处理 → copy 0x20 字节 → 0x20a62ec `bl kbase_mem_alloc (0x2095f7c)`
  - 结构：{u64 va_pages; u64 commit_pages; u64 extent; u64 flags}（sp+0x18 起）
  - 0x20a62d4 ldp x1,x2,[sp+0x18]; ldr x3,[sp+0x28]; x4=&[x29-0x50](flags);
    w6=3 后端参数
- 所以笔记"MEM_ALLOC EPERM" = 号错 + 缺 SET_FLAGS 两步都占了

## 4. 本 build ioctl 号映射（部分，来自分发树 mov/movk 常量）
| ioctl | nr | 说明 |
|---|---|---|
| 0xc0048000 | 0 | VERSION_CHECK → 0x20a3c2c（state→1→2，不建 ctx） |
| 0x40048001 | 1 | SET_FLAGS → 0x20a3a24（state 2→3→4 关键） |
| 0xc0108006 | 6 | kbase_mem_query（probe 误当 MEM_ALLOC） |
| 0xc0208004 | 4 | MEM_*（32B）→ 0x20a489c 子分发 |
| 0xc0208005 | 5 | **MEM_ALLOC（32B）** → 0x20a5398 → kbase_mem_alloc |
| 0xc0208015 | 21 | MEM_*（32B）→ 0x20a5428 |
| 0xc0208016 | 22 | → EINVAL 默认(0x20a6440) |
| 0xc010801e | 30 | → 0x20a4380 区域 |
| 0xc0018035 | 53 | → 0x20a47fc 区域 |
| 0xc0018036 | 54 | → 0x20a5184 |
| 0xc0088033 | 51 | → 0x20a5220 |
| 0xc0108037 | 55 | 早处理（0x20a3a04 附近） |
| 0xc0108038 | 56 | 早处理 → 0x20a3cd0 |
| 0x4008800d | 13 | → 0x20a45f4 子分发（jump table） |

- 与上游 r38p0 编号不同（华为改号）。上游 MEM_ALLOC=_IOWR(0x80,31,32)=0xc020801f
  在本 build 不存在（只有 0xc0208005 nr=5）。

## 5. CVE-2023-4211 可利用性（在"SET_FLAGS 可用"限制下）
- CVE-2023-4211 需要：MEM_ALLOC 建 tracking region + mmap + munmap 拆 VMA + fork
- 关键：**0xc0208005 才是 MEM_ALLOC**，且要求 state==4（VERSION_CHECK→SET_FLAGS）
- SET_FLAGS OK → state=4 → **MEM_ALLOC(0xc0208005) 大概率可用** → CVE-4211 面打开
- 笔记"全部被封"结论基于错误 ioctl 号，需重测
- mmap EINVAL（mali_4211.c）：kbase_mmap 0x20a6d08 要求 state==4 ✓ 且 [kctx+0x10] 非空
  → kbase_context_mmap (0x2096d40)。offset=3 无对应 region → EINVAL 合理

## 6. 下一步实测（设备）
1. 序列：open → VERSION_CHECK(0xc0048000,{11,38}) → SET_FLAGS(0x40048001,
   flags∈0x7a 子集) → 验证 state=4（可先用 0xc0108006 query 试探）
2. MEM_ALLOC 用 **0xc0208005**，结构 {va_pages,commit_pages,extent,flags} 32 字节
   - flags 试 BASE_MEM_MAP_TRACKING_HANDLE(bit2=4?) / GROW_ON_GPF(bit6?)
3. 成功后 mmap(gpu_va) → munmap 半页 → fork → 父 munmap 剩余 → CVE-4211 drain
4. 若 MEM_ALLOC 仍 EPERM：反汇编 kbase_mem_alloc(0x2095f7c) 内部检查
