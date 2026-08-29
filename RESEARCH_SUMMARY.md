# GhostLock 移植研究记录 — Huawei/HarmonyOS 5.10.43 (Kirin 990)

> 本文档记录对华为/HarmonyOS 设备（Kirin 990，内核 5.10.43，Android 12 基座，39-bit VA，4K 页）的安全研究与逆向分析过程。
> 内容聚焦：逆向方法论、内核布局结论、厂商安全机制差异、研究进展与待解问题。
> 不含可直接复现的利用代码。

---

## 1. 研究背景与目标

- **对象设备**：Kirin 990 5G，HarmonyOS 4.0.0.135，内核 5.10.43，串号 VEG0220402007450
- **内核版本串**：
  ```
  Linux version 5.10.43 (HarmonyOS@localhost) (Android (7485623, based on r416183b1)
  clang version 12.0.7) #1 SMP PREEMPT Wed Mar 27 19:19:02 CST 2024
  ```
- **研究目标**：在内核 5.10 的 futex/rtmutex 漏洞影响范围内（CVE-2026-43499 影响 2.6.39~6.1.175），
  验证该设备上是否存在可行的任意写原语，并研究华为对 SELinux/内核的魔改对绕过路径的影响。
- **约束**：P0 = 零内核 panic；测试尽量少做设备离线操作。

## 2. 设备与工具链

| 项 | 值 |
|---|---|
| 交叉编译 | Android NDK r27c（API 35），`TARGET_CONFIG=target_kirin_5_10.h` |
| 内核镜像 | `BOOT.img` 解压得到 ARM64 Image（gzip@0x800，wbits=31） |
| 符号表 | 内嵌 kallsyms（205839 符号，pre-6.4 布局），`_text = 0xffffffc010000000` |
| 反汇编器 | 自研 `a64dis.py`（对照 `rb_erase.asm` 等地面真值校验，命中率 ~90%） |
| 运行观测 | adb + `/proc/kallsyms`（受限）+ dropbox SYSTEM_LAST_KMSG（无 pstore/last_kmsg） |

### 2.1 崩溃日志获取（无 pstore 设备）

设备无 pstore、无 last_kmsg，但 dropbox 自动保存 `SYSTEM_LAST_KMSG`：

```bash
adb shell "dumpsys dropbox 2>/dev/null | grep SYSTEM_LAST_KMSG | tail -5"
adb shell "dumpsys dropbox --print SYSTEM_LAST_KMSG <时间戳> 2>/dev/null" > notes/kmsg_xxx.txt
```

## 3. 关键逆向结论

### 3.1 task_struct / cred 布局（镜像分析，非猜测）

- `task_struct`：cred=+0x7c0，comm=+0x7d0，seccomp=+0x870，pi_lock=+0x894，
  pi_waiters=+0x8a8，pi_top_task=+0x8b8，pi_blocked_on=+0x8c0，prio=+0x124
- `cred`：usage=+0x0，uid=+0x4，securebits=+0x24，caps=+0x28，security=+0x80
- `rt_mutex_waiter`（5.10 无 ww_ctx）：tree=+0x0，pi_tree=+0x18，task=+0x30，
  lock=+0x38，prio=+0x40，deadline=+0x48
- `mm_struct`：0x3a8（mm_alloc memset 大小），slab 对象 0x3c0
- futex hash 用 jhash2，与 kernelsnitch 实现一致（futex_wait_setup 反汇编验证）

### 3.2 华为 SELinux 魔改（重要差异）

- `/sys/fs/selinux/enforce` 是**只读恒 "1" stub**，不可写。
- `get_selinux_enforcing()` 反汇编 = `mov w0,#1; ret` —— **硬编码，不读任何状态变量**。
- `avc_has_perm` / `avc_has_perm_noaudit` 反汇编**完全不读 `selinux_state`**；
  内核文本对 selinux_state 所在页（0xffffffc013daf000）**零 adrp 引用**。
- 结论：该内核**没有运行时 permissive 模式**，写 `selinux_state` 无效且会破坏未知
  残留 .bss 字段（实测：写全 0 → 第 1 次路由崩；写 0x100 → 第 5 次路由崩）。
- 华为 ebitmap 布局与主线不同：node 的 `startbit` 在 +0x38，`MAPSIZE=0x180`
  （主线为 +0x10 / 64），permissive_map 相关字段需按此布局构造。

### 3.3 Mali kbase 驱动（CVE-2023-4211 方向，未完成）

- 华为改了 kbase ioctl 编号：真正的 `MEM_ALLOC = 0xc0208005`（nr=5，32B），
  主线 r38p0 的 `_IOWR(0x80,31,32)=0xc020801f` 在本 build 不存在。
- 状态机：`VERSION_CHECK(0xc0048000) → SET_FLAGS(0x40048001) → state=4` 后
  `MEM_ALLOC` 才可用；state 字段在 `kctx+0x20`，不等于 4 返回 -1 (EPERM)。
- 此方向因优先级低于主链，仅完成 ioctl 映射逆向，未做设备端利用验证。

## 4. 已实证的成果（设备端）

- **W2 写原语**：通过泄漏 child 的 task_struct 地址 → 写 cred 指针为 init_cred →
  child 变 root。设备端多次复现：
  ```
  DIAG=22 IDENT own=0 child=1 sib=0 (task=0xffffff8196da8000)
  DIAG=22 child CapEff=0x000001ffffffffff
  W2 ROOT: child CapEff=all-ones (cred=init_cred)!
  ```
- **IDENT 确认机制**：先 NULL 写 comm（task+0x7d0），再读 child/parent/sibling 的
  comm 是否变空，确认泄漏的 task 是 child 而非固定 idle task（0xffffff80193f2000
  跨 boot 重复出现，是固定系统任务，写它无效）。
- **写前 uid 验证**：cred 写后查询 child uid，非 0 立即中止（避免假候选空转一整轮）。

## 5. 当前阻塞点

1. **SELinux 绕过**：华为 enforcing 硬编码，无 permissive 模式；permissive_map 的
   ebitmap node 布局与主线不同（startbit@+0x38），v126f 用假 node 导致 init SIGSEGV。
   需构造正确布局的 node 使其生效。
2. **采样成功率**：EARLY 窗口（uptime 185-270s）内 child 上下文切换少，perf 采样
   常采到固定 idle task；window-time（480-595s）基带噪声大。命中 child 需多轮重试。
3. **finit_module**：child root 后 kallsyms 仍 errno=13（SELinux enforcing 阻止），
   模块加载路径未打通。

## 6. 经验教训（防呆清单）

1. **偏移必须从 kallsyms 真值核对**：运行时 offsets.json 曾全部错误（基线错），
   导致 W1 一直写错地址。修复：二进制内置防呆，`off_init_cred != 0x34944e0` 或
   `off_selinux_enforcing != 0x3dafa08` 时报错退出。
2. **"route verified" ≠ 写入落地**：华为 enforce 是只读 stub，路由成功不代表
   目标内存真被改。必须加第二级验证（写 sysctl 读回、probe 写 comm 读回）。
3. **华为 SELinux 无 permissive 模式**：不要按主线假设 `selinux_state.enforcing=0`
   即可放行。
4. **KASLR 关闭**：init_cred VA 0xffffffc0134944e0 固定，`data_addr = PAGE_OFFSET|offset`
   （PAGE_OFFSET=0xffffff8000000000），可静态推导。
5. **设备随机崩溃**（uptime 400-460s 等待窗口期间）偶发，与写入无关，需多轮容忍。

## 7. 待办 / 后续方向

- [ ] 按华为 ebitmap 布局（startbit@+0x38，MAPSIZE=0x180）构造合法 permissive_map node
- [ ] 提高 EARLY 采样命中率（采样窗口/CPU 选择调参）
- [ ] 打通 finit_module 路径（模块签名校验/加载网关研究）
- [ ] 整理完整逆向数据（kallsyms、ioctl 映射、ebitmap 布局）为可复用的资料集

## 8. 参考

- `README_KIRIN_510.md`：移植过程与版本历史
- `notes/研究笔记_崩溃分析.md`：崩溃分析与 rb_erase/rtmutex 逆向细节
- `notes/Mali_kbase_逆向结论.md`：kbase ioctl 映射
- `analysis/`：反汇编产物与 kallsyms
