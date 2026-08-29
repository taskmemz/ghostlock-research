# GhostLock Research — Huawei/HarmonyOS 5.10.43 内核安全研究

针对华为 Kirin 990（HarmonyOS 4.0.0.135，内核 5.10.43）的安全研究资料集。

> ⚠️ 本仓库仅包含**研究笔记、逆向分析结论与技术文档**，不含可执行代码。
> 所有内容基于对设备内核镜像的静态分析及设备端行为观测。

## 内容

| 路径 | 说明 |
|---|---|
| `RESEARCH_SUMMARY.md` | 研究总结：方法论、内核布局结论、厂商安全机制差异、进展与阻塞点 |
| `notes/研究笔记_崩溃分析.md` | 崩溃分析记录（rb_erase / rtmutex 逆向、dropbox 日志获取方法） |
| `notes/Mali_kbase_逆向结论.md` | Mali kbase 驱动 ioctl 映射逆向 |
| `analysis/` | 反汇编产物与符号表（另备） |

## 研究主题

- 华为 SELinux 魔改分析（`get_selinux_enforcing` 硬编码、无 permissive 模式）
- 内核 5.10.43 布局逆向（task_struct / cred / rt_mutex_waiter / ebitmap）
- futex/rtmutex 漏洞影响面验证（CVE-2026-43499 范围 2.6.39 ~ 6.1.175）
- Mali kbase 驱动接口差异（CVE-2023-4211 面）

## 环境

- 设备：Kirin 990 5G，HarmonyOS 4.0.0.135，内核 5.10.43
- 工具：Android NDK r27c、自研 ARM64 反汇编器、内嵌 kallsyms 恢复
- 观测：adb / dropbox SYSTEM_LAST_KMSG（设备无 pstore/last_kmsg）
