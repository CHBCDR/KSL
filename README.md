# KSU-like LKM — MT6771 (4.14.141) 闭源内核 Root 授权模块

旧仓库：[https://github.com/CHBCDR/ksu-lkm](https://github.com/CHBCDR/ksu-lkm)（已弃用，2026-08-02 改名 CHBCDR/KSL）

由 DeepSeek V4 Flash 编写

> 🎯 **项目定位（2026-08-02 定稿）**：不追求复刻 KernelSU——闭源内核上本质不可能（无源码打补丁、无 GKI、KPROBES=n、eBPF 只能看不能改、FUNCTION_TRACER 未启用）。
> 目标是自研 **KSU-like** 最小内核授权：LKM 加载 + 内核态提权 + 轻量 su 接口。**验收标准是"机制能跑"，不是"像 KSU"。** 不做 Manager app / overlayfs / 模块管理。

**当前主力：`ksu_lkm_sct.c` v0.19** —— sys_call_table hook 版，**真机全链路验证通过（含用户态 uid=0 输出）**。

## ✅ 当前状态（2026-08-05）

v0.19 真机闭环：非 root 进程（uid 2000）execve 前缀命中 `/data/local/tmp/ksu` → 内核 hook 提权（uid/gid=0 + 全 caps）→ **保留调用者 SELinux 域** → 用户态完全可用：

```
su 2000 -c /data/local/tmp/ksu
uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0
```

| 环节 | 状态 |
|---|---|
| 写入路径（P2 direct / P3 patched AP 补丁） | ✅ 两条路线均真机验证 |
| hook 签名（4.14 arm64 用户参数直传） | ✅ 无死机 |
| 符号解析（偏移推算 + 0xffff 防御） | ✅ |
| 内核态提权 | ✅ |
| 用户态 uid=0 输出 | ✅ 首次（v0.19） |
| SELinux 域保留 | ✅ magisk:s0（v0.19 修复） |

## 版本史

| 版本 | 关键变化 | 状态 |
|---|---|---|
| v0.8 | module_param_cb(ksu_trigger) 触发 hook 初始化（MTK 不调 module init） | ✅ |
| v0.9~v0.14 | 写入方案演进（线性别名 → panic）；v0.14 表页不在线性映射 → 垃圾 VA 写坏内存 | ❌ panic |
| v0.15 | ioremap 表页 + 内容预验证 + P1~P8 前置日志 | ✅ |
| v0.16 | hook 去掉热路径文件写；pstore 实锤死机根因 = **hook 签名错误** | ✅ 诊断 |
| v0.17 | 签名修正（4.14 arm64 syscall 表项 = 用户参数直传，非 fn(pt_regs)） | ✅ 不再死机 |
| v0.18 | ppc/cc 用 sys_execve + 同固件偏移推算 + 地址防御；重启后复现；修正 %p hash 认知 | ✅ 内核态提权 |
| **v0.19** | **prepare_creds() 只改 uid/gid/caps，保留 SELinux 域**（v0.18 的 kernel:s0 域导致提权后不可用） | ✅ **全链路闭环** |

## sys_call_table hook 版原理（v0.19 现行）

- `kallsyms_lookup_name("el0_svc")` 拿异常入口，反汇编 `adrp x27, <page>` 解析出 `sys_call_table` 地址（KALLSYMS_ALL=n 时数据符号不在 kallsyms，只能这样拿）
- 校验 `sct[221] == kallsyms_lookup_name("sys_execve")`，地址错即 abort，绝不盲写
- **写入方案**：ioremap 表页物理页 → 读回内容预验证（必须与页表 walk 描述符一致）→ 必要时清 PTE AP 位（P3 patched）→ 写表项。表页物理地址在 ~120GB 高位保留区，**不在线性映射内**（v0.14 的雷），只能 ioremap；镜像区数据页访问即 fault、表页 walk 正常（真机实测）
- **hook 签名（死机根因，pstore 实锤）**：4.14 arm64 syscall 表项 = **用户参数直传**（SYSCALL_DEFINE 风格，x0 = 第一个参数 = filename）。不是 `fn(pt_regs)`（arm64 4.17 才改）。旧签名把用户 pathname 当 pt_regs → EL1 读用户内存（PAN）→ oops 死机
- **提权（v0.19）**：`prepare_creds()` 复制当前 cred → 只改 uid/euid/suid/fsuid、gid 系列为 0、caps 全满 → `commit_creds()`。**关键：不用 `prepare_kernel_cred(NULL)`**——它返回 init_cred 副本，带 `kernel:s0` 域，commit 后进程写终端/读文件全被 SELinux 拒（exit 1 无输出，avc denied 实锤）
- 热路径不写文件/不睡眠，诊断只靠 `diag_state` 参数节点

## 符号依赖

- 直接链接：`kallsyms_lookup_name`、`printk`、`strncpy_from_user`、`param_ops_charp`（字符串函数自实现，零 lib 依赖）
- 动态解析（kallsyms 直查）：`el0_svc`、`sys_execve`
- 动态解析（同固件偏移推算，KASLR 平移不变；固件升级需重新标定）：
  - `prepare_creds = sys_execve - 0x194cb4`（2026-08-05 真机 kptr_restrict=0 标定）
  - `commit_creds = sys_execve - 0x194910`
  - 防御：推算值高 16 位必须 0xffff，否则不装 hook
- 加载用 `kload`（finit_module + `IGNORE_MODVERSIONS|IGNORE_VERMAGIC`）跳过 CRC/vermagic

## 编译

本机（Windows）没有 Linux + 交叉工具链，**用 GitHub Actions 云编译**：

1. 把 ksu_lkm/ 推到 GitHub 仓库（必须含 `.github/workflows/build-lkm.yml` 和根目录 `config.gz`）
2. Actions 自动跑：拉 `techyminati/android_kernel_realme_mt6771V`（lineage-18.1-rmui，完整树 4.14.142）→ 真机 config.gz → modules_prepare 后 **sed UTS_RELEASE 对齐 4.14.141+** → NDK clang 9.0.8 + GNU binutils 编译
3. 下载 artifact（ksu_lkm_sct.ko + kload）

本地预检（交付前必跑）：`powershell -ExecutionPolicy Bypass -File precheck/godbolt-precheck.ps1`（Godbolt ARM64 GCC -Werror 语法检查）。

## 设备端部署测试（v0.19 验证流程）

```sh
adb push ksu_lkm_sct.ko /data/local/tmp/

# 加载：toybox insmod 走 init_module（MTK 魔改只认 init_module，finit_module 被静默拒绝）
# ⚠️ 必须带 ksu_trigger=1：MTK 不调用模块 init，hook 初始化挂在参数回调上，不带就永远不生效
su -c 'insmod /data/local/tmp/ksu_lkm_sct.ko ksu_path=/data/local/tmp/ksu ksu_trigger=1'
# 若报 CRC/vermagic 错，退回 kload（跳过 MODVERSIONS）：
#   su -c '/data/local/tmp/kload /data/local/tmp/ksu_lkm_sct.ko ksu_path=/data/local/tmp/ksu ksu_trigger=1'

# 确认 hook 装好（dmesg 被 wlan 刷屏不可靠，看 diag_state 参数节点）
su -c 'cat /sys/module/ksu_lkm_sct/parameters/diag_state'   # 期望 5-hooked via slot[13] (patched/direct)

# 准备触发文件（shebang 脚本；hook 按 execve 前缀匹配，与文件内容无关）
su -c "printf '#!/system/bin/sh\nid\n' > /data/local/tmp/ksu && chmod 755 /data/local/tmp/ksu"

# 触发提权（⚠️ 必须 uid 2000 触发：shell 本身是 Magisk root，直接跑是假阳性）
su 2000 -c /data/local/tmp/ksu
# 期望输出: uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0

su -c 'cat /sys/module/ksu_lkm_sct/parameters/diag_state'   # 期望 8-root-granted
su -c 'tail -5 /data/local/tmp/ksu_diag.txt'                # 符号地址应全部 0xffffff...（%px）
```

卸载：`su -c 'rmmod ksu_lkm_sct'`

## 关键排障经验（血泪史）

| 现象 | 病因 / 解法 |
|---|---|
| hook 触发即死机，pstore 显示 `ksu_sys_execve+0x44` / `Accessing user space memory outside uaccess.h` | **hook 签名错**：4.14 arm64 表项是用户参数直传（x0=filename），不是 fn(pt_regs)。旧签名把用户 pathname 当 pt_regs → PAN fault |
| 写入表页 panic，FAR 是 vmalloc 区垃圾地址 | 表页物理地址 ~120GB 不在线性映射内，不能用线性偏移公式算别名（v0.14）。改 ioremap + 内容预验证（v0.15） |
| "提权成功"（8-root-granted）但程序无输出 exit 1 | **SELinux 域崩**：prepare_kernel_cred(NULL) 带 kernel:s0 域，commit 后写 devpts/读文件全被拒（avc denied 实锤）。改 prepare_creds() 保留原域（v0.19） |
| diag_log 里符号地址像"垃圾"（0x3bd6e728）但功能正常 | **MTK printk 对 %p 做启动盐 hash**，打印不可信。改用 %px；kallsyms 直查实际正常 |
| /proc/kallsyms 地址全 0 | kptr_restrict=2，root 下 `echo 0 > /proc/sys/kernel/kptr_restrict` 放开（用完建议恢复） |
| finit_module 报 ENOEXEC + dmesg 空 | MTK 魔改只认 init_module；用 toybox insmod |
| insmod 后 hook 不生效 | MTK 不调 module init，必须带 ksu_trigger=1（参数回调触发） |
| `version magic 'X' should be 'Y'` | vermagic 不匹配，workflow 已 sed 对齐 4.14.141+ |

## 已知限制 / TODO

- 触发方式 = 路径前缀白名单（`ksu_path`），**文件不存在也提权**（hook 在 orig 之前完成 cred 替换，与文件内容无关）——设计如此，后续可加 uid/comm 白名单收紧
- 提权保留调用者 SELinux 域（magisk/shell），不是 KSU 的完整域切换；如需 system 域级别能力需另行 hook selinux 检查
- 轻量 su 接口（userspace 前端）未做——内核授权已就位，补个壳就是完整方案
- 偏移推算依赖同固件（固件升级需重新标定 prepare_creds/commit_creds）

## 验证记录

- 2026-07-31：exec 监控跑通；真机 .config 解出；确认 FUNCTION_TRACER 未启用 → ftrace 版不可行
- 2026-08-01：tracepoint 版加载失败，实锤 `__tracepoint_sched_process_exec` 未导出 → 弃用；kload v2（finit_module flags）确认生效；写出 ksu_lkm_sct.c 并通过 Godbolt 预检
- 2026-08-02：v0.8~v0.15 真机排障（hook 死机、写入 panic），pstore 全程取证
- 2026-08-04：v0.16 签名根因定位（pstore 铁证）；v0.17 不再死机、写入路径跑通；v0.18 提权复现（8-root-granted ×2）
- 2026-08-05：v0.18 修正认知（%p hash、kernel:s0 域锁死用户态）；**v0.19 prepare_creds 保留域 → 首次用户态 uid=0 输出，全链路闭环**
