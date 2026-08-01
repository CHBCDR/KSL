# KSU LKM — MT6771 (4.14.141) 闭源内核 Root 授权模块

**当前主力：`ksu_lkm_sct.c` — sys_call_table hook 版**（真机实测可用路线）。

## 三个版本（按可行性排序）

| 文件 | 机制 | 状态 |
|---|---|---|
| `ksu_lkm_sct.c` | hook `sys_call_table[__NR_execve]` | ✅ **当前主力**，只依赖已导出符号 |
| `ksu_lkm_tp.c` | `sched_process_exec` tracepoint 探针 | ❌ **已死**：真机未导出 `__tracepoint_sched_process_exec`，加载报 `Unknown symbol`（2026-08-01 实测） |
| `ksu_lkm_ft.c` | ftrace hook `do_execveat_common` | ❌ **不可行**：真机 `CONFIG_FUNCTION_TRACER` 未启用 |

> ⚠️ **血泪教训（2026-08-01）**：tracepoint 在真机上事件可用（trace_pipe 能出），但 `__tracepoint_sched_process_exec` **没有 EXPORT_SYMBOL**——模块直接链接引用必然 `Unknown symbol (err 0)`，任何 flags 都救不了。**编译环境（realme 树导出）≠ 真机（MTK 魔改未导出）**，符号依赖必须以真机导出表为准。

## sys_call_table hook 版原理

- `kallsyms_lookup_name("el0_svc")` 拿异常入口，反汇编 `adrp x27, <page>`（+可选 `add`）解析出 `sys_call_table` 地址——KALLSYMS_ALL=n 时数据符号不在 kallsyms，只能这样拿
- 校验 `sct[221] == kallsyms_lookup_name("sys_execve")`，地址错即 abort，绝不盲写
- PTE 检查目标页可写（.bss 通常 RW；若 RO 则告警禁用、不 crash）
- 替换表项为自研函数：arm64 表项签名 `long (*)(const struct pt_regs *)`，从 `regs->regs[0]` 取 filename，白名单前缀命中且非 root → `prepare_kernel_cred(NULL)+commit_creds()` 提权 → 调原 sys_execve

**符号依赖**（全部已确认导出/可解析）：
- 直接链接：`kallsyms_lookup_name`、`printk`、`strncpy_from_user`、`param_ops_charp`（字符串函数自实现，零 lib 依赖）
- 动态解析：`sys_execve`、`prepare_kernel_cred`、`commit_creds`（kallsyms 文本符号）
- 加载用 `kload`（finit_module + `IGNORE_MODVERSIONS|IGNORE_VERMAGIC`）跳过 CRC/vermagic

## 编译

本机（Windows）没有 Linux + 交叉工具链，**用 GitHub Actions 云编译**：

1. 把 ksu_lkm/ 推到 GitHub 仓库（必须含 `.github/workflows/build-lkm.yml` 和根目录 `config.gz`）
2. Actions 自动跑：拉 `techyminati/android_kernel_realme_mt6771V`（lineage-18.1-rmui，完整树 4.14.142）→ 真机 config.gz → modules_prepare 后 **sed UTS_RELEASE 对齐 4.14.141+** → NDK clang 9.0.8 + GNU binutils 编译
3. 下载 artifact（ksu_lkm_sct.ko + kload）

本地预检（交付前必跑）：`powershell -ExecutionPolicy Bypass -File precheck/godbolt-precheck.ps1`（Godbolt ARM64 GCC -Werror 语法检查）。

## 设备端部署测试

```sh
adb push ksu_lkm_sct.ko kload /data/local/tmp/

# kload v2 带 flags，跳过 MODVERSIONS CRC / vermagic（toybox insmod 不认 -f，必须用 kload）
su -c '/data/local/tmp/kload'   # 应显示 "kload v2" 版本行
su -c '/data/local/tmp/kload /data/local/tmp/ksu_lkm_sct.ko ksu_path=/data/local/tmp/ksu'

# 确认 hook 成功（应看到 sct=0x... execve hooked）
su -c 'dmesg | grep ksu_sct'

# 触发提权测试（注意：shell 本身是 Magisk root，必须用普通用户触发，否则假阳性）
su -c 'cp /system/bin/sh /data/local/tmp/ksu && /data/local/tmp/ksu -c id'
# 期望输出: uid=0(root) gid=0(root) ...
```

卸载：
```sh
su -c 'rmmod ksu_lkm_sct'
```

## 故障排查速查（2026-08-01 实测经验）

| 现象 | 病因 |
|---|---|
| 无 SU 加载报 `Operation not permitted` | 正常，加载模块需要 CAP_SYS_MODULE |
| kload v2 报 `Exec format error` + dmesg 空 | ELF 头检查失败（文件损坏/非 arm64）或厂商魔改 |
| `Unknown symbol __tracepoint_* (err 0)` | tracepoint 符号未导出 → 换 sct 版 |
| `no symbol version for module_layout` | MODVERSIONS CRC 不匹配（无 Module.symvers），kload flags 可跳过 |
| `version magic 'X' should be 'Y'` | vermagic 不匹配，workflow 已 sed 对齐 |

## 已知限制 / TODO

- **SELinux**：只改 cred 不过 SELinux 域。enforcing 下提权进程仍属原域，部分操作会被拒。完整 KSU 需 hook selinux 检查（后续做）
- 若 sys_call_table 页被证实 RO：需 PTE 补丁（改 AP 位）后重试，模块已预留检测逻辑
- 触发方式是"路径白名单"，还不是完整 KSU 的 su 管理器架构——先验证机制，再叠功能

## 验证记录

- 2026-07-31：exec 监控跑通；真机 .config 解出；确认 FUNCTION_TRACER 未启用 → ftrace 版不可行
- 2026-08-01：tracepoint 版加载失败，实锤 `__tracepoint_sched_process_exec` 未导出 → 弃用；kload v2（finit_module flags）确认生效；写出 ksu_lkm_sct.c 并通过 Godbolt 预检
