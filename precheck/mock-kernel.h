/*
 * mock-kernel.h — 本地预检用：模拟 4.14 arm64 内核的关键类型/宏
 * 目的：在 Windows 上用 clang -fsyntax-only 对 ksu_lkm_*.c 做语法+类型预检，
 *       抓出 const 限定、类型不匹配、宏缺失等问题，再交付云编译。
 * 注意：只做编译期检查，不做语义正确性验证。
 */

#ifndef _MOCK_KERNEL_H
#define _MOCK_KERNEL_H

#include <stddef.h>

/* ---- 基础类型 ---- */
typedef unsigned int __u32;
typedef int __s32;
typedef __u32 u32;
typedef __s32 s32;
typedef unsigned long long u64;
typedef long long s64;
typedef unsigned long ulong;

typedef __u32 uid_t;
typedef __u32 gid_t;
typedef int pid_t;

/* kuid_t / kgid_t (4.14: struct { uid_t val; }) */
typedef struct { uid_t val; } kuid_t;
typedef struct { gid_t val; } kgid_t;

#define KUIDT_INIT(value) ((kuid_t){ value })
#define KGIDT_INIT(value) ((kgid_t){ value })
#define GLOBAL_ROOT_UID KUIDT_INIT(0)
#define GLOBAL_ROOT_GID KGIDT_INIT(0)
#define current_uid() (current->cred->uid)

/* ---- capabilities (4.14 kernel_cap_t) ---- */
#define _KERNEL_CAPABILITY_U32S 2
typedef struct { __u32 cap[_KERNEL_CAPABILITY_U32S]; } kernel_cap_t;
#define CAP_LAST_U32 ((_KERNEL_CAPABILITY_U32S) - 1)
#define CAP_LAST_CAP 38
#define CAP_FULL_SET ((kernel_cap_t) { { [0 ... CAP_LAST_U32] = 0xffffffffUL } })

/* ---- atomic ---- */
typedef struct { int counter; } atomic_t;
#define atomic_read(v) ((v)->counter)

/* ---- current ---- */
struct cred {
	kuid_t uid, euid, suid, fsuid;
	kgid_t gid, egid, sgid, fsgid;
	kernel_cap_t cap_inheritable, cap_permitted, cap_effective, cap_bset, cap_ambient;
	atomic_t usage;
};
struct task_struct {
	struct cred *cred;
	pid_t pid;
};
extern struct task_struct *current;

/* ---- linux_binprm ---- */
struct linux_binprm {
	const char *filename;
	void *interp;
};

/* ---- tracepoint (4.14 sched_process_exec, 带 old_pid) ---- */
struct tracepoint;
extern int tracepoint_probe_register(struct tracepoint *tp, void *probe, void *data);
extern int tracepoint_probe_unregister(struct tracepoint *tp, void *probe, void *data);
extern struct tracepoint __tracepoint_sched_process_exec;

#define DECLARE_TRACE_SCHED_PROCESS_EXEC \
	static inline int register_trace_sched_process_exec(void (*probe)(void *, struct task_struct *, pid_t, struct linux_binprm *), void *data) \
	{ return tracepoint_probe_register(&__tracepoint_sched_process_exec, (void *)probe, data); } \
	static inline int unregister_trace_sched_process_exec(void (*probe)(void *, struct task_struct *, pid_t, struct linux_binprm *), void *data) \
	{ return tracepoint_probe_unregister(&__tracepoint_sched_process_exec, (void *)probe, data); }

DECLARE_TRACE_SCHED_PROCESS_EXEC

/* ---- module 宏 ---- */
#define module_init(x)
#define module_exit(x)
#define MODULE_LICENSE(x)
#define MODULE_AUTHOR(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_VERSION(x)
#define MODULE_PARM_DESC(x, y)
#define __init
#define __exit

/* module_param(charp) — 源码里已声明变量，这里只需接受宏调用 */
#define module_param(name, type, perm)

/* printk / KERN_* */
#define KERN_INFO "6"
#define KERN_WARNING "4"
#define KERN_ERR "3"
#define printk(fmt, ...) (void)0

/* strncmp / strlen */
#include <string.h>
#include <errno.h>

/* ftrace 相关 (ksu_lkm_ft.c 用) */
struct pt_regs {
	unsigned long regs[31];
};
struct ftrace_ops {
	void (*func)(unsigned long ip, unsigned long parent_ip,
		     struct ftrace_ops *ops, struct pt_regs *regs);
	unsigned long flags;
};
#define FTRACE_OPS_FL_SAVE_REGS (1 << 0)
#define FTRACE_OPS_FL_RECURSION_SAFE (1 << 1)
struct filename {
	const char *name;
};
extern unsigned long kallsyms_lookup_name(const char *name);
static inline int ftrace_set_filter_ip(struct ftrace_ops *ops, unsigned long ip, int remove, int reset) { return 0; }
static inline int register_ftrace_function(struct ftrace_ops *ops) { return 0; }
static inline int unregister_ftrace_function(struct ftrace_ops *ops) { return 0; }

/* prepare_creds / commit_creds */
extern struct cred *prepare_creds(void);
extern int commit_creds(struct cred *new);

/* ---- sys_call_table hook 版 (ksu_lkm_sct.c) ---- */
#define __user

typedef long (*syscall_fn_t)(const struct pt_regs *);
extern struct cred *prepare_kernel_cred(struct task_struct *daemon);
extern long strncpy_from_user(char *dst, const char __user *src, long count);
#define WRITE_ONCE(x, val) ((x) = (val))

/* 页表 mock：手动遍历版（ksu_lkm_sct.c: va_writable，TTBR1+ioremap）*/
#define CONFIG_PGTABLE_LEVELS 3
#define CONFIG_ARM64_VA_BITS 48
#define VA_START (0xffffff8000000000UL)
#define PAGE_OFFSET (0xffffffc000000000UL)
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PHYS_MASK (~0xFFFUL)
#define PTE_WRITE (1UL << 7)
#define __iomem
#define pgd_index(addr) (((addr) >> 30) & 0x1FF)
#define pud_index(addr) (((addr) >> 21) & 0x1FF)
#define pmd_index(addr) (((addr) >> 21) & 0x1FF)
#define pte_index(addr) (((addr) >> 12) & 0x1FF)
extern void __iomem *ioremap_cache(unsigned long phys, unsigned long size);
extern void iounmap(void __iomem *addr);
/* 4.14 arm64: flush_tlb_kernel_page 不存在，用 flush_tlb_kernel_range */
#define flush_tlb_kernel_range(start, end) ((void)0)

/* 写文件诊断（v0.4）*/
#include <stdarg.h>
#include <stdio.h>
typedef long long loff_t;
typedef long ssize_t;
#define IS_ERR(x) ((unsigned long)(x) >= (unsigned long)-4095)
struct file {
	loff_t f_pos;
};
struct inode {
	loff_t i_size;
};
static inline struct inode *file_inode(const struct file *f) { (void)f; return 0; }
static inline loff_t i_size_read(const struct inode *inode) { return inode ? inode->i_size : 0; }
#define O_WRONLY 1
#define O_CREAT 64
#define O_APPEND 1024
extern struct file *filp_open(const char *path, int flags, int mode);
extern ssize_t kernel_write(struct file *file, const void *buf, size_t count, loff_t *pos);
extern int filp_close(struct file *file, void *dummy);

/* module_param_cb（v0.8 触发参数）*/
struct kernel_param;
struct kernel_param_ops {
	int (*set)(const char *val, const struct kernel_param *kp);
	int (*get)(char *buffer, const struct kernel_param *kp);
};
#define module_param_cb(name, ops, arg, perm)
extern int param_get_int(char *buffer, const struct kernel_param *kp);

#endif /* _MOCK_KERNEL_H */
