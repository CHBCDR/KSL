/*
 * ksu_lkm_sct.c — KernelSU 提权 LKM（sys_call_table hook 版）— 真机可用版
 *
 * 背景（为什么不是 tracepoint/ftrace 版）：
 *   1. ksu_lkm_tp.c（tracepoint 版）：真机内核未导出 __tracepoint_sched_process_exec，
 *      加载报 "Unknown symbol __tracepoint_sched_process_exec (err 0)"，死路。
 *   2. ksu_lkm_ft.c（ftrace 版）：真机 CONFIG_FUNCTION_TRACER 未启用，不可行。
 *   3. 本版：hook sys_call_table[__NR_execve]，只直接引用已确认导出的符号
 *      （kallsyms_lookup_name / printk / strncpy_from_user / param_ops_charp），
 *      其余符号全部 kallsyms_lookup_name 动态解析 → 零未知符号依赖，kload
 *      （IGNORE_MODVERSIONS|IGNORE_VERMAGIC）可强制加载。
 *
 * 原理：
 *   - kallsyms_lookup_name("el0_svc") 拿异常入口，反汇编找 "adrp x27, <page>"
 *     解析出 sys_call_table 地址（KALLSYMS_ALL=n 时数据符号不在 kallsyms，
 *     只能这样拿；记忆：el0_svc @0xffffff88ba283f80 → sct @0xffffff88bb032000）。
 *   - 校验 sct[221] == kallsyms_lookup_name("sys_execve")，地址错就 abort。
 *   - PTE 检查 sys_call_table 所在页可写（.bss 通常 RW；若 RO 则告警禁用，
 *     不 crash，便于排查）。
 *   - 替换 sys_execve 表项：arm64 表项签名是 long (*)(const struct pt_regs *)，
 *     从 regs->regs[0] 拿 filename，白名单前缀命中且非 root →
 *     prepare_kernel_cred(NULL)+commit_creds() 标准提权，再调原 sys_execve。
 *
 * 加载（kload v2 带 flags）：
 *   kload /data/local/tmp/ksu_lkm_sct.ko ksu_path=/data/local/tmp/ksu
 * 测试（注意：shell 本身是 Magisk root，必须用普通用户触发，否则假阳性）：
 *   cp /system/bin/sh /data/local/tmp/ksu && /data/local/tmp/ksu -c id
 *
 * MODULE_LICENSE("GPL") 必须：kallsyms_lookup_name 是 EXPORT_SYMBOL_GPL。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <asm/ptrace.h>
#include <asm/pgtable.h>

static char *ksu_path = "/data/local/tmp/ksu";
module_param(ksu_path, charp, 0644);
MODULE_PARM_DESC(ksu_path, "exec path prefix that triggers root grant");

#define NR_EXECVE 221 /* arm64 */

typedef long (*syscall_fn_t)(const struct pt_regs *);
typedef struct cred *(*prepare_kernel_cred_t)(struct task_struct *);
typedef int (*commit_creds_t)(struct cred *);

static syscall_fn_t orig_sys_execve;
static prepare_kernel_cred_t p_prepare_kernel_cred;
static commit_creds_t p_commit_creds;
static syscall_fn_t *sct; /* sys_call_table */

/* ---- 自实现字符串函数，避免依赖 lib 导出符号 ---- */
static size_t k_strlen(const char *s)
{
	const char *p = s;
	while (*p)
		p++;
	return p - s;
}

static int k_strncmp(const char *a, const char *b, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		if (a[i] != b[i])
			return a[i] - b[i];
		if (!a[i])
			return 0;
	}
	return 0;
}

/* ---- 从 el0_svc 反汇编 ADRP x27 (+add) 解析 sys_call_table ---- */
static syscall_fn_t *find_sys_call_table(void)
{
	unsigned long el0 = kallsyms_lookup_name("el0_svc");
	u32 *insn;

	if (!el0) {
		printk(KERN_ERR "ksu_sct: el0_svc not in kallsyms\n");
		return NULL;
	}

	for (insn = (u32 *)el0; (unsigned long)insn < el0 + 256; insn++) {
		u32 w = *insn;
		long immhi, immlo, imm;
		unsigned long addr;

		if ((w & 0x9F000000) != 0x90000000) /* not ADRP */
			continue;
		if ((w & 0x1F) != 27)                /* not x27 */
			continue;

		immhi = (w >> 5) & 0x7FFFF;
		immlo = (w >> 29) & 0x3;
		imm = (immhi << 2) | immlo;
		if (imm & (1L << 20))                /* sign-extend 21bit */
			imm -= (1L << 21);

		addr = ((unsigned long)insn & ~0xFFFUL) + (imm << 12);

		/* 紧跟的 add x27, x27, #imm12（常见于 adrp/add 取地址对） */
		if (((insn[1] & 0xFFC00000) == 0x91000000) && ((insn[1] & 0x1F) == 27))
			addr += (insn[1] >> 10) & 0xFFF;

		printk(KERN_INFO "ksu_sct: el0_svc ADRP x27 -> sct=0x%lx\n", addr);
		return (syscall_fn_t *)addr;
	}
	printk(KERN_ERR "ksu_sct: no ADRP x27 found in el0_svc\n");
	return NULL;
}

/* ---- PTE 可写性检查（避免写只读页直接 oops） ---- */
static int va_writable(unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset_k(addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return 0;
	pud = pud_offset(pgd, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		return 0;
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return 0;
	if (pmd_trans_huge(*pmd) || pmd_devmap(*pmd))
		return (pmd_val(*pmd) & PTE_WRITE) != 0;
	if (pmd_bad(*pmd))
		return 0;
	pte = pte_offset_kernel(pmd, addr);
	if (pte_none(*pte))
		return 0;
	return (pte_val(*pte) & PTE_WRITE) != 0;
}

/* ---- hook: arm64 syscall 表项签名 fn(const struct pt_regs *) ---- */
static long ksu_sys_execve(const struct pt_regs *regs)
{
	const char __user *filename = (const char __user *)regs->regs[0];
	char buf[256];
	long n;

	n = strncpy_from_user(buf, filename, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = 0;
		if (k_strncmp(buf, ksu_path, k_strlen(ksu_path)) == 0 &&
		    current_uid().val != 0) {
			struct cred *new = p_prepare_kernel_cred(NULL);
			if (new) {
				p_commit_creds(new);
				printk(KERN_INFO "ksu_sct: ROOT granted pid=%d %s\n",
				       current->pid, buf);
			}
		}
	}
	return orig_sys_execve(regs);
}

static int __init ksu_sct_init(void)
{
	unsigned long se;

	sct = find_sys_call_table();
	if (!sct)
		return -ENOENT;

	se = kallsyms_lookup_name("sys_execve");
	p_prepare_kernel_cred =
		(prepare_kernel_cred_t)kallsyms_lookup_name("prepare_kernel_cred");
	p_commit_creds = (commit_creds_t)kallsyms_lookup_name("commit_creds");

	if (!se || !p_prepare_kernel_cred || !p_commit_creds) {
		printk(KERN_ERR "ksu_sct: kallsyms resolve failed "
		       "(sys_execve=%lx ppc=%p cc=%p)\n",
		       se, p_prepare_kernel_cred, p_commit_creds);
		return -ENOENT;
	}

	orig_sys_execve = sct[NR_EXECVE];
	if ((unsigned long)orig_sys_execve != se) {
		printk(KERN_ERR "ksu_sct: sct[%d]=%p != sys_execve=%lx, "
		       "sct addr wrong, abort\n", NR_EXECVE, orig_sys_execve, se);
		return -EINVAL;
	}

	if (!va_writable((unsigned long)&sct[NR_EXECVE])) {
		printk(KERN_ERR "ksu_sct: sys_call_table page is RO, hook disabled "
		       "(sct=%p entry=%p). Need PTE patch.\n",
		       sct, &sct[NR_EXECVE]);
		return 0; /* 模块加载成功但不 hook，便于排查 */
	}

	WRITE_ONCE(sct[NR_EXECVE], ksu_sys_execve);
	printk(KERN_INFO "ksu_sct: sct=%p, execve hooked -> %ps, trigger=%s\n",
	       sct, ksu_sys_execve, ksu_path);
	return 0;
}

static void __exit ksu_sct_exit(void)
{
	if (sct && orig_sys_execve &&
	    sct[NR_EXECVE] == ksu_sys_execve)
		WRITE_ONCE(sct[NR_EXECVE], orig_sys_execve);
	printk(KERN_INFO "ksu_sct: unhooked\n");
}

module_init(ksu_sct_init);
module_exit(ksu_sct_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DS");
MODULE_DESCRIPTION("KSU root grant via sys_call_table execve hook (4.14 MT6771)");
MODULE_VERSION("0.2");
