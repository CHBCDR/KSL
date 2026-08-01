/*
 * ksu_lkm_sct.c — KernelSU 提权 LKM（sys_call_table hook 版）v0.3
 *
 * v0.3 变更：PTE 补丁。真机疑似把 .bss 设只读（实测 hook 未生效、init
 *   走到 "page is RO, hook disabled" 分支）。现在页不可写时自动遍历页表
 *   改 PTE 的 AP 位（EL1 RO -> RW）+ flush TLB，然后写 hook，并读回验证。
 *   同时把页表遍历的每一级条目值都打印出来，便于远程诊断。
 *
 * 背景（为什么不是 tracepoint/ftrace 版）：
 *   1. ksu_lkm_tp.c（tracepoint 版）：真机内核未导出 __tracepoint_sched_process_exec，
 *      加载报 "Unknown symbol __tracepoint_sched_process_exec (err 0)"，死路。
 *   2. ksu_lkm_ft.c（ftrace 版）：真机 CONFIG_FUNCTION_TRACER 未启用，不可行。
 *   3. 本版：hook sys_call_table[__NR_execve]，只直接引用已确认导出的符号
 *      （kallsyms_lookup_name / printk / strncpy_from_user / param_ops_charp），
 *      其余符号全部 kallsyms_lookup_name 动态解析 → 零未知符号依赖。
 *      加载用 insmod（init_module）即可：vermagic 靠 workflow sed 对齐
 *      （4.14.141+），CRC 靠 kload 改名 __versions 跳过（或直接 insmod 也可，
 *      实测 insmod 能加载）。
 *
 * 原理：
 *   - kallsyms_lookup_name("el0_svc") 拿异常入口，反汇编找 "adrp x27, <page>"
 *     解析出 sys_call_table 地址（KALLSYMS_ALL=n 时数据符号不在 kallsyms）。
 *   - 校验 sct[221] == kallsyms_lookup_name("sys_execve")，地址错就 abort。
 *   - PTE 检查目标页可写；只读则 PTE 补丁（AP[2:1]=00）后写。
 *   - arm64 表项签名 long (*)(const struct pt_regs *)：regs->regs[0] 是 filename，
 *     白名单前缀命中且非 root → prepare_kernel_cred(NULL)+commit_creds() 提权。
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
#include <linux/io.h>
#include <linux/mm.h>
#include <asm/ptrace.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

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

/* ---- 遍历内核页表（TTBR1_EL1 + ioremap_cache，零数据符号依赖） ----
 * 返回: 1 = 找到 PTE（*out = 条目值）；0 = huge pmd（*out = pmd 值）；
 *      -1 = 失败。真机：VA_BITS=39, 4K 页, PGTABLE_LEVELS=3（pgd→pmd→pte）。 */
static int walk_pte(unsigned long addr, u64 *out)
{
	u64 ttbr1, e;
	u64 *tbl;

	asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));

	tbl = (u64 *)ioremap_cache(ttbr1 & PHYS_MASK, PAGE_SIZE);
	if (!tbl) {
		printk(KERN_ERR "ksu_sct: walk pgd ioremap fail\n");
		return -1;
	}
	e = tbl[pgd_index(addr)];
	iounmap(tbl);
	if ((e & 3) != 3) {
		printk(KERN_ERR "ksu_sct: pgd entry bad: 0x%llx\n", e);
		return -1;
	}

#if CONFIG_PGTABLE_LEVELS >= 4
	tbl = (u64 *)ioremap_cache(e & PHYS_MASK, PAGE_SIZE);
	if (!tbl) {
		printk(KERN_ERR "ksu_sct: walk pud ioremap fail\n");
		return -1;
	}
	e = tbl[pud_index(addr)];
	iounmap(tbl);
	if ((e & 3) != 3) {
		printk(KERN_ERR "ksu_sct: pud entry bad: 0x%llx\n", e);
		return -1;
	}
#endif

	tbl = (u64 *)ioremap_cache(e & PHYS_MASK, PAGE_SIZE);
	if (!tbl) {
		printk(KERN_ERR "ksu_sct: walk pmd ioremap fail\n");
		return -1;
	}
	e = tbl[pmd_index(addr)];
	iounmap(tbl);
	if ((e & 3) == 0) {
		printk(KERN_ERR "ksu_sct: pmd none: 0x%llx\n", e);
		return -1;
	}
	if ((e & 3) == 1) { /* huge block */
		if (out)
			*out = e;
		return 0;
	}

	tbl = (u64 *)ioremap_cache(e & PHYS_MASK, PAGE_SIZE);
	if (!tbl) {
		printk(KERN_ERR "ksu_sct: walk pte ioremap fail\n");
		return -1;
	}
	e = tbl[pte_index(addr)];
	iounmap(tbl);
	if ((e & 3) == 0) {
		printk(KERN_ERR "ksu_sct: pte none: 0x%llx\n", e);
		return -1;
	}
	if (out)
		*out = e;
	return 1;
}

static int va_writable(unsigned long addr)
{
	u64 pteval = 0;
	int r = walk_pte(addr, &pteval);

	if (r == 1)
		return (pteval & PTE_WRITE) != 0;
	if (r == 0) /* huge pmd */
		return (pteval & PTE_WRITE) != 0;
	return 0;
}

/* ---- PTE 补丁：把目标页改成 EL1 可写（AP[2:1] = 00）+ flush TLB ---- */
static int make_va_writable(unsigned long addr)
{
	u64 ttbr1, e;
	u64 *tbl;

	asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));

	tbl = (u64 *)ioremap_cache(ttbr1 & PHYS_MASK, PAGE_SIZE);
	if (!tbl)
		return 0;
	e = tbl[pgd_index(addr)];
	iounmap(tbl);
	if ((e & 3) != 3)
		return 0;

#if CONFIG_PGTABLE_LEVELS >= 4
	tbl = (u64 *)ioremap_cache(e & PHYS_MASK, PAGE_SIZE);
	if (!tbl)
		return 0;
	e = tbl[pud_index(addr)];
	iounmap(tbl);
	if ((e & 3) != 3)
		return 0;
#endif

	tbl = (u64 *)ioremap_cache(e & PHYS_MASK, PAGE_SIZE);
	if (!tbl)
		return 0;
	e = tbl[pmd_index(addr)];
	iounmap(tbl);
	if ((e & 3) != 3) /* huge 不支持（sys_call_table 在 .bss 4K 页，不会 huge） */
		return 0;

	tbl = (u64 *)ioremap_cache(e & PHYS_MASK, PAGE_SIZE);
	if (!tbl)
		return 0;
	tbl[pte_index(addr)] &= ~(3UL << 6); /* AP[2:1] = 00 -> EL1 RW */
	iounmap(tbl);

	/* 4.14 arm64 只有 flush_tlb_kernel_range（没有 flush_tlb_kernel_page） */
	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
	printk(KERN_INFO "ksu_sct: PTE patched writable @0x%lx\n", addr);
	return 1;
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
		printk(KERN_WARNING "ksu_sct: page not writable, PTE patch attempt "
		       "(sct=%p entry=%p)\n", sct, &sct[NR_EXECVE]);
		if (!make_va_writable((unsigned long)&sct[NR_EXECVE])) {
			printk(KERN_ERR "ksu_sct: PTE patch failed, hook disabled\n");
			return 0; /* 加载成功但不 hook，便于远程诊断 */
		}
		if (!va_writable((unsigned long)&sct[NR_EXECVE])) {
			printk(KERN_ERR "ksu_sct: still not writable after patch, "
			       "hook disabled\n");
			return 0;
		}
	}

	WRITE_ONCE(sct[NR_EXECVE], ksu_sys_execve);
	if (sct[NR_EXECVE] != ksu_sys_execve) {
		printk(KERN_ERR "ksu_sct: write verify failed, hook disabled\n");
		return 0;
	}
	printk(KERN_INFO "ksu_sct: sct=%p, execve hooked -> %ps, trigger=%s\n",
	       sct, ksu_sys_execve, ksu_path);
	return 0;
}

static void __exit ksu_sct_exit(void)
{
	if (sct && orig_sys_execve && sct[NR_EXECVE] == ksu_sys_execve)
		WRITE_ONCE(sct[NR_EXECVE], orig_sys_execve);
	printk(KERN_INFO "ksu_sct: unhooked\n");
}

module_init(ksu_sct_init);
module_exit(ksu_sct_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DS");
MODULE_DESCRIPTION("KSU root grant via sys_call_table execve hook (4.14 MT6771)");
MODULE_VERSION("0.3");
