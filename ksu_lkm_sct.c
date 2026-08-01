/*
 * ksu_lkm_sct.c — KernelSU 提权 LKM（sys_call_table hook 版）v0.6
 *
 * v0.6 变更：/sys 参数节点状态标记（diag_state）。
 *   实测：exit 能写 ksu_diag.txt 而 init 写不进（或 init 未执行），文件诊断
 *   不可靠。改为 module_param(diag_state, charp, 0444)——init 每走一步就更新
 *   diag_state 指针，用户 cat /sys/module/ksu_lkm_sct/parameters/diag_state
 *   即可看到 init 执行进度（0=init 没跑 / 1=在跑 / 5=hooked / 8=提权）。
 *   零依赖文件权限、dmesg、logcat。
 *
 * v0.5：直接定义 int init_module(void)（绕开 module_init 宏的 alias 机制）。
 * v0.4：写文件诊断（/data/local/tmp/ksu_diag.txt）。
 * v0.3：PTE 补丁（页只读时改 AP 位 + flush TLB + 写回验证）。
 *
 * 背景：tracepoint 版（真机未导出 __tracepoint_sched_process_exec）与
 *   ftrace 版（CONFIG_FUNCTION_TRACER 未启用）均死路。本版只直接引用
 *   已导出符号，其余 kallsyms_lookup_name 动态解析。加载用 insmod
 *   （init_module），vermagic 靠 workflow sed 对齐 4.14.141+。
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
#include <linux/fs.h>
#include <asm/ptrace.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

static char *ksu_path = "/data/local/tmp/ksu";
module_param(ksu_path, charp, 0644);
MODULE_PARM_DESC(ksu_path, "exec path prefix that triggers root grant");

/* 状态标记：init/hook 每步更新，cat /sys/module/ksu_lkm_sct/parameters/diag_state 查看 */
static char *diag_state = "0-init-not-run";
module_param(diag_state, charp, 0444);

#define NR_EXECVE 221 /* arm64 */
#define DIAG_FILE "/data/local/tmp/ksu_diag.txt"

typedef long (*syscall_fn_t)(const struct pt_regs *);
typedef struct cred *(*prepare_kernel_cred_t)(struct task_struct *);
typedef int (*commit_creds_t)(struct cred *);

static syscall_fn_t orig_sys_execve;
static prepare_kernel_cred_t p_prepare_kernel_cred;
static commit_creds_t p_commit_creds;
static syscall_fn_t *sct; /* sys_call_table */

/* ---- 写文件诊断（辅助通道，/sys diag_state 为主） ---- */
static void diag_log(const char *fmt, ...)
{
	struct file *f;
	va_list args;
	char buf[256];
	int n;
	loff_t pos;

	f = filp_open(DIAG_FILE, O_WRONLY | O_CREAT, 0644);
	if (IS_ERR(f))
		return;

	va_start(args, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	if (n > 0) {
		if (n >= (int)sizeof(buf))
			n = (int)sizeof(buf) - 1;
		pos = i_size_read(file_inode(f));
		kernel_write(f, buf, n, &pos);
	}
	filp_close(f, NULL);
}

/* ---- 自实现字符串函数 ---- */
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
		diag_log("el0_svc not in kallsyms\n");
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

		if (((insn[1] & 0xFFC00000) == 0x91000000) && ((insn[1] & 0x1F) == 27))
			addr += (insn[1] >> 10) & 0xFFF;

		diag_log("el0_svc=%lx ADRP x27 -> sct=0x%lx\n", el0, addr);
		return (syscall_fn_t *)addr;
	}
	diag_log("no ADRP x27 found in el0_svc=%lx\n", el0);
	return NULL;
}

/* ---- 遍历内核页表（TTBR1_EL1 + ioremap_cache） ----
 * 返回: 1 = PTE（*out=值）；0 = huge pmd；-1 = 失败。 */
static int walk_pte(unsigned long addr, u64 *out)
{
	u64 ttbr1, e;
	u64 *tbl;

	asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));

	tbl = (u64 *)ioremap_cache(ttbr1 & PHYS_MASK, PAGE_SIZE);
	if (!tbl) {
		diag_log("walk: pgd ioremap fail\n");
		return -1;
	}
	e = tbl[pgd_index(addr)];
	iounmap(tbl);
	if ((e & 3) != 3) {
		diag_log("walk: pgd bad 0x%llx\n", e);
		return -1;
	}

#if CONFIG_PGTABLE_LEVELS >= 4
	tbl = (u64 *)ioremap_cache(e & PHYS_MASK, PAGE_SIZE);
	if (!tbl) {
		diag_log("walk: pud ioremap fail\n");
		return -1;
	}
	e = tbl[pud_index(addr)];
	iounmap(tbl);
	if ((e & 3) != 3) {
		diag_log("walk: pud bad 0x%llx\n", e);
		return -1;
	}
#endif

	tbl = (u64 *)ioremap_cache(e & PHYS_MASK, PAGE_SIZE);
	if (!tbl) {
		diag_log("walk: pmd ioremap fail\n");
		return -1;
	}
	e = tbl[pmd_index(addr)];
	iounmap(tbl);
	if ((e & 3) == 0) {
		diag_log("walk: pmd none 0x%llx\n", e);
		return -1;
	}
	if ((e & 3) == 1) { /* huge block */
		if (out)
			*out = e;
		return 0;
	}

	tbl = (u64 *)ioremap_cache(e & PHYS_MASK, PAGE_SIZE);
	if (!tbl) {
		diag_log("walk: pte ioremap fail\n");
		return -1;
	}
	e = tbl[pte_index(addr)];
	iounmap(tbl);
	if ((e & 3) == 0) {
		diag_log("walk: pte none 0x%llx\n", e);
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
	if (r == 0)
		return (pteval & PTE_WRITE) != 0;
	return 0;
}

/* ---- PTE 补丁：AP[2:1] = 00（EL1 RW）+ flush TLB ---- */
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
	if ((e & 3) != 3) /* huge 不支持 */
		return 0;

	tbl = (u64 *)ioremap_cache(e & PHYS_MASK, PAGE_SIZE);
	if (!tbl)
		return 0;
	tbl[pte_index(addr)] &= ~(3UL << 6); /* AP[2:1] = 00 -> EL1 RW */
	iounmap(tbl);

	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
	diag_log("PTE patched writable @0x%lx\n", addr);
	return 1;
}

/* ---- hook: arm64 syscall 表项签名 fn(const struct pt_regs *) ---- */
static int diag_once;
static long ksu_sys_execve(const struct pt_regs *regs)
{
	const char __user *filename = (const char __user *)regs->regs[0];
	char buf[256];
	long n;

	if (!diag_once) {
		diag_once = 1;
		diag_state = "6-hook-called";
		diag_log("hook called first time\n");
	}

	n = strncpy_from_user(buf, filename, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = 0;
		if (k_strncmp(buf, ksu_path, k_strlen(ksu_path)) == 0 &&
		    current_uid().val != 0) {
			struct cred *new;

			diag_state = "7-matched";
			diag_log("match! pid=%d uid=%d file=%s\n",
				 current->pid, current_uid().val, buf);
			new = p_prepare_kernel_cred(NULL);
			if (new) {
				p_commit_creds(new);
				diag_state = "8-root-granted";
				diag_log("root granted pid=%d\n", current->pid);
			} else {
				diag_log("prepare_kernel_cred NULL!\n");
			}
		}
	}
	return orig_sys_execve(regs);
}

static int ksu_sct_init(void)
{
	unsigned long se, el0;
	int r;

	diag_state = "1-init-running";
	diag_log("=== ksu_sct init start ===\n");
	diag_log("ksu_path=%s\n", ksu_path ? ksu_path : "(null)");

	sct = find_sys_call_table();
	if (!sct) {
		diag_state = "2-no-sct";
		return -ENOENT;
	}
	diag_state = "2-sct-found";

	el0 = kallsyms_lookup_name("el0_svc");
	se = kallsyms_lookup_name("sys_execve");
	p_prepare_kernel_cred =
		(prepare_kernel_cred_t)kallsyms_lookup_name("prepare_kernel_cred");
	p_commit_creds = (commit_creds_t)kallsyms_lookup_name("commit_creds");

	diag_log("kallsyms: el0_svc=%lx sys_execve=%lx ppc=%p cc=%p\n",
		 el0, se, p_prepare_kernel_cred, p_commit_creds);

	if (!se || !p_prepare_kernel_cred || !p_commit_creds) {
		diag_state = "2-kallsyms-fail";
		return -ENOENT;
	}

	orig_sys_execve = sct[NR_EXECVE];
	diag_log("sct=%p sct[%d]=%p\n", sct, NR_EXECVE, orig_sys_execve);
	if ((unsigned long)orig_sys_execve != se) {
		diag_state = "3-sct-mismatch";
		return -EINVAL;
	}
	diag_state = "3-sct-verified";

	r = va_writable((unsigned long)&sct[NR_EXECVE]);
	diag_log("va_writable=%d\n", r);
	if (!r) {
		diag_state = "4-patching";
		if (!make_va_writable((unsigned long)&sct[NR_EXECVE])) {
			diag_state = "4-patch-failed";
			diag_log("PTE patch failed, hook disabled\n");
			return 0;
		}
		if (!va_writable((unsigned long)&sct[NR_EXECVE])) {
			diag_state = "4-still-ro";
			diag_log("still not writable after patch\n");
			return 0;
		}
		diag_state = "4-patched";
		diag_log("PTE patch verified writable\n");
	} else {
		diag_state = "4-writable";
	}

	WRITE_ONCE(sct[NR_EXECVE], ksu_sys_execve);
	if (sct[NR_EXECVE] != ksu_sys_execve) {
		diag_state = "4-verify-failed";
		diag_log("write verify FAILED\n");
		return 0;
	}
	diag_state = "5-hooked";
	diag_log("HOOK OK: sct[%d] -> %ps, trigger=%s\n",
		 NR_EXECVE, ksu_sys_execve, ksu_path);
	return 0;
}

static void ksu_sct_exit(void)
{
	if (sct && orig_sys_execve && sct[NR_EXECVE] == ksu_sys_execve)
		WRITE_ONCE(sct[NR_EXECVE], orig_sys_execve);
	diag_state = "9-exited";
	diag_log("=== unhooked ===\n");
	printk(KERN_INFO "ksu_sct: unhooked\n");
}

/* 用标准 module_init/module_exit 宏：生成 .initcall6.init 段。
 * 实测直接定义 init_module() 不执行（v0.5/v0.6），怀疑 MTK 内核
 * 的模块 init 走 initcall 段而非标准 mod->init 路径。 */
module_init(ksu_sct_init);
module_exit(ksu_sct_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DS");
MODULE_DESCRIPTION("KSU root grant via sys_call_table execve hook (4.14 MT6771)");
MODULE_VERSION("0.7");
