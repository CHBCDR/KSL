/*
 * ksu_lkm_sct.c — KSL 提权 LKM（sys_call_table hook 版）v0.11 诊断版
 *
 * v0.11（2026-08-02）：诊断专用，只报告、绝不写入。
 *   v0.9/v0.10 真机连续 panic 两次，共同点：都在访问 walk 算出的物理页时崩溃
 *   （v0.10 崩在写前读回预验证的读取本身）。v0.8 证明读页表（ioremap 表页+读表项）
 *   安全，但按 walk 结果访问 phys 会崩 → 怀疑 walk 在真机上返回了错误物理地址。
 *   本版：加载后只 walk + 报告所有表项和 phys，不做任何内存写入；
 *   加 sys_execve 文本地址交叉验证（内核镜像连续映射 → phys 差 == va 差，
 *   不等则 walk 布局有问题）。拿到真实数据后再设计写入方案。
 *
 * v0.10：别名写 + 写前读回预验证（真机仍 panic，崩在预验证读取）。
 * v0.9：ioremap 别名写 + AP 补丁（block 分支 bug，真机 panic）。
 * v0.8：module_param_cb(ksu_trigger) 触发 hook 初始化（MTK 不调 module init）。
 * v0.6：diag_state /sys 参数节点状态标记。
 * v0.5：直接定义 int init_module(void)。
 * v0.4：写文件诊断。v0.3：PTE 补丁。
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

/* 记录 hook 实际写入方式（本版无写入，恒为 none） */
static char *hook_method = "none";
module_param(hook_method, charp, 0444);

/* 触发参数：MTK 内核不调用模块 init（实测 mod->init 失效），
 * 但模块参数解析（parse_args）正常 → 把诊断初始化挂到参数 set 回调，
 * insmod 传 ksu_trigger=1 即触发（也可 echo 1 > /sys/.../parameters/ksu_trigger）。 */
static int ksu_trigger = 0;

static int ksu_hook_init(void);

static int ksu_trigger_set(const char *val, const struct kernel_param *kp)
{
	diag_state = "A-trigger-set";
	ksu_hook_init();
	return 0;
}

static const struct kernel_param_ops ksu_trigger_ops = {
	.set = ksu_trigger_set,
	.get = param_get_int,
};

module_param_cb(ksu_trigger, &ksu_trigger_ops, &ksu_trigger, 0644);

#define NR_EXECVE 221 /* arm64 */
#define DIAG_FILE "/data/local/tmp/ksu_diag.txt"

typedef long (*syscall_fn_t)(const struct pt_regs *);
typedef struct cred *(*prepare_kernel_cred_t)(struct task_struct *);
typedef int (*commit_creds_t)(struct cred *);

static syscall_fn_t orig_sys_execve;
static prepare_kernel_cred_t p_prepare_kernel_cred;
static commit_creds_t p_commit_creds;
static syscall_fn_t *sct; /* sys_call_table */

/* ---- 写文件诊断（每次打开追加，SELinux 可能拦，/sys diag_state 为主） ---- */
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

/* ---- diag_state 格式化（带缓冲），同步写文件，panic 后可从文件定位最后一步 ---- */
static char diag_buf[192];

static void diag_set(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(diag_buf, sizeof(diag_buf), fmt, args);
	va_end(args);
	diag_state = diag_buf;
	diag_log("diag: %s\n", diag_buf);
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

/* ---- 页表 walk 报告：逐级读表项并打印，返回 phys 和类型，不做任何写入 ----
 * 返回: 1 = 4K PTE，0 = 2MB block，-1 = 失败（各级表项已打印到 diag 文件） */
static int walk_report(unsigned long va, const char *tag, u64 *phys_out)
{
	u64 ttbr1, l0_e = 0, l1_e = 0, l2_e = 0, l3_e = 0;
	u64 *tbl;
	int type = -1;

	asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
	diag_log("[%s] va=%lx ttbr1=%llx\n", tag, va, ttbr1);

	tbl = (u64 *)ioremap_cache(ttbr1 & PHYS_MASK & PAGE_MASK, PAGE_SIZE);
	if (!tbl) {
		diag_log("[%s] pgd remap FAIL\n", tag);
		return -1;
	}
	l0_e = tbl[pgd_index(va)];
	iounmap(tbl);
	diag_log("[%s] pgd[%lu]=%llx\n", tag, (unsigned long)pgd_index(va), l0_e);
	if ((l0_e & 3) != 3) {
		diag_log("[%s] pgd entry invalid\n", tag);
		return -1;
	}

#if CONFIG_PGTABLE_LEVELS >= 4
	tbl = (u64 *)ioremap_cache(l0_e & PHYS_MASK & PAGE_MASK, PAGE_SIZE);
	if (!tbl) {
		diag_log("[%s] pud remap FAIL\n", tag);
		return -1;
	}
	l1_e = tbl[pud_index(va)];
	iounmap(tbl);
	diag_log("[%s] pud[%lu]=%llx\n", tag, (unsigned long)pud_index(va), l1_e);
	if ((l1_e & 3) != 3) {
		diag_log("[%s] pud entry invalid\n", tag);
		return -1;
	}
#else
	l1_e = l0_e;
#endif

	tbl = (u64 *)ioremap_cache(l1_e & PHYS_MASK & PAGE_MASK, PAGE_SIZE);
	if (!tbl) {
		diag_log("[%s] pmd remap FAIL\n", tag);
		return -1;
	}
	l2_e = tbl[pmd_index(va)];
	iounmap(tbl);
	diag_log("[%s] pmd[%lu]=%llx\n", tag, (unsigned long)pmd_index(va), l2_e);
	if ((l2_e & 3) == 0) {
		diag_log("[%s] pmd entry NONE\n", tag);
		return -1;
	}
	if ((l2_e & 3) == 1) { /* 2MB block */
		*phys_out = (l2_e & PHYS_MASK & ~((1UL << 21) - 1)) |
			    (va & ((1UL << 21) - 1));
		type = 0;
		diag_log("[%s] pmd BLOCK phys=%llx\n", tag, *phys_out);
		return type;
	}

	tbl = (u64 *)ioremap_cache(l2_e & PHYS_MASK & PAGE_MASK, PAGE_SIZE);
	if (!tbl) {
		diag_log("[%s] pte remap FAIL\n", tag);
		return -1;
	}
	l3_e = tbl[pte_index(va)];
	iounmap(tbl);
	diag_log("[%s] pte[%lu]=%llx\n", tag, (unsigned long)pte_index(va), l3_e);
	if ((l3_e & 3) == 0) {
		diag_log("[%s] pte entry NONE\n", tag);
		return -1;
	}
	*phys_out = l3_e & PHYS_MASK & PAGE_MASK;
	type = 1;
	diag_log("[%s] pte 4K phys=%llx\n", tag, *phys_out);
	return type;
}

/* ---- hook 函数（本版不安装，仅打印地址供下一版确认模块文本位置） ---- */
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

static int ksu_hook_init(void)
{
	unsigned long se, el0;
	u64 phys_sct = 0, phys_ex = 0;
	int r1, r2;

	diag_state = "1-init-running";
	diag_log("=== ksu_sct diag init start ===\n");
	diag_log("build: PGTABLE_LEVELS=%d VA_BITS=%d\n",
		 CONFIG_PGTABLE_LEVELS, CONFIG_ARM64_VA_BITS);
	diag_log("ksu_path=%s\n", ksu_path ? ksu_path : "(null)");
	diag_log("hook_fn=%ps\n", ksu_sys_execve);

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

	/* ---- 诊断阶段：只 walk 只报告，不做任何内存写入 ---- */
	diag_log("---- walk sct[%d] @ %p ----\n", NR_EXECVE, &sct[NR_EXECVE]);
	r1 = walk_report((unsigned long)&sct[NR_EXECVE], "sct", &phys_sct);

	diag_log("---- walk sys_execve @ %lx ----\n", se);
	r2 = walk_report(se, "execve", &phys_ex);

	if (r1 >= 0 && r2 >= 0) {
		unsigned long va_diff =
			(unsigned long)&sct[NR_EXECVE] - se;
		u64 phys_diff = (phys_sct > phys_ex) ?
				phys_sct - phys_ex : phys_ex - phys_sct;

		diag_log("CROSS: va_diff=%lx phys_diff=%llx\n", va_diff, phys_diff);
		if (va_diff == (unsigned long)phys_diff)
			diag_set("R-ok sct=%llx(%d) ex=%llx(%d) diff=%lx match",
				 phys_sct, r1, phys_ex, r2, va_diff);
		else
			diag_set("R-mismatch sct=%llx(%d) ex=%llx(%d) vd=%lx pd=%llx",
				 phys_sct, r1, phys_ex, r2, va_diff, phys_diff);
	} else {
		diag_set("R-walk-fail r1=%d r2=%d", r1, r2);
	}

	diag_log("=== diag done ===\n");
	return 0;
}

static void ksu_sct_exit(void)
{
	diag_state = "9-exited";
	diag_log("=== exited ===\n");
}

module_init(ksu_hook_init);
module_exit(ksu_sct_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DS");
MODULE_DESCRIPTION("KSL diag-only LKM (sys_call_table walk report, MT6771 4.14)");
MODULE_VERSION("0.11");
