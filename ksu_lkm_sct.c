/*
 * ksu_lkm_sct.c — KSL 提权 LKM（sys_call_table hook 版）v0.10
 *
 * v0.10 变更（2026-08-02）：
 *   v0.9 真机 panic（死机重启）。根因：make_va_writable 的 2MB block 分支
 *   用 block 描述符当页表地址 remap（block 的 bit[20:12] 是保留位），
 *   写到了内核镜像自身内存 → 内核崩溃。同时说明：sct 页确实是 2MB block
 *   映射（walk 到 pmd 级为 block），且别名写在真机上未走通。
 *   - 删除 AP 补丁兜底（不再有任何改页表/写未知地址的操作）
 *   - 别名写加"写前读回预验证"：先从新映射读回原值，必须等于预期值
 *     （sys_execve）才证明物理地址正确，否则绝不下笔 → 不可能写坏内存
 *   - 失败一律安全报告，不再尝试高风险路径
 *
 * v0.9：ioremap 别名写 + AP 补丁（block 分支有 bug，真机 panic）。
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

/* 记录 hook 实际写入方式：alias / patch / none */
static char *hook_method = "none";
module_param(hook_method, charp, 0444);

/* 触发参数：MTK 内核不调用模块 init（实测 mod->init 失效），
 * 但模块参数解析（parse_args）正常 → 把 hook 初始化挂到参数 set 回调，
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

/* ---- diag_state 格式化（带缓冲，失败时给出具体位置） ---- */
static char diag_buf[192];

static void diag_set(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(diag_buf, sizeof(diag_buf), fmt, args);
	va_end(args);
	diag_state = diag_buf;
}

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

/* ---- 遍历内核页表（TTBR1_EL1，ioremap 读表） ----
 * 返回: 1 = 4K PTE（*pte_out=PTE 值，*phys_out=页物理基址）
 *       0 = 2MB block（*pte_out=块描述符，*phys_out=含块内偏移的物理地址）
 *      -1 = 失败（diag_state 已给出具体原因） */
static int walk_va(unsigned long va, u64 *pte_out, u64 *phys_out)
{
	u64 ttbr1, e;
	u64 *tbl;

	asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));

	tbl = (u64 *)ioremap_cache(ttbr1 & PHYS_MASK & PAGE_MASK, PAGE_SIZE);
	if (!tbl) {
		diag_set("W-pgd-remap-fail");
		return -1;
	}
	e = tbl[pgd_index(va)];
	iounmap(tbl);
	if ((e & 3) != 3) {
		diag_set("W-pgd-bad=%llx", e);
		return -1;
	}

#if CONFIG_PGTABLE_LEVELS >= 4
	tbl = (u64 *)ioremap_cache(e & PHYS_MASK & PAGE_MASK, PAGE_SIZE);
	if (!tbl) {
		diag_set("W-pud-remap-fail");
		return -1;
	}
	e = tbl[pud_index(va)];
	iounmap(tbl);
	if ((e & 3) != 3) {
		diag_set("W-pud-bad=%llx", e);
		return -1;
	}
#endif

	tbl = (u64 *)ioremap_cache(e & PHYS_MASK & PAGE_MASK, PAGE_SIZE);
	if (!tbl) {
		diag_set("W-pmd-remap-fail");
		return -1;
	}
	e = tbl[pmd_index(va)];
	iounmap(tbl);
	if ((e & 3) == 0) {
		diag_set("W-pmd-none=%llx", e);
		return -1;
	}
	if ((e & 3) == 1) { /* 2MB block */
		if (pte_out)
			*pte_out = e;
		if (phys_out)
			*phys_out = (e & PHYS_MASK & ~((1UL << 21) - 1)) |
				    (va & ((1UL << 21) - 1));
		return 0;
	}

	tbl = (u64 *)ioremap_cache(e & PHYS_MASK & PAGE_MASK, PAGE_SIZE);
	if (!tbl) {
		diag_set("W-pte-remap-fail");
		return -1;
	}
	e = tbl[pte_index(va)];
	iounmap(tbl);
	if ((e & 3) == 0) {
		diag_set("W-pte-none=%llx", e);
		return -1;
	}
	if (pte_out)
		*pte_out = e;
	if (phys_out)
		*phys_out = (e & PHYS_MASK & PAGE_MASK);
	return 1;
}

/* ---- 写入：ioremap 物理页别名（新 RW 映射），带写前读回预验证 ----
 * 下笔前先从新映射读回原值，必须等于 expect（sys_execve）才证明
 * phys 正确；否则绝不下笔 → 物理地址错误时不可能写坏内存。 */
static int write_via_alias(unsigned long va, syscall_fn_t fn, syscall_fn_t expect)
{
	u64 pte = 0, phys = 0;
	syscall_fn_t *t, orig;
	void *m;
	int r = walk_va(va, &pte, &phys);

	if (r < 0)
		return 0; /* walk 失败时 diag_state 已设置 */

	diag_set("5a-walk-ok type=%d phys=%llx pte=%llx", r, phys, pte);
	m = ioremap_cache(phys & PAGE_MASK, PAGE_SIZE);
	if (!m) {
		diag_set("5a-remap-fail phys=%llx", phys);
		return 0;
	}
	t = (syscall_fn_t *)((char *)m + (va & (PAGE_SIZE - 1)));
	orig = *t; /* 读回预验证 */
	if (orig != expect) {
		diag_set("5a-phys-mismatch got=%p want=%p phys=%llx",
			 (void *)orig, (void *)expect, phys);
		iounmap(m);
		return 0;
	}
	WRITE_ONCE(*t, fn);
	if (*t != fn) {
		diag_set("5a-write-fail phys=%llx", phys);
		iounmap(m);
		return 0;
	}
	iounmap(m);
	hook_method = (r == 0) ? "alias-block" : "alias-4k";
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

static int ksu_hook_init(void)
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

	/* 1) 首选：ioremap 物理页别名写（写前读回预验证，物理地址错则绝不下笔） */
	r = write_via_alias((unsigned long)&sct[NR_EXECVE], ksu_sys_execve,
			    orig_sys_execve);
	if (r && sct[NR_EXECVE] == ksu_sys_execve) {
		diag_log("HOOK OK via %s: sct[%d] -> %ps, trigger=%s\n",
			 hook_method, NR_EXECVE, ksu_sys_execve, ksu_path);
		diag_state = "5-hooked";
		return 0;
	}

	/* 2) 别名路径失败：安全放弃，绝不再尝试任何写操作（防 panic）。
	 *    diag_state 已给出具体原因（5a-* 或 W-*）。 */
	if (r == 0)
		return 0;

	/* r==1 但原映射读回不一致：缓存/映射异常，报告即可 */
	diag_set("5a-orig-verify-fail");
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
module_init(ksu_hook_init);
module_exit(ksu_sct_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DS");
MODULE_DESCRIPTION("KSL root grant via sys_call_table execve hook (4.14 MT6771)");
MODULE_VERSION("0.10");
