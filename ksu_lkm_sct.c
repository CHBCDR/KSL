/*
 * ksu_lkm_sct.c — KSL 提权 LKM（sys_call_table hook 版）v0.18
 *
 * v0.18（2026-08-04）：ppc/cc 符号解析改推算 + 防御。
 *   真机 v0.17 实测：kallsyms_lookup_name("prepare_kernel_cred") 返回
 *   0x3bd6e728、("commit_creds") 返回 0x25088d9e —— 用户空间垃圾值！
 *   （el0_svc/sys_execve 等符号正常，仅这两个异常 → MTK kallsyms 表/查找
 *   对该两符号有问题。）若直接用，提权时 blr 垃圾地址 → 死机。
 *   修复：用 sys_execve（kallsyms 查询可靠）+ 同固件固定偏移推算：
 *     prepare_kernel_cred = sys_execve - 0x19455c
 *     commit_creds        = sys_execve - 0x194910
 *   （偏移来自 2026-08-01 真机 kallsyms 记录；KASLR 整体平移不改变相对
 *   偏移，同固件可靠；固件升级需重新标定。）
 *   防御：推算值必须在内核地址空间（高 16 位 0xffff），否则不装 hook。
 *
 * v0.17（2026-08-04）：hook 签名修正 —— 4.14 arm64 syscall 表项是
 *   **用户参数直传**（SYSCALL_DEFINE 风格，x0=第一个参数），不是 fn(pt_regs)！
 *   （arm64 从 4.17 才改成 pt_regs 风格。）
 *   真机 pstore 铁证（v0.16）：
 *     PC = ksu_sys_execve+0x40 = LDR x1,[x0]，x0 = 0x70cf207350（用户地址，
 *     execve 的 pathname），x26=0xdd（221），x27=sys_call_table
 *     “Internal error: Accessing user space memory outside uaccess.h routines”
 *     → EL1 访问用户内存 → oops → die → exception reboot（死机）
 *   旧签名 long hook(const struct pt_regs *) 把用户 pathname 当 pt_regs 指针，
 *   regs->regs[0] 即读用户地址 → 必死机。v0.14 的 +0x44 崩溃也是同一原因
 *   （读 [x0]），此前“垃圾 VA 写坏内存”的判断作废。
 *   v0.17 真机：hook 不再死机（diag_state=6-hook-called），写入路径完整
 *   成功（5-hooked patched）—— 签名修复 + ioremap 写入方案双验证通过。
 *
 * v0.16（2026-08-04）：hook 函数去掉文件写（diag_log）。
 *   注：v0.16 的写入路径（ioremap 表页补丁）insmod 时未崩、hook 装上了
 *   （pstore 显示 insmod 成功、bash 下一条 execve 才死机）——写入方案本身
 *   真机成立。
 *
 * v0.15（2026-08-02）：表页补丁改用 ioremap + 内容预验证 + 前置日志。
 *   v0.14 真机 panic。根因（分析）：表页物理地址在 ~120GB 高位保留区
 *   （pgd[262]=0x1bfff6803 等，超出线性映射覆盖的 1-9GB 范围），v0.14 用
 *   线性偏移公式（只对线性映射内 phys 成立）去算表页别名 → 得到垃圾 VA，
 *   若恰落在某个 vmalloc 映射上，写表项即写坏内核内存 → panic。
 *   v0.15 修正：
 *   - 表页补丁改用 ioremap（真机所有 walk 都在 ioremap 这些表页并成功读取）
 *   - 内容预验证：写表项前先经 ioremap 读回当前值，必须等于 walk 读到的
 *     描述符（lin_desc）才证明表页/索引正确，否则绝不下笔
 *   - 每步前置日志：任何一步崩了，/data/local/tmp/ksu_diag.txt 都能
 *     精确指出崩在哪一步
 *   - 补丁后重走 cand 确认 AP 已清，再写 sct 表项
 *
 * v0.14：线性别名补丁（表页不在线性映射内 → panic）。
 * v0.13：pgd 扫描 + slot 自动推导（真机命中线性映射，叶 RO）。
 * v0.12：PAGE_OFFSET 候选线性别名（真机 R-no-candidate）。
 * v0.11：诊断版（只 walk 只报告，真机跑通）。
 * v0.10：别名写 + 读回预验证（真机 panic：ioremap 镜像区页访问 fault）。
 * v0.9：ioremap 别名写 + AP 补丁（block 分支 bug，真机 panic）。
 * v0.8：module_param_cb(ksu_trigger) 触发 hook 初始化（MTK 不调 module init）。
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
#include <linux/uidgid.h>
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

/* v0.20: uid whitelist, comma-separated ("2000,10105"); empty = any uid */
static char *ksu_uids = "";
module_param(ksu_uids, charp, 0644);
MODULE_PARM_DESC(ksu_uids, "comma-separated uid whitelist for root grant; empty = any non-root uid");

/* 状态标记：init/hook 每步更新，cat /sys/module/ksu_lkm_sct/parameters/diag_state 查看 */
static char *diag_state = "0-init-not-run";
module_param(diag_state, charp, 0444);

/* 记录 hook 实际写入方式：direct / patched / none */
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

/* v0.20 (2026-08-05): optional uid whitelist via ksu_uids module param.
 * Default empty = grant any non-root uid (v0.19 behavior unchanged, no
 * regression). Set e.g. ksu_uids=2000 to only grant uid 2000 (shell).
 */
/* v0.19 (2026-08-05): fix SELinux domain breakage from v0.18.
 * v0.18 used prepare_kernel_cred(NULL) -> cred carries kernel:s0 domain,
 * SELinux denied terminal writes / file access after commit_creds
 * (avc denied, scontext=u:r:kernel:s0, comm=sh) -> "8-root-granted" but
 * the process could not run (exit 1, no output). Root never usable.
 * v0.19: use prepare_creds() and only change uid/gid/caps, keep the
 * caller's SELinux domain. Offsets re-calibrated on device 2026-08-05:
 *   prepare_creds = sys_execve - 0x194cb4
 *   commit_creds  = sys_execve - 0x194910 (unchanged)
 */
#define NR_EXECVE 221 /* arm64 */
#define DIAG_FILE "/data/local/tmp/ksu_diag.txt"

/* v0.18：MTK kallsyms 对 ppc/cc 直查返回垃圾 → 用 sys_execve 推算。
 * 偏移来自 2026-08-01 真机 kallsyms：
 *   prepare_kernel_cred = sys_execve - 0x19455c
 *   commit_creds        = sys_execve - 0x194910
 * KASLR 整体平移不改变相对偏移（同固件可靠；固件升级需重新标定）。 */
#define KSL_OFF_PREPARE_CREDS       0x194cb4UL
#define KSL_OFF_COMMIT_CREDS        0x194910UL

/* 4.14 arm64：syscall 表项 = 用户参数直传（SYSCALL_DEFINE 风格，x0=第一个参数），
 * 不是 fn(struct pt_regs *)。arm64 从 4.17 才改 pt_regs 风格。 */
typedef long (*syscall_fn_t)(const char __user *filename,
			     const char __user *const __user *argv,
			     const char __user *const __user *envp);
typedef struct cred *(*prepare_creds_t)(void);
typedef int (*commit_creds_t)(struct cred *);

static syscall_fn_t orig_sys_execve;
static prepare_creds_t p_prepare_creds;
static commit_creds_t p_commit_creds;
static syscall_fn_t *sct; /* sys_call_table */

/* ---- 写文件诊断（每次打开追加，真机已验证可用） ---- */
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

/* ---- diag_state 格式化（带缓冲），同步写文件 ---- */
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

/* v0.20: uid whitelist check (ksu_uids, comma-separated; empty = allow all) */
static int ksu_uid_allowed(unsigned int uid)
{
	const char *p = ksu_uids;
	unsigned long v = 0;
	int have = 0;

	if (!p || !p[0])
		return 1;

	while (*p) {
		if (*p >= '0' && *p <= '9') {
			v = v * 10 + (unsigned long)(*p - '0');
			have = 1;
		} else if (*p == ',') {
			if (have && v == uid)
				return 1;
			v = 0;
			have = 0;
		}
		p++;
	}
	if (have && v == uid)
		return 1;
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

/* ---- 页表 walk 报告：逐级读表项并打印 ----
 * 返回: 1 = 4K PTE，0 = 2MB block，-1 = 失败
 * phys_out    = 字节级物理地址（含页内偏移）
 * desc_out    = 叶子描述符
 * tbl_phys_out= 包含叶子描述符的表页物理地址（补丁用）
 * leaf_idx_out= 叶子在表页内的索引（补丁用） */
static int walk_report(unsigned long va, const char *tag, u64 *phys_out,
		       u64 *desc_out, u64 *tbl_phys_out,
		       unsigned long *leaf_idx_out)
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
		*desc_out = l2_e;
		*tbl_phys_out = l1_e & PHYS_MASK & PAGE_MASK;
		*leaf_idx_out = pmd_index(va);
		type = 0;
		diag_log("[%s] pmd BLOCK phys=%llx tbl=%llx idx=%lu\n", tag,
			 *phys_out, *tbl_phys_out, *leaf_idx_out);
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
	/* 字节级物理地址（含页内偏移），供交叉验证和别名写入 */
	*phys_out = (l3_e & PHYS_MASK & PAGE_MASK) | (va & (PAGE_SIZE - 1));
	*desc_out = l3_e;
	*tbl_phys_out = l2_e & PHYS_MASK & PAGE_MASK;
	*leaf_idx_out = pte_index(va);
	type = 1;
	diag_log("[%s] pte 4K phys=%llx tbl=%llx idx=%lu\n", tag,
		 *phys_out, *tbl_phys_out, *leaf_idx_out);
	return type;
}

/* ---- 扫描 pgd 表：打印所有有效表项（内存布局图） ---- */
static void scan_pgd(void)
{
	u64 ttbr1, e;
	u64 *tbl;
	int i;

	asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
	tbl = (u64 *)ioremap_cache(ttbr1 & PHYS_MASK & PAGE_MASK, PAGE_SIZE);
	if (!tbl) {
		diag_log("scan: pgd remap FAIL\n");
		return;
	}
	for (i = 0; i < 512; i++) {
		e = tbl[i];
		if ((e & 3) != 0)
			diag_log("pgd[%d]=%llx\n", i, e);
	}
	iounmap(tbl);
}

/* ---- 找 slot 内第一个有效映射的 (VA, phys) 对（线性映射偏移推导用） ----
 * 返回 0 成功（va_first/phys_first 输出），-1 失败。 */
static int slot_first(unsigned long slot_va, u64 *va_first, u64 *phys_first)
{
	u64 ttbr1, e;
	u64 *tbl;
	int i;

	asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
	tbl = (u64 *)ioremap_cache(ttbr1 & PHYS_MASK & PAGE_MASK, PAGE_SIZE);
	if (!tbl)
		return -1;
	e = tbl[(slot_va >> 30) & 0x1FF];
	iounmap(tbl);
	if ((e & 3) != 3)
		return -1; /* 只要 table（block 无法下钻推导） */

	tbl = (u64 *)ioremap_cache(e & PHYS_MASK & PAGE_MASK, PAGE_SIZE);
	if (!tbl)
		return -1;
	for (i = 0; i < 512; i++) {
		e = tbl[i];
		if ((e & 3) == 0)
			continue;
		if ((e & 3) == 1) { /* 2MB block */
			*va_first = slot_va + ((unsigned long)i << 21);
			*phys_first = e & PHYS_MASK & ~((1UL << 21) - 1);
			iounmap(tbl);
			return 0;
		}
		/* table → 下钻找第一个 pte */
		{
			u64 *t2 =
				(u64 *)ioremap_cache(e & PHYS_MASK & PAGE_MASK,
						     PAGE_SIZE);
			u64 e2;
			int j;

			if (!t2)
				continue;
			for (j = 0; j < 512; j++) {
				e2 = t2[j];
				if ((e2 & 3) == 1) {
					*va_first = slot_va +
						    ((unsigned long)i << 21) +
						    ((unsigned long)j << 12);
					*phys_first = e2 & PHYS_MASK & PAGE_MASK;
					iounmap(t2);
					iounmap(tbl);
					return 0;
				}
			}
			iounmap(t2);
		}
	}
	iounmap(tbl);
	return -1;
}

/* ---- 线性映射别名写入 + ioremap 表页 AP 补丁（v0.15） ----
 * 1) 扫描 slot 推导线性别名 cand（phys 与 sct 页一致，真机已验证）
 * 2) 叶子 RW → 直接写
 * 3) 叶子 RO → AP 补丁：ioremap 表页（真机反复证明表页 ioremap 安全），
 *    写前内容预验证（当前表项值必须 == walk 读到的描述符），
 *    写后读回验证，flush TLB，重走 cand 确认可写，再写 sct 表项。
 * 每步前置日志：任何一步崩了，ksu_diag.txt 都能指出位置。 */
static int write_via_linear(unsigned long va, syscall_fn_t fn,
			    syscall_fn_t expect)
{
	u64 pte = 0, desc = 0, tphys = 0, phys_page, phys_byte;
	u64 ttbr1, e;
	u64 *tbl;
	unsigned long tidx = 0;
	int i, r;

	r = walk_report(va, "sct", &pte, &desc, &tphys, &tidx);
	if (r < 0) {
		diag_set("W-sct-walk-fail");
		return 0;
	}
	phys_page = pte & PAGE_MASK;
	phys_byte = phys_page | (va & (PAGE_SIZE - 1));
	diag_log("sct byte phys=%llx\n", phys_byte);

	asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
	tbl = (u64 *)ioremap_cache(ttbr1 & PHYS_MASK & PAGE_MASK, PAGE_SIZE);
	if (!tbl) {
		diag_set("W-pgd-remap-fail");
		return 0;
	}

	for (i = 0; i < 512; i++) {
		unsigned long slot_va;
		u64 va_first = 0, phys_first = 0, cand = 0;
		u64 lin_phys = 0, lin_desc = 0, lin_tbl = 0;
		unsigned long lin_idx = 0;
		syscall_fn_t orig;
		int rt, st;

		e = tbl[i];
		if ((e & 3) != 3)
			continue; /* 只要 table 项 */

		slot_va = (unsigned long)VA_START + ((unsigned long)i << 30);
		st = slot_first(slot_va, &va_first, &phys_first);
		if (st < 0)
			continue;

		cand = phys_byte + (va_first - phys_first);
		diag_log("-- slot[%d] va_first=%llx phys_first=%llx cand=%llx --\n",
			 i, va_first, phys_first, cand);

		rt = walk_report((unsigned long)cand, "lin", &lin_phys,
				 &lin_desc, &lin_tbl, &lin_idx);
		if (rt < 0) {
			diag_log("cand walk fail\n");
			continue;
		}
		if (lin_phys != phys_byte) {
			diag_log("cand phys mismatch: got=%llx want=%llx\n",
				 lin_phys, phys_byte);
			continue;
		}

		diag_log("P1: readback cand\n");
		orig = *(syscall_fn_t *)(unsigned long)cand;
		diag_log("cand readback=%lx\n", (unsigned long)orig);
		if (orig != expect) {
			diag_log("cand no-match\n");
			continue;
		}

		/* 物理页确认无误。检查叶子可写性 */
		if (!(lin_desc & (1UL << 7))) {
			diag_log("P2: leaf RW, direct write\n");
			WRITE_ONCE(*(syscall_fn_t *)(unsigned long)cand, fn);
			if (*(syscall_fn_t *)(unsigned long)cand != fn) {
				diag_set("W-write-fail cand=%llx", cand);
				iounmap(tbl);
				return 0;
			}
			hook_method = "direct";
			diag_set("5-hooked via slot[%d] cand=%llx (direct)",
				 i, cand);
			iounmap(tbl);
			return 1;
		}

		/* RO 叶子 → AP 补丁（ioremap 表页 + 内容预验证） */
		diag_log("P3: RO leaf, patch via ioremap tbl=%llx idx=%lu\n",
			 lin_tbl, lin_idx);
		{
			u64 new_desc = lin_desc & ~(3UL << 6);
			u64 cur;
			u64 *t2 = (u64 *)ioremap_cache(lin_tbl & PAGE_MASK,
						       PAGE_SIZE);

			if (!t2) {
				diag_log("P3: ioremap tbl FAIL\n");
				continue;
			}
			/* 内容预验证：表项当前值必须 == walk 读到的描述符 */
			cur = t2[lin_idx];
			diag_log("P4: cur=%llx expect=%llx\n", cur, lin_desc);
			if (cur != lin_desc) {
				diag_log("P4: CONTENT MISMATCH, abort\n");
				iounmap(t2);
				continue;
			}
			diag_log("P5: write newdesc=%llx\n", new_desc);
			t2[lin_idx] = new_desc;
			if (t2[lin_idx] != new_desc) {
				diag_log("P5: WRITE FAILED\n");
				iounmap(t2);
				continue;
			}
			iounmap(t2);
			diag_log("P6: table patched, flush 2MB @ %lx\n",
				 (unsigned long)cand & ~((1UL << 21) - 1));
			flush_tlb_kernel_range(
				(unsigned long)cand & ~((1UL << 21) - 1),
				((unsigned long)cand & ~((1UL << 21) - 1)) +
					(1UL << 21));

			/* 重走 cand 确认叶子已可写 */
			rt = walk_report((unsigned long)cand, "lin2", &lin_phys,
					 &lin_desc, &lin_tbl, &lin_idx);
			if (rt < 0 || (lin_desc & (1UL << 7))) {
				diag_log("P7: rewalk not writable, abort\n");
				continue;
			}

			diag_log("P8: write sct entry via cand\n");
			WRITE_ONCE(*(syscall_fn_t *)(unsigned long)cand, fn);
			if (*(syscall_fn_t *)(unsigned long)cand != fn) {
				diag_set("W-write-fail-after-patch cand=%llx",
					 cand);
				iounmap(tbl);
				return 0;
			}
			if (*(syscall_fn_t *)va != fn) {
				diag_set("W-orig-verify-fail cand=%llx", cand);
				iounmap(tbl);
				return 0;
			}
			hook_method = "patched";
			diag_set("5-hooked via slot[%d] cand=%llx (patched)",
				 i, cand);
			iounmap(tbl);
			return 1;
		}
	}
	iounmap(tbl);
	diag_set("R-no-candidate");
	return 0;
}

/* ---- hook: 4.14 arm64 syscall 表项签名（用户参数直传） ----
 * v0.17：签名改为 SYSCALL_DEFINE 风格（filename, argv, envp）——
 * 4.14 arm64 调用表项时 x0=第一个系统调用参数，不是 pt_regs。
 * v0.16 死机根因：旧签名把用户 pathname 当 pt_regs → 读用户地址 →
 * EL1 访问用户内存（PAN）→ oops → die → exception reboot。
 * 热路径上不做文件写/睡眠操作，诊断只靠 diag_state。 */
static int diag_once;

static long ksu_sys_execve(const char __user *filename,
			   const char __user *const __user *argv,
			   const char __user *const __user *envp)
{
	char buf[256];
	long n;

	if (!diag_once) {
		diag_once = 1;
		diag_state = "6-hook-called";
	}

	n = strncpy_from_user(buf, filename, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = 0;
		if (k_strncmp(buf, ksu_path, k_strlen(ksu_path)) == 0 &&
		    current_uid().val != 0 &&
		    ksu_uid_allowed(current_uid().val)) {
			struct cred *nc;

			diag_state = "7-matched";
			nc = p_prepare_creds();
			if (nc) {
				/* v0.19: only change uid/gid/caps, keep caller's
				 * SELinux domain (prepare_kernel_cred would carry
				 * kernel:s0 -> terminal writes denied). */
				nc->uid = nc->euid = nc->suid = nc->fsuid =
					GLOBAL_ROOT_UID;
				nc->gid = nc->egid = nc->sgid = nc->fsgid =
					GLOBAL_ROOT_GID;
				nc->cap_effective = CAP_FULL_SET;
				nc->cap_permitted = CAP_FULL_SET;
				nc->cap_inheritable = CAP_FULL_SET;
				nc->cap_bset = CAP_FULL_SET;
				p_commit_creds(nc);
				diag_state = "8-root-granted";
			} else {
				diag_state = "7-prep-fail";
			}
		}
	}
	return orig_sys_execve(filename, argv, envp);
}

static int ksu_hook_init(void)
{
	unsigned long se, el0;
	u64 phys_sct = 0, phys_ex = 0, d1 = 0, d2 = 0, t1 = 0, t2 = 0;
	unsigned long i1 = 0, i2 = 0;
	int r1, r2, rw;

	diag_state = "1-init-running";
	diag_log("=== ksu_sct init start ===\n");
	diag_log("build: PGTABLE_LEVELS=%d VA_BITS=%d VA_START=%lx PAGE_OFFSET=%lx\n",
		 CONFIG_PGTABLE_LEVELS, CONFIG_ARM64_VA_BITS,
		 (unsigned long)VA_START, (unsigned long)PAGE_OFFSET);
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
	/* MTK 内核 kallsyms_lookup_name 对 prepare_kernel_cred/commit_creds 返回
	 * 用户空间垃圾值（v0.17 真机实测 0x3bd6e728/0x25088d9e）。
	 * 改用 sys_execve（查询可靠）+ 同固件固定偏移推算（KASLR 整体平移
	 * 不改变相对偏移）。kl_* 仅作对照打印。 */
	{
		prepare_creds_t pc_kl;
		commit_creds_t cc_kl;

		/* reference: direct lookup (%px prints raw value; MTK %p is hashed) */
		pc_kl = (prepare_creds_t)kallsyms_lookup_name("prepare_creds");
		cc_kl = (commit_creds_t)kallsyms_lookup_name("commit_creds");
		/* calibrated on device 2026-08-05 (same firmware, offsets fixed):
		 *   prepare_creds = sys_execve - 0x194cb4
		 *   commit_creds  = sys_execve - 0x194910 */
		p_prepare_creds = (prepare_creds_t)(se -
				KSL_OFF_PREPARE_CREDS);
		p_commit_creds = (commit_creds_t)(se - KSL_OFF_COMMIT_CREDS);

		diag_log("kallsyms: el0_svc=%lx sys_execve=%lx\n", el0, se);
		diag_log("pc: kl=%px calc=%px | cc: kl=%px calc=%px\n", pc_kl,
			 (void *)p_prepare_creds, cc_kl, (void *)p_commit_creds);
	}

	/* 防御：关键符号必须落在内核地址空间（高 16 位 0xffff） */
	if (!se || ((unsigned long)se >> 48) != 0xffff ||
	    ((unsigned long)p_prepare_creds >> 48) != 0xffff ||
	    ((unsigned long)p_commit_creds >> 48) != 0xffff) {
		diag_state = "2-kallsyms-fail";
		return -ENOENT;
	}

	orig_sys_execve = sct[NR_EXECVE];
	diag_log("sct=%lx sct[%d]=%lx\n", (unsigned long)sct, NR_EXECVE,
		 (unsigned long)orig_sys_execve);
	if ((unsigned long)orig_sys_execve != se) {
		diag_state = "3-sct-mismatch";
		return -EINVAL;
	}
	diag_state = "3-sct-verified";

	/* ---- 交叉验证 walk（字节级 phys，应逐字节吻合） ---- */
	diag_log("---- walk sct[%d] @ %lx ----\n", NR_EXECVE,
		 (unsigned long)&sct[NR_EXECVE]);
	r1 = walk_report((unsigned long)&sct[NR_EXECVE], "sct", &phys_sct, &d1,
			 &t1, &i1);

	diag_log("---- walk sys_execve @ %lx ----\n", se);
	r2 = walk_report(se, "execve", &phys_ex, &d2, &t2, &i2);

	if (r1 >= 0 && r2 >= 0) {
		unsigned long va_diff =
			(unsigned long)&sct[NR_EXECVE] - se;
		u64 phys_diff = (phys_sct > phys_ex) ?
				phys_sct - phys_ex : phys_ex - phys_sct;

		diag_log("CROSS: va_diff=%lx phys_diff=%llx\n", va_diff, phys_diff);
		if (va_diff == (unsigned long)phys_diff)
			diag_log("CROSS MATCH (walk 正确)\n");
		else
			diag_log("CROSS MISMATCH (walk 有问题)\n");
	}

	/* ---- 内存布局图 ---- */
	diag_log("---- pgd scan ----\n");
	scan_pgd();

	/* ---- 线性映射别名写入（自动定位 + ioremap 表页补丁） ---- */
	rw = write_via_linear((unsigned long)&sct[NR_EXECVE], ksu_sys_execve,
			      orig_sys_execve);
	if (rw)
		diag_log("HOOK OK via %s\n", hook_method);

	diag_log("=== init done ===\n");
	return 0;
}

static void ksu_sct_exit(void)
{
	if (sct && orig_sys_execve && sct[NR_EXECVE] == ksu_sys_execve)
		WRITE_ONCE(sct[NR_EXECVE], orig_sys_execve);
	diag_state = "9-exited";
	diag_log("=== exited ===\n");
}

module_init(ksu_hook_init);
module_exit(ksu_sct_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DS");
MODULE_DESCRIPTION("KSL root grant via sct execve hook, ioremap table patch (MT6771 4.14)");
MODULE_VERSION("0.18");
