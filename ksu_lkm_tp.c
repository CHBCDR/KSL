/*
 * ksu_lkm_tp.c — KernelSU 提权 LKM（sched_process_exec tracepoint 版）
 *
 * 原理：
 *   注册 sched_process_exec tracepoint 探针，当任意进程 exec 的目标路径
 *   匹配白名单前缀（默认 /data/local/tmp/ksu）时，把该进程的 cred 直接
 *   改成 root（uid/gid=0 + 全 capabilities）。
 *
 * 为什么选 tracepoint 而不是 hook sys_call_table：
 *   - 本机 sys_call_table 在 BSS 段且映射只读，改它要碰只读内存 + PAN
 *   - tracepoint 是内核原生回调机制，注册探针即可，不修改任何代码/数据
 *   - 4.14 的 sched_process_exec tracepoint 符号是 EXPORT_SYMBOL_GPL，
 *     模块可直接链接引用（本机已确认该 tracepoint 完全可用）
 *
 * 关键时序（为什么改 cred 会生效）：
 *   trace_sched_process_exec 在 fs/exec.c 的 exec_binprm() 里调用，此时
 *   binary handler（load_elf_binary 等）内部已经执行过 install_exec_creds，
 *   current->cred 就是即将生效的 bprm->cred（prepare_bprm_creds 复制出来的，
 *   usage==1 私有）。改它的字段 = 新程序以 root 身份运行。
 *
 * 回调上下文限制（重要）：
 *   tracepoint 回调在 rcu_read_lock_sched（preempt_disable）下执行，不能睡眠，
 *   所以不能用 prepare_kernel_cred/commit_creds（GFP_KERNEL 分配可能睡眠，
 *   会触发 "scheduling while atomic"）。
 *   替代：检查 cred->usage==1（确认私有无共享）后直接改字段，零分配零睡眠。
 *   usage>1 时放弃提权并告警（不污染共享 cred）。
 *
 * 编译：见 Makefile / build.sh（需要 4.14 MT6771 源码树）
 * 加载：insmod -f /data/local/tmp/ksu_lkm_tp.ko ksu_path=/data/local/tmp/ksu
 * 测试：cp /system/bin/sh /data/local/tmp/ksu && /data/local/tmp/ksu -c id
 *
 * MODULE_LICENSE("GPL") 必须：tracepoint_probe_register 是 EXPORT_SYMBOL_GPL。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/binfmts.h>
#include <trace/events/sched.h>

/* 白名单前缀：exec 路径以此开头则提权（可 insmod 时传参覆盖） */
static char *ksu_path = "/data/local/tmp/ksu";
module_param(ksu_path, charp, 0644);
MODULE_PARM_DESC(ksu_path, "exec path prefix that triggers root grant");

/*
 * 探针签名（4.14 新版，带 old_pid）：
 *   void probe(void *data, struct task_struct *p, pid_t old_pid,
 *              struct linux_binprm *bprm)
 * 与 include/trace/events/sched.h 的 TP_PROTO 一致。
 */
static void ksu_exec_probe(void *data, struct task_struct *p,
			   pid_t old_pid, struct linux_binprm *bprm)
{
	struct cred *cred;
	size_t plen;

	if (!bprm || !bprm->filename)
		return;

	plen = strlen(ksu_path);
	if (!plen || strncmp(bprm->filename, ksu_path, plen) != 0)
		return;

	/* 已是 root 的进程不动 */
	if (current_uid().val == 0)
		return;

	cred = (struct cred *)current->cred; /* current->cred 是 const，改字段需去 const */
	if (!cred)
		return;

	/* 回调在 preempt_disable 下，不能分配/睡眠；usage==1 才直接改字段 */
	if (atomic_read(&cred->usage) != 1) {
		printk(KERN_WARNING "ksu_tp: pid=%d cred usage=%d shared, skip\n",
		       current->pid, atomic_read(&cred->usage));
		return;
	}

	cred->uid = cred->euid = cred->suid = cred->fsuid = GLOBAL_ROOT_UID;
	cred->gid = cred->egid = cred->sgid = cred->fsgid = GLOBAL_ROOT_GID;
	cred->cap_effective = cred->cap_permitted = cred->cap_inheritable =
		cred->cap_bset = cred->cap_ambient = CAP_FULL_SET;

	printk(KERN_INFO "ksu_tp: ROOT granted pid=%d filename=%s\n",
	       current->pid, bprm->filename);
}

static int __init ksu_tp_init(void)
{
	int ret;

	ret = register_trace_sched_process_exec(ksu_exec_probe, NULL);
	if (ret) {
		printk(KERN_ERR "ksu_tp: register probe failed: %d\n", ret);
		return ret;
	}

	printk(KERN_INFO "ksu_tp: sched_process_exec probe registered, trigger path=%s\n",
	       ksu_path);
	return 0;
}

static void __exit ksu_tp_exit(void)
{
	unregister_trace_sched_process_exec(ksu_exec_probe, NULL);
	printk(KERN_INFO "ksu_tp: probe unregistered\n");
}

module_init(ksu_tp_init);
module_exit(ksu_tp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DS");
MODULE_DESCRIPTION("KSU root grant via sched_process_exec tracepoint (4.14 MT6771)");
MODULE_VERSION("0.1");
