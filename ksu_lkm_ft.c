/*
 * ksu_lkm_ft.c — KernelSU 提权 LKM（ftrace hook do_execveat_common 版）
 *
 * 备选方案：当 tracepoint 版（ksu_lkm_tp.c）因符号未导出等原因编不过/加载
 * 失败时，用这个版本。KernelSU 早期版本（v0.9.x）就是 ftrace hook
 * do_execveat_common 的路线，属于正统做法。
 *
 * 原理：
 *   ftrace（FTRACE=y，本机确认）是内核原生插桩机制。把 do_execveat_common
 *   的入口通过 ftrace_set_filter_ip 挂到自己的 ops 上，函数被调用时回调
 *   触发。回调运行在被 hook 函数的调用上下文（进程上下文，可以睡眠），
 *   直接读参数寄存器拿 filename，匹配白名单后用标准
 *   prepare_creds()/commit_creds() 提权。
 *
 * 前提（设备上先验证）：
 *   - CONFIG_DYNAMIC_FTRACE=y（本机 FTRACE=y）
 *   - CONFIG_DYNAMIC_FTRACE_WITH_REGS=y（回调要拿 pt_regs 里的参数；
 *     没有的话 regs==NULL，回调直接跳过，功能失效）
 *   - do_execveat_common 在 available_filter_functions 里：
 *       grep do_execveat_common /sys/kernel/debug/tracing/available_filter_functions
 *   - kallsyms_lookup_name 可用（本机已确认导出：0xffffff88ba376fe4）
 *
 * 编译/加载/测试：同 ksu_lkm_tp.c（模块名换成 ksu_lkm_ft.ko）
 *
 * MODULE_LICENSE("GPL") 必须：kallsyms_lookup_name / ftrace 接口都是 GPL 导出。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/fs.h>

static char *ksu_path = "/data/local/tmp/ksu";
module_param(ksu_path, charp, 0644);
MODULE_PARM_DESC(ksu_path, "exec path prefix that triggers root grant");

static unsigned long hook_addr;

static void ksu_ft_func(unsigned long ip, unsigned long parent_ip,
			struct ftrace_ops *ops, struct pt_regs *regs)
{
	struct filename *fn;
	struct cred *new;

	/* arm64 调用约定：do_execveat_common(int fd, struct filename *filename, ...)
	 * x0=fd, x1=filename。没有 SAVE_REGS 支持时 regs 为 NULL，直接跳过。 */
	if (!regs)
		return;

	fn = (struct filename *)regs->regs[1];
	if (!fn || !fn->name)
		return;

	if (strncmp(fn->name, ksu_path, strlen(ksu_path)) != 0)
		return;

	if (current_uid().val == 0)
		return;

	/* 进程上下文，可以睡眠 → 标准安全提权 */
	new = prepare_creds();
	if (!new)
		return;

	new->uid = new->euid = new->suid = new->fsuid = GLOBAL_ROOT_UID;
	new->gid = new->egid = new->sgid = new->fsgid = GLOBAL_ROOT_GID;
	new->cap_effective = new->cap_permitted = new->cap_inheritable =
		new->cap_bset = new->cap_ambient = CAP_FULL_SET;

	commit_creds(new);
	printk(KERN_INFO "ksu_ft: ROOT granted pid=%d filename=%s\n",
	       current->pid, fn->name);
}

static struct ftrace_ops ksu_ops = {
	.func = ksu_ft_func,
	.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE,
};

static int __init ksu_ft_init(void)
{
	int ret;

	hook_addr = kallsyms_lookup_name("do_execveat_common");
	if (!hook_addr) {
		printk(KERN_ERR "ksu_ft: do_execveat_common not found in kallsyms\n");
		return -ENOENT;
	}

	/* 必须先设 filter 再注册：注册后 ops 只对 filter 里的 ip 生效，
	 * 否则会 hook 到所有插桩函数，性能灾难且回调全函数触发 */
	ret = ftrace_set_filter_ip(&ksu_ops, hook_addr, 0, 0);
	if (ret) {
		printk(KERN_ERR "ksu_ft: ftrace_set_filter_ip(0x%lx) failed: %d "
		       "(not in available_filter_functions?)\n", hook_addr, ret);
		return ret;
	}

	ret = register_ftrace_function(&ksu_ops);
	if (ret) {
		printk(KERN_ERR "ksu_ft: register_ftrace_function failed: %d\n", ret);
		ftrace_set_filter_ip(&ksu_ops, hook_addr, 1, 0);
		return ret;
	}

	printk(KERN_INFO "ksu_ft: hooked do_execveat_common @0x%lx, trigger path=%s\n",
	       hook_addr, ksu_path);
	return 0;
}

static void __exit ksu_ft_exit(void)
{
	unregister_ftrace_function(&ksu_ops);
	ftrace_set_filter_ip(&ksu_ops, hook_addr, 1, 0);
	printk(KERN_INFO "ksu_ft: unhooked\n");
}

module_init(ksu_ft_init);
module_exit(ksu_ft_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DS");
MODULE_DESCRIPTION("KSU root grant via ftrace hook of do_execveat_common (4.14 MT6771)");
MODULE_VERSION("0.1");
