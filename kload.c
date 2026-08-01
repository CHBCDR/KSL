/*
 * kload.c — 强制加载内核模块的小工具（Android/arm64）
 *
 * 为什么需要它：Android 的 toybox insmod 不支持 -f（MODULE_INIT_IGNORE_*），
 * 而本机内核 MODVERSIONS=y 且 .ko 由第三方源码树编译，CRC 未必匹配。
 * 直接用 finit_module + IGNORE_MODVERSIONS|IGNORE_VERMAGIC 标志加载，
 * 等效于 insmod -f，并支持传模块参数。
 *
 * 用法: kload <module.ko> [param=value ...]
 * 例:   kload /data/local/tmp/ksu_lkm_tp.ko ksu_path=/data/local/tmp/ksu
 *
 * 编译（NDK r21e）:
 *   clang --target=aarch64-linux-android21 -static -O2 kload.c -o kload
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

/* linux/module.h 里的标志（避免依赖内核头） */
#ifndef MODULE_INIT_IGNORE_MODVERSIONS
#define MODULE_INIT_IGNORE_MODVERSIONS 0x0001
#define MODULE_INIT_IGNORE_VERMAGIC    0x0002
#endif

#ifndef SYS_finit_module
#define SYS_finit_module 273 /* arm64 */
#endif

int main(int argc, char **argv)
{
	int fd;
	long ret;
	char *params = "";
	size_t len = 0;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <module.ko> [param=value ...]\n", argv[0]);
		fprintf(stderr, "kload v2 (finit_module + IGNORE_MODVERSIONS|IGNORE_VERMAGIC)\n");
		return 1;
	}

	fd = open(argv[1], O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	/* 拼接模块参数（空格分隔） */
	if (argc > 2) {
		for (int i = 2; i < argc; i++)
			len += strlen(argv[i]) + 1;
		params = calloc(1, len + 1);
		if (!params) {
			fprintf(stderr, "calloc failed\n");
			close(fd);
			return 1;
		}
		for (int i = 2; i < argc; i++) {
			if (i > 2)
				strcat(params, " ");
			strcat(params, argv[i]);
		}
	}

	ret = syscall(SYS_finit_module, fd, params,
		      MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC);
	if (ret < 0) {
		perror("finit_module");
		free(params);
		close(fd);
		return 1;
	}

	printf("module loaded: %s\n", argv[1]);
	free(params);
	close(fd);
	return 0;
}
