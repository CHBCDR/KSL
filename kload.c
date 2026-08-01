/*
 * kload.c — 强制加载内核模块的小工具（Android/arm64）v3
 *
 * v3 变更：finit_module 失败时自动回退 init_module（老接口）。
 *   真机 MTK 魔改内核的 finit_module 疑似被改（静默 ENOEXEC），
 *   而 init_module 路径行为正常（有完整报错输出）。init_module
 *   无 flags 参数，vermagic/CRC 必须真匹配（workflow 已 sed 对齐
 *   UTS_RELEASE + make modules 生成 Module.symvers）。
 *
 * v2 说明：finit_module + IGNORE_MODVERSIONS|IGNORE_VERMAGIC，
 *   等效 insmod -f，支持传模块参数（Android toybox insmod 不认 -f）。
 *
 * 用法: kload <module.ko> [param=value ...]
 * 例:   kload /data/local/tmp/ksu_lkm_sct.ko ksu_path=/data/local/tmp/ksu
 *
 * 编译（NDK r21e）:
 *   clang --target=aarch64-linux-android21 -static -O2 kload.c -o kload
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>

/* linux/module.h 里的标志（避免依赖内核头） */
#ifndef MODULE_INIT_IGNORE_MODVERSIONS
#define MODULE_INIT_IGNORE_MODVERSIONS 0x0001
#define MODULE_INIT_IGNORE_VERMAGIC    0x0002
#endif

#ifndef SYS_finit_module
#define SYS_finit_module 273 /* arm64 */
#endif
#ifndef SYS_init_module
#define SYS_init_module 105 /* arm64 */
#endif

static int load_via_init_module(int fd, const char *params)
{
	struct stat st;
	void *buf;
	long ret;

	if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
	    st.st_size > 64 * 1024 * 1024) {
		fprintf(stderr, "init_module: bad file size\n");
		return -1;
	}

	buf = malloc(st.st_size);
	if (!buf) {
		fprintf(stderr, "init_module: malloc failed\n");
		return -1;
	}

	if (lseek(fd, 0, SEEK_SET) < 0 ||
	    read(fd, buf, st.st_size) != st.st_size) {
		fprintf(stderr, "init_module: read failed\n");
		free(buf);
		return -1;
	}

	ret = syscall(SYS_init_module, buf, st.st_size, params);
	free(buf);
	return (int)ret;
}

int main(int argc, char **argv)
{
	int fd;
	long ret;
	char *params = "";
	size_t len = 0;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <module.ko> [param=value ...]\n", argv[0]);
		fprintf(stderr, "kload v3 (finit_module flags + init_module fallback)\n");
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

	/* 优先 finit_module + ignore flags */
	ret = syscall(SYS_finit_module, fd, params,
		      MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC);
	if (ret < 0) {
		perror("finit_module");
		/* 回退 init_module（无 flags，vermagic/CRC 需真匹配） */
		ret = load_via_init_module(fd, params);
		if (ret < 0) {
			perror("init_module");
			free(params);
			close(fd);
			return 1;
		}
		printf("module loaded via init_module: %s\n", argv[1]);
	} else {
		printf("module loaded via finit_module: %s\n", argv[1]);
	}

	free(params);
	close(fd);
	return 0;
}
