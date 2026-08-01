/*
 * kload.c — 强制加载内核模块的小工具（Android/arm64）v4
 *
 * v4 变更：init_module 回退前，把 ELF 里 __versions 段改名（不是删除）。
 *   内核 find_sec("__versions") 按节名匹配，名字改掉 → index.vers=0 →
 *   完全跳过 MODVERSIONS CRC 检查。只改 shstrtab 一个字符串，不动段表/
 *   符号表/重定位，比 objcopy 删段安全得多（objcopy 删段会因符号表残留
 *   __versions 符号/重定位引用报错，GNU/llvm 行为还不一致）。
 *   改名后无 __versions → vermagic 完整比较（含版本号）→ 需要 workflow
 *   的 UTS_RELEASE 对齐（4.14.141+），sed 已完成。
 *
 * v3 变更：finit_module 失败时自动回退 init_module（老接口）。
 *   真机 MTK 魔改内核的 finit_module 疑似被改（静默 ENOEXEC），
 *   而 init_module 路径行为正常（有完整报错输出）。
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
#include <elf.h>

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

/* 把 __versions 段改名（__versions → xxversions），让内核 find_sec
 * 找不到 → index.vers=0 → 跳过 MODVERSIONS CRC 检查。 */
static int neutralise_versions(void *buf, size_t len)
{
	Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
	Elf64_Shdr *sh;
	char *shstr;
	unsigned int i;

	if (len < sizeof(*eh) || memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
	    eh->e_type != ET_REL)
		return -1;

	if (eh->e_shoff == 0 || eh->e_shnum == 0 ||
	    eh->e_shstrndx >= eh->e_shnum)
		return -1;

	sh = (Elf64_Shdr *)((char *)buf + eh->e_shoff);
	shstr = (char *)buf + sh[eh->e_shstrndx].sh_offset;

	for (i = 1; i < eh->e_shnum; i++) {
		char *name = shstr + sh[i].sh_name;
		if (strcmp(name, "__versions") == 0) {
			name[0] = 'x';
			name[1] = 'x'; /* "__versions" -> "xxversions" */
			fprintf(stderr, "init_module: __versions renamed -> CRC check skipped\n");
			return 0;
		}
	}
	return 0; /* 本来就没有 __versions，无需处理 */
}

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

	/* 改 __versions 段名 → 内核跳过 CRC（vermagic 靠 UTS_RELEASE 对齐） */
	neutralise_versions(buf, (size_t)st.st_size);

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
		fprintf(stderr, "kload v4 (finit_module flags + init_module + __versions rename)\n");
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

	/* 优先 finit_module + ignore flags（部分内核 finit_module 正常） */
	ret = syscall(SYS_finit_module, fd, params,
		      MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC);
	if (ret < 0) {
		perror("finit_module");
		/* 回退 init_module：__versions 改名跳过 CRC，vermagic 靠 sed 对齐 */
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
