/*
 * ksu_su.c - lightweight su frontend for KSL (KSU-like LKM)
 *
 * The kernel hook (ksu_lkm_sct.ko) grants root to any execve whose
 * filename starts with ksu_path (default /data/local/tmp/ksu). Place
 * this binary at /data/local/tmp/ksu_su so a non-root caller gets
 * uid 0 before this main() runs. This program then just runs the
 * requested command as root.
 *
 * Usage:
 *   ksu_su <command> [args...]   # run command as root
 *   ksu_su                       # interactive shell
 *
 * If executed without the kernel grant (getuid() != 0), it refuses
 * (e.g. someone copied it outside the ksu_path prefix).
 *
 * Build (NDK clang, arm64 static, same as kload):
 *   clang --target=aarch64-linux-android21 -static -O2 ksu_su.c -o ksu_su
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (getuid() != 0) {
		fprintf(stderr, "ksu_su: root not granted "
			"(kernel hook missing or uid not allowed?)\n");
		return 1;
	}

	if (argc >= 2) {
		execvp(argv[1], &argv[1]);
		fprintf(stderr, "ksu_su: exec %s: %s\n", argv[1],
			strerror(errno));
		return 127;
	}

	execl("/system/bin/sh", "sh", (char *)NULL);
	fprintf(stderr, "ksu_su: exec sh: %s\n", strerror(errno));
	return 127;
}
