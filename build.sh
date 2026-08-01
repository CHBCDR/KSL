#!/bin/sh
# 用公开 MT6771 4.14 源码树交叉编译 KSU LKM
# 依赖: Linux 主机 (WSL/Ubuntu/云编译) + 源码树 + 交叉编译器
# 用法: ./build.sh [源码树路径]
set -e

SRC=${1:-$HOME/kernel_umidigi_f2_mt6771_4.14}
ARCH=arm64

if [ ! -d "$SRC" ]; then
  echo "[!] 源码树不存在: $SRC"
  echo "    先 clone:"
  echo "    git clone --depth 1 https://github.com/Hadenix/kernel_umidigi_f2_mt6771_4.14.git"
  echo "    或者用 --depth 1 拉 techyminati/android_kernel_realme_mt6771V (4.14.142) 作对照"
  exit 1
fi

# 优先用源码树自带/NDK 的 clang，否则回退发行版 gcc
if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
  CROSS_COMPILE=${CROSS_COMPILE:-aarch64-linux-gnu-}
  make KERNELDIR="$SRC" ARCH=$ARCH CROSS_COMPILE="$CROSS_COMPILE" all
else
  echo "[!] 未找到 aarch64-linux-gnu-gcc，尝试 clang + llvm"
  make KERNELDIR="$SRC" ARCH=$ARCH CC=clang LLVM=1 LLVM_IAS=1 all
fi

echo
echo "=== 产物 ==="
ls -la *.ko 2>/dev/null || true
echo
echo "下一步（设备上，终端抽风就用 MT 管理器写脚本执行）："
echo "  adb push ksu_lkm_tp.ko /data/local/tmp/"
echo "  su -c 'insmod -f /data/local/tmp/ksu_lkm_tp.ko ksu_path=/data/local/tmp/ksu'"
echo "  su -c 'dmesg | grep ksu_tp'"
echo "  su -c 'cp /system/bin/sh /data/local/tmp/ksu && /data/local/tmp/ksu -c id'"
