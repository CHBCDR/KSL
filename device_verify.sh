#!/system/bin/sh
# KSL 真机一键验证脚本 — 加载 + 触发 + 非root提权 + 卸载
# 用法：先把 ksu_lkm_sct.ko 和 kload 推到 /data/local/tmp/，然后：
#   sh /data/local/tmp/device_verify.sh
# 注意：本机终端会截断长命令，务必用脚本文件执行；如果报语法错，先转 LF（dos2unix）。

M=/data/local/tmp
KO=$M/ksu_lkm_sct.ko
SYS=/sys/module/ksu_lkm_sct/parameters

echo "== [1/5] 加载模块（insmod + ksu_trigger=1，MTK 不调 init 必须带 trigger）=="
insmod $KO ksu_path=$M/ksu ksu_trigger=1 2>&1
if [ $? -ne 0 ]; then
  echo "!! insmod 失败，退回 kload（跳过 CRC/vermagic）"
  $M/kload $KO ksu_path=$M/ksu ksu_trigger=1 2>&1
fi

echo "== [2/5] diag_state（期望 5-hooked；0-init-not-run = trigger 没生效）=="
cat $SYS/diag_state 2>&1

echo "== [3/5] 准备白名单 payload =="
cp /system/bin/sh $M/ksu && chmod 755 $M/ksu
ls -l $M/ksu

echo "== [4/5] 非 root 触发（当前 uid=$(id -u)）=="
if [ "$(id -u)" = "0" ]; then
  echo "-- 当前是 root（Magisk shell），用 su 2000 降权触发 --"
  su 2000 -c "$M/ksu -c id"
else
  echo "-- 当前非 root，直接触发 --"
  $M/ksu -c id
fi
echo "-- 触发后 diag_state（期望 8-root-granted）--"
cat $SYS/diag_state 2>&1

echo "== [5/5] 卸载 =="
rmmod ksu_lkm_sct 2>&1
echo "-- 卸载后读取（应报 No such file = 模块已卸载）--"
cat $SYS/diag_state 2>&1
echo "DONE"
