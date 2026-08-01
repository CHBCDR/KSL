# KernelSU LKM - cross compile
# Output: ksu_lkm_sct.ko (sys_call_table hook version, the usable one)
#
# NOTE (dead ends, source kept for reference):
#   ksu_lkm_tp.c (tracepoint version): device kernel does NOT export
#     __tracepoint_sched_process_exec -> "Unknown symbol" at load time.
#   ksu_lkm_ft.c (ftrace version): device kernel has CONFIG_FUNCTION_TRACER
#     disabled, ftrace build fails / useless on device.

obj-m += ksu_lkm_sct.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
