#
# Loadable kernel module to create /dev/csmem.
#
# /dev/csmem acts like /dev/mem. This provides userspace access to
# physical memory on a kernel built with !CONFIG_DEVMEM.
# It is only intended to be used in controlled situations, e.g. for
# investigations into memory-mapped CoreSight debug.
#

MOD=cskern
KERNSRC=/lib/modules/$(shell uname -r)/build
KERNARCH=$(KERNSRC)/arch/arm64

MODSRC=$(shell pwd)
obj-m += $(MOD).o

load : $(MOD).ko
	sudo insmod $^
	dmesg | tail -6
	@ls -l /dev/cs*mem

$(MOD).ko : $(MOD).c
	make -C $(KERNSRC) M=$(MODSRC) modules

unload :
	sudo rmmod $(MOD)
	dmesg | tail -1

.PHONY : $(MOD).tar
$(MOD).tar :
	cd .. && tar cvf $@ $(MOD)/$(MOD).c $(MOD)/Makefile $(MOD)/testmem.py

clean :
	rm -rf $(MOD).o $(MOD).ko $(MOD).mod.* Module.symvers modules.order .tmp_versions .$(MOD).*.cmd $(MOD).tar
