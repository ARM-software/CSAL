#
# Loadable kernel module to discover CoreSight ROM address and other
# useful debug properties.
#
# This module reports the information and then deliberately fails
# its initialization, so it doesn't stay loaded.
#

MOD=csinfo
KERNSRC=/lib/modules/$(shell uname -r)/build

MODSRC=$(shell pwd)
obj-m += $(MOD).o

load: $(MOD).ko
	@echo
	@echo Load CoreSight reporting module... expect \"Resource temporarily unavailable\"
	-sudo insmod $^
	dmesg | tail -10

$(MOD).ko : $(MOD).c
	make -C $(KERNSRC) M=$(MODSRC) modules

unload :
	sudo rmmod $(MOD)
	dmesg | tail -1

.PHONY : $(MOD).tar
$(MOD).tar :
	cd .. && tar cvf $@ $(MOD)/$(MOD).c $(MOD)/Makefile

clean :
	rm -rf $(MOD).o $(MOD).ko $(MOD).mod.* Module.symvers modules.order .tmp_versions .$(MOD).*.cmd $(MOD).tar


