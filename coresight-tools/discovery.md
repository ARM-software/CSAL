# CoreSight self-hosted discovery

Using self-hosted trace relies device drivers knowing the location and connections of the on-chip trace components. Under Linux, this information would typically be provided as a Device Tree or ACPI tables. But how is the configuration created in the first place?

This page explains how to discover the CoreSight configuration of a given system, with a focus on self-hosted discovery (i.e. from software run on the system). The procedure varies depending on how much information you already have. Some of the discovery steps can potentially crash devices, or require loading kernel modules, so there's no point running them if you can get the information from the manufacturer's datasheet.

Procedures that involve running software on the system, under Linux (or another OS), assume that you have root privilege.

It might be helpful to start by asking some questions...

  * do you have a datasheet showing the memory map, and are the CoreSight devices shown? Or does the map show an area "reserved for debug" or labelled "CoreSight" or "CSSYS"?
  * do you have physical JTAG access to the device and a JTAG debugger such as Arm DS-5 that can do platform discovery?
  * do you have a datasheet showing the connections between the CoreSight devices?
  * do you have a device configuration file for a debugger such as Arm DS-5?

Having established what information we've got, we can then select the easiest route to finding the full configuration. We don't want to rush into using exotic and invasive techniques if we can get the information from a datasheet!

## Steps to discovering CoreSight

The following steps start with the end goal (discovering the complete topology) and progressively build up a sequence of pre-requisite steps to achieve the goal with minimum effort and risk. The easiest option is listed first in each step. Once you have worked out what you need to do, you can then follow the steps backwards until you have achieved your goal: a description of the whole system.


## Finding the CoreSight devices and topology
### Finding the CoreSight system connections

The trace bus (ATB) connections between the devices need to be discovered. These can be found from any one of:

  * the manufacturer's datasheet, if it has this information
  *  a DS-5 SDF (not RVC) file for the system
  * using the cstopology tool supplied with CSAL, or the --topology option of the csscan.py script. For topology detection you will need the CoreSight device addresses and access to physical memory. This tool puts the CoreSight devices into a special mode ("integration mode"). CoreSight architecture guidelines recommend to do a power-off reset after using this mode. In practice, this is often not necessary, but nevertheless it is recommended to do topology discovery only in a controlled environment and not as part of normal system startup.

### Finding the CoreSight device addresses

The list of CoreSight devices, their physical addresses, and their types and hardware configurations, can be found from any one of:

  * the manufacturer's datasheet, if it has this information
  *  a DS-5 SDF or RVC file for the system (device addresses may need to be adjusted - see ROM Table advice below)
  * scanning the ROM table to find the device addresses, and reading the device identifier registers to identify the device types, using the cslist tool supplied with CSAL, or the csscan.py script. For this you will need the CoreSight top-level ROM Table base address and access to physical memory. Note that some devices may not make the CoreSight memory area accessible. You can do a quick check using "sudo busybox devmem <romaddr> 32".

### Finding the CoreSight top-level ROM Table base address(es)

The ROM Table base address(es) can be found from any one of:

  * the manufacturer's datasheet, if it has this information
  * a DS-5 SDF file for the system (addresses are from an external debugger's point of view and may need to be adjusted)
  * reading ROM Table Base Address register (MDRAR / DBGRAR) from any of the cores. For this you can build and load the csinfo kernel module supplied with CSAL: the ROM Table base address is shown in dmesg output. For this you will need to set up for building kernel modules (see below).

In a multi-socket system, each socket might have its own separate top-level ROM Table, mapped (along with other peripherals) at different areas of the common physical memory space seen by cores on both sockets. Each core's ROM Table base address register should point to whichever top-level ROM Table directly or indirectly has an entry for that core.

Note: the ARM architecture specification states that use of MDRAR/DBGRAR is deprecated. In general, software should rely on the firmware providing descriptor tables like ACPI or Device Tree. But we are describing a situation where these tables do not exist and MDRAR/DBGRAR may be the only option. It will work on most systems, but you should be prepared for the value of MDRAR/DBGRAR to be incorrect - the value is hardwired during core integration and some SoCs may not have done this correctly.

### Getting access to physical memory

  * /dev/mem, if the kernel was built with CONFIG_DEVMEM
  * building and loading the cskern kernel module supplied with CSAL. For this you will need to set up for building kernel modules.

### Getting a DS-5 SDF or RVC file

  * check to see if the file is supplied with DS-5
  * attach DS-5 to the board with JTAG and use the DS-5 Platform Configuration Editor (PCE) to generate a file

### Set up for building kernel modules

  * you will need kernel sources and headers exactly matching your kernel. Generally these would be located in ``/lib/modules/`uname -r`/build``. If not, use your package manager to install kernel-devel.

### Starting from nothing

This is a summary of the procedure if you haven't got a manufacturer datasheet or a JTAG connection. All you have is a Linux prompt and sudo access.

  * set up your system for building kernel modules
  * build and load the csinfo kernel module to find the base address of the top-level ROM Table. This also prints useful information about the system's debug capabilities.
  * get access to physical memory from userspace: if you haven't got /dev/mem, build and load the cskern kernel module.
  * run the `csscan.py` or `cslist` tools (as root) to discover the CoreSight devices. Edit the output to remove any devices that you don't want to deal with.
  * run the `csscan.py --topology` or `cstopology` tools to discover the CoreSight system topology and build a complete topology description.
  * convert the topology description into any required formats, e.g. Linux device tree or ACPI tables.

Hints and tips

  * Some devices have two or more separate CoreSight subsystems - one for the application cores and one for the management cores (usually Cortex-Ms). For self-hosted trace, the management subsystem can be mostly ignored, although it may share (and manage) a global CoreSight timestamp generator with the application trace subsystem.
  * Access to the top-level ROM Table might cause lockups, or it may be necessary to use a workaround such as connecting an external JTAG device to cause on-chip logic to power-on the main debug subsystem. Vendor assistance may be needed.
  * Individual devices might be powered-off or security-protected. In this case, even though the devices are listed in the ROM table, access to the device may lock up the system. If the devices relate to system management areas encountered during discovery, the discovery should be repeated with these areas excluded (some trial and error might be necessary). If they are devices needed for self-hosted trace, it may be necessary to ask the vendor how to enable access.
  * A variety of IP, such as graphics units, DSPs etc. can generate trace, either in standard formats (e.g. MIPI STP) or custom formats - discovery of unknown types of trace source is normal. There is a risk of multiple trace sources using the same trace source identifier and being funnelled together, resulting in a corrupt trace stream. As it might not be known how to disable trace sources or set the 7-bit trace source identifier, it might be necessary to use an input port on a funnel to block trace from unknown sources.
  * Some chip families have a variety of different parts with different numbers of cores, and may exhibit chip-to-chip variation in device addresses (e.g. because all the parts are produced from the same die and different physical cores have been fused out). It's still unclear how chip-to-chip variation is best dealt with in system descriptions. It may be possible to rerun cslist on each chip to find physical addresses, without having to rerun the more invasive topology discovery procedure, if topology is described in terms of logical devices. Or the vendor may provide an alternative procedure for finding out which physical cores are enabled, which can be used to customise the system description file.
