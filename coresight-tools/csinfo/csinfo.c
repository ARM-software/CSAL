/*
 * Discover CoreSight capabilities and ROM base address.
 */

/*
Copyright (C) ARM Ltd. 2019.  All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#ifdef SHOW_CPU_HWCAPS
#include <asm/cpufeature.h>
#endif


MODULE_AUTHOR("Arm Ltd");
MODULE_DESCRIPTION("CoreSight: report basic info, then unload");
MODULE_VERSION("0.2");
MODULE_LICENSE("Proprietary");


static char const *const dbgarch_str[] = {
	[1] = "ARMv6, debug v6",
	[2] = "ARMv6, debug v6.1",
	[3] = "ARMv7, debug v7 with baseline CP14",
	[4] = "ARMv7, debug v7 with full CP14",
	[5] = "ARMv7, debug v7.1",
	[6] = "ARMv8, debug v8",
	[7] = "ARMv8.1, debug v8 with VHE",
	[8] = "ARMv8.2, debug v8.2",
	[9] = "Armv8.4 debug",
	[10] = "Armv8.8 debug",
	[11] = "Armv8.9 debug",
};


struct cpu_info {
	/* Following are expected to be unique per CPU */
	unsigned int cpu;  /* CPU number */
	u64 mpidr;	/* CPU identifier within the topology, e.g. 2.1.3 */
	/* Following are expected to be identiical for a given MIDR */
	u32 midr;	/* CPU type descriptor (e.g. "Arm Cortex-A75 r2p0") */
	u64 rombase;	/* Top-level ROM base address (zero on newer CPUs) */
};


static void collect_on_cpu(void *infov)
{
	unsigned int const cpu = smp_processor_id();
	struct cpu_info *info = (struct cpu_info *)infov + cpu;
	unsigned int TraceVer, DebugVer;

#ifndef CONFIG_64BIT

	u32 dbgid, dbgdevid, mpidr32;
	{
		u32 midr;
		__asm__("mrc p15,0,%0,c0,c0,0":"=r"(midr));
		info->midr = midr;
	}
        __asm__("mrc p15,0,%0,c0,c0,5":"=r"(mpidr32));
        info->mpidr = mpidr32;
	__asm__("mrc p14,0,%0,c0,c0,0":"=r"(dbgid));
	pr_info("  DBGDIDR           = 0x%08x\n", dbgid);
	DebugVer = (dbgid >> 16) & 0xf;
        __asm__("mrc p14,0,%0,c7,c2,7":"=r"(dbgdevid));
	pr_info("  DBGDEVID          = 0x%08x\n", dbgdevid);
	{
		u32 hi, lo;
		__asm__("mrrc p14,0,%0,%1,c1":"=r"(lo),"=r"(hi));
                info->rombase = ((u64)hi << 32) | lo;
        }

#else

	u64 dfr64;
	{
		u32 midr;
		__asm__("mrs %0,MIDR_EL1":"=r"(midr));
		info->midr = midr;
	}
	{
		u64 mpidr;
		__asm__("mrs %0,MPIDR_EL1":"=r"(mpidr));
		info->mpidr = mpidr;
	}
	__asm__("mrs %0,ID_AA64DFR0_EL1":"=r"(dfr64));
	pr_info("  ID_AA64DFR0_EL1   = 0x%016llx\n", dfr64);
	TraceVer = (unsigned int)(dfr64 >> 4) & 0xf;
	DebugVer = (unsigned int)dfr64 & 0xf;
	pr_info("    ETM system register interface %simplemented\n", (TraceVer ? "" : "not "));
	{
		u64 rombase;
		__asm__("mrs %0,MDRAR_EL1":"=r"(rombase));
		info->rombase = rombase;
	}
    {
        u64 cpuectlr;
        __asm__("mrs %0,CPUECTLR_EL1":"=r"(cpuectlr));
        pr_info("    CPUECTLR_EL1 = 0x%016lx\n", cpuectlr);
    }

#endif

	if (DebugVer < (sizeof dbgarch_str / sizeof dbgarch_str[0]))
		pr_info("#%-3u    Debug architecture: %s\n", cpu, dbgarch_str[DebugVer]);
	else
		pr_info("#%-3u    Debug architecture: %u?\n", cpu, DebugVer);
}


static void show_debug_info(void)
{
	int cpu;
	struct cpu_info *infos = (struct cpu_info *)vmalloc(sizeof(struct cpu_info) * NR_CPUS);
	memset(infos, 0, sizeof(struct cpu_info) * NR_CPUS);
	on_each_cpu(collect_on_cpu, infos, 1);
	for (cpu = 0; cpu < NR_CPUS; ++cpu) {
		struct cpu_info const *info = &infos[cpu];
		if (info->midr != 0) {
			pr_info("#%-3u  MIDR: %08x   MPIDR: 0x%016llx  ROM table: 0x%016llx\n",
				cpu, info->midr, info->mpidr, (info->rombase & ~3));
		}
	}
	vfree(infos);
}


#ifdef SHOW_CPU_HWCAPS
/*
 * Show currently enabled CPU capabilities, to help understand what code alternatives
 * have been applied to the in-memory kernel.
 */
static void show_cpu_hwcaps(void)
{
	int i = 0;
	int panic = 0;
	while (1) {
		i = find_next_bit(cpu_hwcaps, ARM64_NCAPS, i);
		if (i == ARM64_NCAPS)
			break;
		pr_info("  CPU capability %u\n", i);
		++i;
		++panic;
		if (panic > 1000)
			break;
	}
}
#endif


static int __init csinfo_init(void)
{
#ifndef CONFIG_64BIT
	pr_info("CoreSight information module (AArch32)\n");
#else
	pr_info("CoreSight information module (AArch64)\n");
#endif
	show_debug_info();
#ifdef SHOW_CPU_HWCAPS
        show_cpu_hwcaps();
#endif
	/* We have to return some error so as not to stay resident... let's pick
	   one that won't be confused with a genuine failure to load. */
	return -EAGAIN;
}


module_init(csinfo_init);
