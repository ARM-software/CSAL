/*!
 * \file       cs_access_cmnfns.h
 * \brief      CS Access Library - internal library types and function declarations - not exposed on API.
 *
 * \copyright  Copyright (C) ARM Limited, 2014-2016. All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _included_cs_access_cmnfns_h
#define _included_cs_access_cmnfns_h

#include "cs_types.h"
/* Now one of UNIX_USERSPACE, UNIX_KERNEL or BAREMETAL will have been defined. */

#include "cs_etm_types.h"
#include "cs_etmv4_types.h"
#include "cs_stm_types.h"
#include "cs_ts_gen.h"
#include "cs_memap.h"

#include "csregisters.h"

#ifdef UNIX_USERSPACE
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#endif				/* UNIX_USERSPACE */

#ifdef UNIX_KERNEL
#include <linux/kernel.h>
#include <linux/slab.h>
#define malloc(x) kmalloc(x, GFP_KERNEL)
#define free(p) kfree(p)
#endif				/* UNIX_KERNEL */

#if defined(UNIX_USERSPACE) || defined(BAREMETAL)
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#endif
#if defined(UNIX_KERNEL)
#include <linux/string.h>
#include <asm/io.h>
#define assert(x) BUG_ON(x)
#endif
#include <stddef.h>
#include <stdarg.h>

#ifdef USE_DEVMEMD
#include "cs_stub_devmemd.h"
#endif /* USE_DEVMEMD */


#define CS_LIB_VERSION_MAJ 0x02
#define CS_LIB_VERSION_MIN 0x03

/*
  DIAG defines whether this build is capable of writing diagnostic messages.
  The actual production of individual messages is controlled by tests under
  the DTRACE/DTRACEG macros.

  Compile with -DDIAG=0 for a bare-metal build.
*/
#ifndef DIAG
#define DIAG 1
#endif				/* DIAG */


/*
  CHECK defines whether this build is capable of extra self-checking.
  Note that the self-checks may involve additional memory transactions with
  the CoreSight devices, e.g. reading back registers after writing.
  The actual self-checks are controlled by the DCHECK macro.
*/
#ifndef CHECK
#define CHECK 1
#endif				/* CHECK */


/**
 *  Upper limits on input/output ports of devices in the trace bus
 */
#define CS_MAX_IN_PORTS 8
#define CS_MAX_OUT_PORTS 8



struct cs_device;

struct cs_device_ops {
    void (*unregister) (struct cs_device * d);
};


/*
  Information relating to a single CoreSight component.
  A "component" generally corresponds to a single 4K programmable memory-mapped block.
*/
struct cs_device {
    /* Next device in global list - no particular order */
    struct cs_device *next;

    struct cs_device_ops ops;

    /* Generic properties of the device */
    cs_physaddr_t phys_addr;      /**< The physical address in the target memory space */
    unsigned char volatile *local_addr;   /**< Address of the device page in our space */
#ifdef CSAL_MEMAP
    cs_device_t memap;            /**< MEM-AP, if device is being accessed indirectly */
#endif
    unsigned char devtype_from_id;
    cs_devtype_t type;
    unsigned short part_number;	  /**< CoreSight part number, 3 hex digits */
    unsigned int devclass;
    unsigned int devaff0;	  /**< Device affinity register for CPU-affine devices - might be CPU's MPIDR, but might also be zero */
    cs_cpu_t affine_cpu;	  /**< Set by the user via the API */
    cs_power_domain_t power_domain;
    int is_unlocked:1;
    int is_permanently_unlocked:1;

#if DIAG
    int diag_tracing:1;		  /**< Diagnostic messages for actions on this device */
#endif				/* DIAG */
    unsigned int n_api_errors;

    /* Trace bus topology */
    unsigned int n_in_ports;
    unsigned int n_out_ports;
    struct cs_device *ins[CS_MAX_IN_PORTS];
    unsigned char from_out_port[CS_MAX_IN_PORTS];
    struct cs_device *outs[CS_MAX_OUT_PORTS];
    unsigned char to_in_port[CS_MAX_OUT_PORTS];

    /* Device-specific properties */
    union {
        struct debug_props {
            unsigned int didr;	      /**< Contents of DBGDIDR */
            unsigned int devid;	      /**< Contents of DBGDEVID, or zero when not present */
            unsigned int pcsamplereg; /**< Offset to PC sampling register */
            unsigned int debug_arch;  /**< debug architecture */
            struct cs_device *pmu;    /**< PMU for this CPU */
            struct cs_device *etm;    /**< ETM for this CPU */
            struct cs_device *cti;    /**< CTI for this CPU */
        } debug;
        struct pmu_props {
            unsigned int cfgr;
            unsigned int n_counters;  /**< Number of event counters, not including cycle counter */
            unsigned char map_scale;  /**< Spacing in the memory map (power of 2) */
        } pmu;
        struct cti_props {
#define CTI_CHANNELS 4
#define CTI_CHANNEL_MASK ((1U << CTI_CHANNELS) - 1)	/* i.e. 0x0F for 4-channel CTI */
#define CTI_MAX_IN_PORTS 10
#define CTI_MAX_OUT_PORTS 10
            unsigned char n_triggers;	/**< Generally 8, but 9 seen for Cortex-A8 */
            unsigned char n_channels;	/**< Generally 4 */
            struct {
                struct cs_device *dev;
                unsigned int devportid;
            } src[CTI_MAX_IN_PORTS];
            struct {
                struct cs_device *dev;
                unsigned int devportid;
            } dst[CTI_MAX_OUT_PORTS];
        } cti;
        struct etm_props {
            unsigned int etmidr;
            cs_etm_static_config_t sc;
            union {		// union of arch specifc configs - starting with ETMv4
                cs_etm_v4_static_config_t etmv4_sc;
            } sc_ex;
        } etm;
        struct etb_props {
            unsigned int buffer_size_bytes;
            int currently_reading:1;
            int finished_reading:1;
            int is_tmc_device:1;	/* This is a TMC, as opposed to e.g. a classic ETB */
            /* For pre-TMC ETBs, the read and write pointers address words within
               the buffer RAM - for CoreSight ETBs the buffer is always 32-bit RAM,
               so the pointers are scaled by 4.  Only very old pre-CoreSight ETBs
               have other RAM sizes and a RAM width register. */
#define ETB_WIDTH_SCALE_SHIFT 2
            int pointer_scale_shift:4;
            struct tmc_props {
                /* Use the CS_TMC_CONFIG_TYPE_XYZ macros to interpret the config_type field */
                unsigned int config_type:2;	/* Build-time TMC configuration (ETR, ETF, ETB) */
                unsigned int memory_width:4;	/* Memory width: 2 for 32b up to 5 for 256b */
            } tmc;
        } etb;
        struct itm_props {
            unsigned int n_ports;
        } itm;
        struct stm_props {
            unsigned int n_ports;
            unsigned int n_masters;
            unsigned int current_master;
            unsigned char **ext_ports;	  /**< array of pointers to mappings of master ports. */
            int basic_ports:1;
            stm_static_config_t s_config;     /**< RO features registers */
        } stm;
        struct ts_gen_props {
            cs_ts_gen_config_t config;
        } ts;
        struct memap_props {
            int DAR_present:1;            /**< Direct Access Registers are available */
            int TAR_valid:1;              /**< We have a cached copy of the TAR */
            int memap_LPAE:1;             /**< Large Physical Addresses implemented */
            unsigned long cached_TAR;     /**< Cached copy of the TAR */
        } memap;
    } v;
};

#define IS_V8(dev) (dev->v.debug.debug_arch == 0x8)

/*
  We maintain a list of addresses not to be probed, to avoid bus lockups.
*/
struct addr_exclude {
    struct addr_exclude *next;
    cs_physaddr_t from;
    cs_physaddr_t to;
};

/*
  Global information for the system.

  Currently "scope of management of CoreSight library" <= "SoC".  I.e. there is
  no provision for the library managing multiple SoCs, or multiple physical memory
  spaces etc.
*/
struct global {
    struct cs_device *device_top;
#ifdef UNIX_USERSPACE
    int mem_fd;			   /**< File handle for the memory mapped I/O */
#endif				/* UNIX_USERSPACE */
#ifdef CSAL_MEMAP
    cs_device_t memap_default;     /**< MEM-AP parent for new devices, or NULL */
#endif
    int init_called:1;
    int registration_open:1;
    int force_writes:1;
    int diag_tracing_default:1;	   /**< Default trace setting for new devices */
    int diag_checking:1;	   /**< Default diag setting for new devices */
    unsigned int n_api_errors;
    unsigned int n_devices;
    cs_power_domain_t power_domain_default;
    struct cs_device *timestamp_device;
    struct addr_exclude *exclusions;
    int phys_addr_lpae:1;	/* 1 if built with LPAE */
    int virt_addr_64bit:1;	/* 1 if built with 64 bit virtual addresses */
    int devaff0_used:1;		/* Non-zero DEVAFF0 has been seen */
};

/**
 * Convert an opaque device descriptor into a pointer to a device structure
 */
#define DEV(d) cs_get_device_struct(d)

/**
 * Convert a pointer to a device structure into an opaque device descriptor
 */
#define DEVDESC(d) ((void *)(d))

/**
 * The special opaque device descriptor indicating an error
 */
#define ERRDESC ((void *)0)


#ifdef DIAG
#define DTRACE(d) ((d)->diag_tracing || G.diag_tracing_default)
#define DTRACEG   (G.diag_tracing_default)
#else				/* !DIAG */
#define DTRACE(d) 0
#define DTRACEG   0
#endif				/* DIAG */

/*
  DCHECK() defines whether extra checks are done on the device.
*/
#if CHECK
#define DCHECK(d) (G.diag_checking)
#else				/* !CHECK */
#define DCHECK(d) 0
#endif				/* CHECK */


#ifdef UNIX_USERSPACE
/*
  Check that the offset argument to mmap() is wide enough that we can map any
  physical address in /dev/mem.  This might need us to define _FILE_OFFSET_BITS=64.
*/
typedef int check_mmap_offset_is_big_enough[1 /
                                            (sizeof(off_t) >=
                                             sizeof(cs_physaddr_t))];
#endif				/* UNIX_USERSPACE */


#ifdef UNIX_KERNEL
#undef DIAG
#endif

#ifdef DIAG

#ifdef UNIX_KERNEL
#define diagf printk
#else
#define diagf _diagf
extern void _diagf(char const *s, ...);
#endif

#else				/* !DIAG */
void diagf(char const *s, ...)
{
}
#endif				/* DIAG */
/*
  This is the "physical address" value for a non-memory-mapped device, e.g.
  a replicator, that is represented for topology reasons
*/
#define CS_NO_PHYS_ADDR 1

/*
  Coresight devices must be aligned on a 4K page - this may be the case even
  if the OS kernel is using larger pages.  (We then have to get creative
  with memory mappings.)
*/
#define is_4k_page_address(x) (((x) & 0xfff) == 0)

/* Claim tag handling constants */
#define CS_CLAIM_PMU_EXTERNAL  0x04	/* PMU in use - in DBGCLAIM */
#define CS_CLAIM_PMU_INTERNAL  0x08
#define CS_CLAIM_CTI_EXTERNAL  0x10	/* CPU CTI in use - in DBGCLAIM */
#define CS_CLAIM_CTI_INTERNAL  0x20


/* Extern declarations - make common function implementations visible across all compilation
   units, but not external API */


/* Non API functions implemented in cs_access_cmnfns.c */
/* data */
extern struct global G;

/* functions */
extern int cs_device_is_non_mmio(struct cs_device *d);
extern int cs_device_is_funnel(struct cs_device *d);
extern int cs_device_is_replicator(struct cs_device *d);
extern char const *cs_device_type_name(struct cs_device *d);
extern int cs_report_error(char const *fmt, ...);
extern int cs_report_device_error(struct cs_device *d, char const *fmt,
                                  ...);
extern struct cs_device *cs_get_device_struct(cs_device_t dev);
extern void cs_device_init(struct cs_device *d, cs_physaddr_t addr);
extern struct cs_device *cs_device_new(cs_physaddr_t addr,
                                       void volatile *local_addr);

extern unsigned int volatile *_cs_get_register_address(struct cs_device *d,
                                                       unsigned int off);
extern uint32_t _cs_read(struct cs_device *d, unsigned int off);
extern uint64_t _cs_read64(struct cs_device *d, unsigned int off);

extern int _cs_write_wo(struct cs_device *d, unsigned int off,
                        uint32_t data);
extern int _cs_write64_wo(struct cs_device *d, unsigned int off,
                          uint64_t data);
extern int _cs_write_traced(struct cs_device *d, unsigned int off,
                            uint32_t data, char const *oname);
extern int _cs_write64_traced(struct cs_device *d, unsigned int off,
                              uint64_t data, char const *oname);
extern int _cs_write_mask(struct cs_device *d, unsigned int off,
                          uint32_t mask, uint32_t data);
extern int _cs_set_mask(struct cs_device *d, unsigned int off,
                        uint32_t mask, uint32_t data);
extern int _cs_set_bit(struct cs_device *d, unsigned int off,
                       uint32_t mask, int value);
extern int _cs_set(struct cs_device *d, unsigned int off,
                   uint32_t bits);
extern int _cs_set_wo(struct cs_device *d, unsigned int off,
                      uint32_t bits);
extern int _cs_clear(struct cs_device *d, unsigned int off,
                     uint32_t bits);
extern int _cs_isset(struct cs_device *d, unsigned int off,
                     uint32_t bits);
extern void _cs_set_wait_iterations(int iterations);
extern int _cs_wait(struct cs_device *d, unsigned int off,
                    unsigned int bit);
extern int _cs_waitnot(struct cs_device *d, unsigned int off,
                       unsigned int bit);
extern int _cs_waitbits(struct cs_device *d, unsigned int off,
                        uint32_t bits, cs_reg_waitbits_op_t operation,
                        uint32_t pattern, uint32_t *p_last_val);

extern int _cs_claim(struct cs_device *d, uint32_t bit);
extern int _cs_unclaim(struct cs_device *d, uint32_t bit);
extern int _cs_isclaimed(struct cs_device *d, uint32_t bit);

extern int _cs_isunlocked(struct cs_device *d);
extern int _cs_is_lockable(struct cs_device *d);
extern void _cs_unlock(struct cs_device *d);
extern void _cs_lock(struct cs_device *d);

extern void *io_map(cs_physaddr_t addr, unsigned int size, int writable);
extern void io_unmap(void volatile *addr, unsigned int size);
extern int _cs_map(struct cs_device *d, int writable);
extern void _cs_unmap(struct cs_device *d);

#define _cs_write(d, off, data) _cs_write_traced(d, off, data, #off)
#define _cs_write64(d, off, data) _cs_write64_traced(d, off, data, #off)

/* Non API fns in cs_sw_stim.c */
extern unsigned int cs_stm_get_ext_ports_size(struct cs_device *d);
extern int _cs_swstim_trace_enable(struct cs_device *d);
extern int _cs_swstim_trace_disable(struct cs_device *d);
extern int _cs_swstim_set_trace_id(struct cs_device *d, cs_atid_t id);
extern int _cs_stm_config_static_init(struct cs_device *d);

/* Non API fns in cs_etm.c */
extern unsigned int _cs_etm_version(struct cs_device *d);
extern int _cs_etm_enable_programming(struct cs_device *d);
extern int _cs_etm_disable_programming(struct cs_device *d);
extern int _cs_etm_static_config_init(struct cs_device *d);

/* none API fns in cs_ts_gen.c */
extern int _cs_tsgen_enable(struct cs_device *d, int enable);


#endif				/* _included_cs_access_cmnfns_h */

/* end of  cs_access_cmnfns.h */
