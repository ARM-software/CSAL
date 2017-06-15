/*
  CoreSight access library demonstrator

  ST-Ericsson Snowball and ARM Versatile Express TC2 boards are currently supported out-of-the-box.

  Copyright (C) ARM Limited, 2013-2016. All rights reserved.

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

#define _GNU_SOURCE

#include "csaccess.h"
#include "cs_utility.h"
#include "cs_demo_known_boards.h"

/* The CS register specification is needed only for the filter details in
   ETM/PTM configuration - this should be abstracted out somehow (TBD) */
#include "csregisters.h"

#include "cs_trace_metadata.h"

#include <sched.h>		/* for CPU_* family, requires glibc 2.6 or later */
#include <unistd.h>		/* for usleep() */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>

#ifndef UNIX_USERSPACE
#define UNIX_USERSPACE 1
#endif				/* UNIX_USERSPACE */

#if UNIX_USERSPACE
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#endif				/* UNIX_USERSPACE */


/* Change these to capture the specific region of the kernel required
   KERNEL_TRACE_SIZE          is the extent of the region to trace
   KERNEL_TRACE_VIRTUAL_ADDR  is the virtual address of the start of the region to trace,
   i.e. corresponding to addresses in the vmlinux file
*/

#define KERNEL_TRACE_SIZE 0x700000
#define ALL_CPUS -1

static struct cs_devices_t devices;

/* command line options */
static int cpu_to_trace;
static bool itm;
static bool itm_only;
static bool full;
static unsigned int seed = 0x10000000;
static bool verbose;
static bool trace_timestamps;
static bool trace_cycle_accurate;
#define BOARD_NAME_LEN 256
static char board_name[BOARD_NAME_LEN];

static bool etb_stop_on_flush;
static unsigned int etb_post_trig_words;

static bool return_stack;

#define INVALID_ADDRESS 1	/* never a valid address */
static unsigned long o_trace_start_address = INVALID_ADDRESS;
static unsigned long o_trace_end_address = INVALID_ADDRESS;

static unsigned long kernel_virtual_address(void)
{
    static unsigned long addr = 0;
    if (!addr) {
        FILE *fd = fopen("/proc/kallsyms", "r");
        if (fd) {
            /* Pick the address of whichever kernel symbol happens to be first,
               and round down to a page boundary */
            if (fscanf(fd, "%lx", &addr) == 1) {
                addr &= ~0xfff;	/* assume 4K pages */
                printf("kernel symbol found @ 0x%lX\n", addr);
            }
            fclose(fd);
        }
    }
    return addr;
}

#ifndef KERNEL_TRACE_VIRTUAL_ADDR
#define KERNEL_TRACE_VIRTUAL_ADDR (kernel_virtual_address())
#endif				/* KERNEL_TRACE_VIRTUAL_ADDR */

/* Pause after each significant step in the demo */
int pause_mode;

void pause_demo(void)
{
    fflush(stdout);
    if (pause_mode) {
        int c;
        fprintf(stderr, "[press RETURN to continue or q/Q to quit]\r");
        fflush(stderr);
        c = getchar();
        if (c == 'q' || c == 'Q') {
            fprintf(stderr, "CSDEMO: exiting demo.\n");
            exit(EXIT_FAILURE);
        }
    } else {
        fflush(stderr);
    }
}


void await_user_stop(void)
{
    int c;
    fprintf(stderr, "[press RETURN to stop tracing or q/Q to quit]\r");
    fflush(stderr);
    c = getchar();
    if (c == 'q' || c == 'Q') {
        fprintf(stderr, "CSDEMO: exiting demo.\n");
        exit(EXIT_FAILURE);
    }
}


static int do_init_etm(cs_device_t dev)
{
    int rc;
    struct cs_etm_config config;
    int etm_version = cs_etm_get_version(dev);

    printf("CSDEMO: Initialising ETM/PTM\n");

    /* ASSERT that this is an etm etc */
    assert(cs_device_has_class(dev, CS_DEVCLASS_SOURCE));

    /* set to a 'clean' state - clears events & values, retains ctrl and ID, ensure programmable */
    if ((rc = cs_etm_clean(dev)) != 0) {
        printf("CSDEMO: Failed to set ETM/PTM into clean state\n");
        return rc;
    }

    /* program up some basic trace control.
       Set up to trace all instructions.
    */
    if (!CS_ETMVERSION_IS_ETMV4(etm_version)) {

        cs_etm_config_init(&config);
        config.flags = CS_ETMC_CONFIG;
        cs_etm_config_get(dev, &config);
        config.trace_enable_event = CS_ETMER_ALWAYS;
        config.flags |= CS_ETMC_TRACE_ENABLE;
        /* "To trace all memory:
           - set bit [24] in the ETMTECR1 to 1
           - set all other bits in the ETMTECR1 to 0
           - set the ETMEEVER to 0x6F (TRUE)
           This has the effect of excluding nothing, that is, tracing everything." */
        config.trace_enable_event = CS_ETMER_ALWAYS;
        config.trace_enable_cr1 = CS_ETMTECR1_EXCLUDE;
        config.trace_enable_cr2 = 0x00000000;
        cs_etm_config_put(dev, &config);
    } else {
        /* ETMv4 initialisation */
        cs_etmv4_config_t v4config;

        cs_etm_config_init_ex(dev, &v4config);
        v4config.flags = CS_ETMC_CONFIG;
        cs_etm_config_get_ex(dev, &v4config);
        v4config.flags |= CS_ETMC_TRACE_ENABLE | CS_ETMC_EVENTSELECT;
        /* trace enable */
        if (itm_only) {
            printf("No Viewinst, ITM only\n");
            v4config.victlr = 0x0;	/* Viewinst - trace nothing. */
        } else {
            printf("Viewinst trace everything\n");
            v4config.victlr = 0x201;	/* Viewinst - trace all, ss started. */
        }
        v4config.viiectlr = 0;	/* no address range */
        v4config.vissctlr = 0;	/* no start stop points */
        /* event select */
        v4config.eventctlr0r = 0;	/* disable all event tracing */
        v4config.eventctlr1r = 0;
        /* config */
        v4config.stallcrlr = 0;	/* no stall */
        v4config.syncpr = 0xC;	/* sync 4096 bytes */
        cs_etm_config_put_ex(dev, &v4config);

    }
    return 0;
}

static void show_etm_config(unsigned int n)
{
    cs_etm_config_t tconfig;	/* PTM/ETMv3 config */
    cs_etmv4_config_t t4config;	/* ETMv4 config */
    void *p_config = 0;

    if (CS_ETMVERSION_MAJOR(cs_etm_get_version(devices.ptm[n])) >=
        CS_ETMVERSION_ETMv4)
        p_config = &t4config;
    else
        p_config = &tconfig;

    cs_etm_config_init_ex(devices.ptm[n], p_config);
    tconfig.flags = CS_ETMC_ALL;
    t4config.flags = CS_ETMC_ALL;
    cs_etm_config_get_ex(devices.ptm[n], p_config);
    cs_etm_config_print_ex(devices.ptm[n], p_config);
}

static int do_config_etmv3_ptm(int n_core)
{
    cs_etm_config_t tconfig;

    cs_etm_config_init(&tconfig);
    tconfig.flags = CS_ETMC_TRACE_ENABLE;
    cs_etm_config_get(devices.ptm[n_core], &tconfig);
    //   cs_etm_config_print(&tconfig);
    tconfig.flags = CS_ETMC_TRACE_ENABLE;

    if (!full) {
        /* Select address comparator #0 as a start address */
        /* Select address comparator #1 as a stop address */
        /* n.b. ETM numbers the comparators from 1. */
        tconfig.flags |= CS_ETMC_ADDR_COMP;
        tconfig.trace_enable_cr1 = 0x1;	/* address range comparator 0 */
        tconfig.trace_start_comparators = 0x0000;	/* Select comparator #0 as a start address */
        tconfig.trace_stop_comparators = 0x0000;	/* Select comparator #1 as a stop address  */
        tconfig.addr_comp_mask = 0x3;	/* Set address comparators 0 and 1 for programming */
        tconfig.addr_comp[0].address = o_trace_start_address & 0xFFFFFFFE;
//      tconfig.addr_comp[0].access_type = CS_ETMACT_EX|CS_ETMACT_ARMTHUMB|CS_ETMACT_USER;
        //tconfig.addr_comp[0].access_type = 0x1;
        tconfig.addr_comp[0].access_type = 0x1 | CS_ETMACT_ARMTHUMB;
        tconfig.addr_comp[1].address = o_trace_end_address & 0xFFFFFFFE;
//      tconfig.addr_comp[1].access_type = CS_ETMACT_EX|CS_ETMACT_ARMTHUMB|CS_ETMACT_USER;
        tconfig.addr_comp[1].access_type = 0x1 | CS_ETMACT_ARMTHUMB;
    }
    tconfig.flags |= CS_ETMC_COUNTER;
    tconfig.counter_mask = 0x03;	/* set first 2 bits in mask to ensure first 2 counters are programmed */
    tconfig.counter[0].value = 0x1000;
    tconfig.counter[0].enable_event = CS_ETMER_ALWAYS;	/*CS_ETMER_SAC(0); */
    tconfig.counter[0].reload_value = 0x2000;
    tconfig.counter[0].reload_event = CS_ETMER_CZERO(0);
    tconfig.counter[1].value = 0x1000;
    tconfig.counter[1].enable_event = CS_ETMER_SEQSTATE(2);
    tconfig.counter[1].reload_value = 0x2000;
    tconfig.counter[1].reload_event = CS_ETMER_CZERO(1);

    tconfig.flags |= CS_ETMC_SEQUENCER;
    tconfig.sequencer.state = 1;
    tconfig.sequencer.transition_event[CS_ETMSQOFF(1, 2)] =
        CS_ETMER_SAC(0);
    tconfig.sequencer.transition_event[CS_ETMSQOFF(2, 3)] =
        CS_ETMER_SAC(1);
    tconfig.sequencer.transition_event[CS_ETMSQOFF(1, 3)] = CS_ETME_NEVER;
    tconfig.sequencer.transition_event[CS_ETMSQOFF(2, 1)] = CS_ETME_NEVER;
    tconfig.sequencer.transition_event[CS_ETMSQOFF(3, 1)] = CS_ETME_NEVER;
    tconfig.sequencer.transition_event[CS_ETMSQOFF(3, 2)] = CS_ETME_NEVER;
    
    if (trace_timestamps) {
        tconfig.flags |= CS_ETMC_TS_EVENT;
        tconfig.timestamp_event = CS_ETMER_CZERO(0);
    }

    if (return_stack) {
        tconfig.cr.raw.c.ret_stack = 1;
    }

    cs_etm_config_print(&tconfig);
    cs_etm_config_put(devices.ptm[n_core], &tconfig);

    /* Show the resulting configuration */
    printf("CSDEMO: Reading back configuration after programming...\n");
    show_etm_config(n_core);

    if (cs_error_count() > 0) {
        printf
            ("CSDEMO: %u errors reported in configuration - not running demo\n",
             cs_error_count());
        return -1;
    }
    return 0;
}

static int do_config_etmv4(int n_core)
{
    cs_etmv4_config_t tconfig;
    cs_device_t etm = devices.ptm[n_core];

    /* default settings are trace everything - already set. */
    cs_etm_config_init_ex(etm, &tconfig);
    tconfig.flags =
        CS_ETMC_TRACE_ENABLE | CS_ETMC_CONFIG | CS_ETMC_EVENTSELECT;
    cs_etm_config_get_ex(etm, &tconfig);

    if (tconfig.scv4->idr2.bits.vmidsize > 0)
        tconfig.configr.bits.vmid = 1;	/* VMID trace enable */
    if (tconfig.scv4->idr2.bits.cidsize > 0)
        tconfig.configr.bits.cid = 1;	/* context ID trace enable. */

    if (return_stack)
        tconfig.configr.bits.rs = 1; /* set the return stack */
    
    if (!full) {
        /*  set up an address range filter - use comparator pair and the view-inst registers */

        tconfig.addr_comps[0].acvr_l = o_trace_start_address & 0xFFFFFFFF;
        tconfig.addr_comps[0].acvr_h =
            (o_trace_start_address >> 32) & 0xFFFFFFFF;
        tconfig.addr_comps[0].acatr_l = 0x0;	/* instuction address compare, all ELs, no ctxt, vmid, data, etc */
        tconfig.addr_comps[1].acvr_l = o_trace_end_address & 0xFFFFFFFF;
        tconfig.addr_comps[1].acvr_h =
            (o_trace_end_address >> 32) & 0xFFFFFFFF;
        tconfig.addr_comps[1].acatr_l = 0x0;	/* instuction address compare, all ELs, no ctxt, vmid, data, etc */

        /* mark the config structure to program the above registers on 'put' */
        tconfig.addr_comps_acc_mask = 0x3;
        tconfig.flags |= CS_ETMC_ADDR_COMP;

        /* finally, set up ViewInst to trace according to the resources we have set up */
        tconfig.viiectlr = 0x1;	/* program the address comp pair 0 for include */
        tconfig.syncpr = 0x0;	/* no extra sync */

    }
    cs_etm_config_print_ex(etm, &tconfig);
    cs_etm_config_put_ex(etm, &tconfig);

    /* Show the resulting configuration */
    printf("CSDEMO: Reading back configuration after programming...\n");
    show_etm_config(n_core);

    if (cs_error_count() > 0) {
        printf
            ("CSDEMO: %u errors reported in configuration - not running demo\n",
             cs_error_count());
        return -1;
    }
    return 0;
}

static int do_configure_trace(const struct board *board)
{
    int i, r;

    printf("CSDEMO: Configuring trace...\n");
    /* Ensure TPIU isn't generating back-pressure */
    cs_disable_tpiu();
    /* While programming, ensure we are not collecting trace */
    cs_sink_disable(devices.etb);
    if (devices.itm_etb != NULL) {
        cs_sink_disable(devices.itm_etb);
    }
    for (i = 0; i < board->n_cpu; ++i) {
        printf
            ("CSDEMO: Configuring trace source id for CPU #%d ETM/PTM...\n",
             i);
        devices.ptm[i] = cs_cpu_get_device(i, CS_DEVCLASS_SOURCE);
        if (devices.ptm[i] == CS_ERRDESC) {
            fprintf(stderr, "** Failed to get trace source for CPU #%d\n",
                    i);
            return -1;
        }
        if (cs_set_trace_source_id(devices.ptm[i], 0x10 + i) < 0) {
            return -1;
        }
        if (do_init_etm(devices.ptm[i]) < 0) {
            return -1;
        }
    }
    if (itm) {
        cs_set_trace_source_id(devices.itm, 0x20);
    }
    cs_checkpoint();

    for (i = 0; i < board->n_cpu; ++i) {
        if (CS_ETMVERSION_MAJOR(cs_etm_get_version(devices.ptm[i])) >=
            CS_ETMVERSION_ETMv4)
            r = do_config_etmv4(i);
        else
            r = do_config_etmv3_ptm(i);
        if (r != 0)
            return r;
    }

    printf("CSDEMO: Enabling trace...\n");
    if (cs_sink_enable(devices.etb) != 0) {
        printf
            ("CSDEMO: Could not enable trace buffer - not running demo\n");
        return -1;
    }
    if (devices.itm_etb != NULL) {
        if (cs_sink_enable(devices.itm_etb) != 0) {
            printf("CSDEMO: Could not enable ITM trace buffer\n");
        }
    }

    for (i = 0; i < board->n_cpu; ++i) {
        if (trace_timestamps)
            cs_trace_enable_timestamps(devices.ptm[i], 1);
        if (trace_cycle_accurate)
            cs_trace_enable_cycle_accurate(devices.ptm[i], 1);
        cs_trace_enable(devices.ptm[i]);
    }

    if (itm) {
        cs_trace_swstim_enable_all_ports(devices.itm);
        cs_trace_swstim_set_sync_repeat(devices.itm, 32);
        if (trace_timestamps)
            cs_trace_enable_timestamps(devices.itm, 1);
        cs_trace_enable(devices.itm);
    }

    unsigned int ffcr_val;
    /* for this demo we may set stop on flush and stop capture by maunal flushing later */
    if (etb_stop_on_flush) {
        /* set up some bits in the FFCR - enabling the  ETB later will retain these bits */
        ffcr_val = cs_device_read(devices.etb, CS_ETB_FLFMT_CTRL);
        ffcr_val |= CS_ETB_FLFMT_CTRL_StopFl;
        if (cs_device_write(devices.etb, CS_ETB_FLFMT_CTRL, ffcr_val) == 0) {
            printf("CSDEMO: setting stop on flush, ETB FFCR = 0x%08X",
                   ffcr_val);
        } else {
            printf
                ("CSDEMO: Failed to set stop on flush, ETB FFCR to 0x%08X",
                 ffcr_val);
        }
    }

    cs_checkpoint();
    if (cs_error_count() > 0) {
        printf
            ("CSDEMO: %u errors reported when enabling trace - not running demo\n",
             cs_error_count());
        return -1;
    }

    printf("CSDEMO: CTI settings....\n");
    cs_cti_diag();

    printf("CSDEMO: Configured and enabled trace.\n");
    return 0;
}

/* if we have set up stop on flush, manual flush and wait for stop */
static void cs_etb_flush_and_wait_stop()
{
    unsigned int ffcr_val, ffsr_val;
    printf("CSDEMO: Flushing ETB and waiting for formatter stop\n");
    ffcr_val = cs_device_read(devices.etb, CS_ETB_FLFMT_CTRL);
    ffcr_val |= CS_ETB_FLFMT_CTRL_FOnMan;
    cs_device_write(devices.etb, CS_ETB_FLFMT_CTRL, ffcr_val);
    if (cs_device_wait
        (devices.etb, CS_ETB_FLFMT_STATUS, CS_ETB_FLFMT_STATUS_FtStopped,
         CS_REG_WAITBITS_ALL_1, 0, &ffsr_val) == 0) {
        if (verbose)
            printf("CSDEMO: ETB collection stopped\n");
    } else {
        if (verbose)
            printf("CSDEMO: ETB FFSR=0x%08X\n", ffsr_val);
        printf
            ("CSDEMO: Warning ETB collection not stopped on flush on trigger\n");
    }
}

#if NOT_CURRENTLY_USED
static void do_show_device(cs_device_t d)
{
    printf("  %" CS_PHYSFMT ":\n", cs_device_address(d));
}

/*
  This is really for integration testing - we would not normally write trace
  directly into an ETB.
*/
static void do_generate_synthetic_trace_data()
{
    {
        union {
            int n;		/* Force alignment */
            char s[16];
        } buf;
        strcpy(buf.s, "Hello world");
        cs_insert_trace_data(devices.etb, &buf, sizeof buf);
    }
}
#endif


/** Show process current affinity */
static int show_affinity(void)
{
    int rc, n, i;
    cpu_set_t cpus;
    rc = sched_getaffinity( /*calling process */ 0, sizeof cpus, &cpus);
    if (rc < 0) {
        perror("sched_getaffinity");
        return rc;
    }
    printf("** Currently affine CPUs:");
    /* On older kernels, CPU_COUNT is not available */
#ifdef CPU_COUNT
    n = CPU_COUNT(&cpus);
#else
    n = CPU_SETSIZE;
#endif
    for (i = 0; n > 0; ++i) {
        if (CPU_ISSET(i, &cpus)) {
            printf(" #%u", i);
            --n;
        }
    }
    printf("\n");
    return rc;
}

/** Set process affinity to a single specified CPU */
static int set_affinity(unsigned int cpu)
{
    int rc;
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(cpu, &cpus);
    rc = sched_setaffinity( /*calling process */ 0, sizeof cpus, &cpus);
    if (rc < 0) {
        perror("sched_setaffinity");
        fprintf(stderr, "** Failed to set process affinity to CPU=%u\n",
                cpu);
    }
    return rc;
}


static int help(void)
{
    printf("Usage:\n");
    printf("-h\tThis help screen.\n");
    printf("-c <cpu>\tSelect CPU for demo to run on. Default is 0.\n");
    printf
        ("-board-name <name>  \tcConfigure according to supplied hardware name rather than probing the board 'cpuinfo'\n");
    printf
        ("-trace-start <address>\tStart trace capture at given <address>.\n");
    printf
        ("                      \tDefault is address of first code symbol.\n");
    printf
        ("-trace-stop <address> \tStop trace capture at <given address>.\n");
    printf
        ("                      \tDefault is address of first code symbol + KERNEL_TRACE_SIZE.\n");
    printf("-itm\tEnable ITM tracing, ITM tracing disabled by default.\n");
    printf("-itm_only\tEnable ITM tracing only, Leave core trace off.\n");
    printf("-cycle-accurate\tEnable Cycle Accurate tracing\n");
    printf("-timestamps\tEnable trace timestamps\n");
    printf
        ("-filter\tShow restricted amount of trace - enables extraction of memory area for decode\n");
    printf
        ("-fon-stop\tEnable ETB stop on flush. Uses manual flush to halt ETB trace collection\n");
    printf("-pause\tRun the demo with a pause after each step.\n");
    return EXIT_FAILURE;
}


int main(int argc, char **argv)
{
    /* Defaults */
    int stage = 2;
    cpu_to_trace = ALL_CPUS;	// no CPU affinity selected (yet), trace all CPUs
    itm = false;
    itm_only = false;
    full = true;
    etb_stop_on_flush = 0;
    etb_post_trig_words = 0;
    verbose = false;
    trace_timestamps = false;
    trace_cycle_accurate = false;
    return_stack = false;
    board_name[0] = 0;

    pause_mode = 0;

    if (argc >= 2) {
        int i = 1;
        for (; i < argc; ++i) {
            char const *opt = argv[i];
            if (opt[0] != '-') {
                fprintf(stderr,
                        "Unknown argument \"%s\", use -h for help:\n",
                        opt);
                return help();
            } else {
                ++opt;
                if (opt[0] == '-') {
                    ++opt;
                }
                if (strcmp(opt, "c") == 0) {
                    if (i + 1 < argc) {
                        cpu_to_trace = strtoul(argv[i + 1], NULL, 0);
                        printf("Selecting CPU #%d\n", cpu_to_trace);
                        ++i;
                    } else {
                        return help();
                    }
                } else if (strncmp(opt, "seed", 4) == 0) {
                    if (i + 1 < argc) {
                        seed = strtoul(argv[i + 1], NULL, 0);
                        printf("ITM trace seed starts at %u / 0x%x\n",
                               seed, seed);
                        ++i;
                    } else {
                        return help();
                    }
                } else if (strncmp(opt, "no-run", 6) == 0) {
                    stage = 0;
                } else if (strncmp(opt, "itm_only", 7) == 0) {
                    printf("Enabling ITM Only\n");
                    itm = true;
                    itm_only = true;
                } else if (strncmp(opt, "itm", 3) == 0) {
                    printf("Enabling ITM\n");
                    itm = true;
                } else if (strncmp(opt, "timestamps", 3) == 0) {
                    printf("Enabling trace timestamps\n");
                    trace_timestamps = true;
                } else if (strncmp(opt, "cycle-accurate", 3) == 0) {
                    printf("Enabling cycle accurate trace\n");
                    trace_cycle_accurate = true;
                } else if (strncmp(opt, "fon-stop", 8) == 0) {
                    printf("Enabling ETB Stop on Flush\n");
                    etb_stop_on_flush = true;
                } else if (strncmp(opt, "return-stack", 12) == 0) {
                    printf("Enabling ETM return stack\n");
                    return_stack = true;
                } else if (strncmp(opt, "etb-words", 9) == 0) {
                    if (i + 1 < argc) {
                        etb_post_trig_words =
                            strtoul(argv[i + 1], NULL, 0);
                        printf
                            ("Collecting %d words in ETB after trigger\n",
                             etb_post_trig_words);
                        ++i;
                    } else {
                        return help();
                    }
                } else if (strncmp(opt, "no-itm", 6) == 0) {
                    printf("Disabling ITM\n");
                    itm = false;
                } else if (strncmp(opt, "h", 1) == 0) {
                    help();
                    return EXIT_SUCCESS;
                } else if (strcmp(opt, "v") == 0) {
                    cs_diag_set(1);
                    verbose = true;
                } else if (strncmp(opt, "filter", 6) == 0) {
                    printf("Trace filtering active.\n");
                    full = false;
                } else if (strncmp(opt, "pause", 5) == 0) {
                    pause_mode = 1;
                } else if (strncmp(opt, "no-pause", 8) == 0) {
                    pause_mode = 0;
                } else if (strcmp(opt, "trace-start") == 0) {
                    if (i + 1 >= argc) {
                        return help();
                    }
                    ++i;
                    sscanf(argv[i], "%lx", &o_trace_start_address);
                } else if (strcmp(opt, "trace-stop") == 0) {
                    if (i + 1 >= argc) {
                        return help();
                    }
                    ++i;
                    sscanf(argv[i], "%lx", &o_trace_end_address);
                } else if (strcmp(opt, "board-name") == 0) {
                    if (i + 1 >= argc) {
                        return help();
                    }
                    ++i;
                    strncpy(board_name, argv[i], BOARD_NAME_LEN - 1);
                    board_name[BOARD_NAME_LEN - 1] = 0;
                } else {
                    fprintf(stderr,
                            "Unknown option \"%s\", use -h for help:\n",
                            opt);
                    return help();
                }
            }
        }
    } else {
        printf("Default configuration, no CPU affinity selected. ");
        if (itm) {
            printf("ITM enabled.\n");
        } else {
            printf("ITM disabled.\n");
        }
    }

    if (o_trace_start_address == INVALID_ADDRESS) {
        o_trace_start_address = KERNEL_TRACE_VIRTUAL_ADDR;
    }
    if (o_trace_end_address == INVALID_ADDRESS) {
        o_trace_end_address = o_trace_start_address + KERNEL_TRACE_SIZE;
    }
    if (!(o_trace_start_address < o_trace_end_address)) {
        fprintf(stderr,
                "** trace end address 0x%lx must be greater than trace start address 0x%lx\n",
                o_trace_end_address, o_trace_start_address);
        return EXIT_FAILURE;
    }

    /*
      printf("Trace start and end addresses set to 0x%lX - 0x%lX\n", o_trace_start_address, o_trace_end_address);
      printf("At present we see %s\n", itm ? "ITM enabled" : "No ITM"); */

    const struct board *board;
    int i;
    printf("CoreSight demonstrator\n");
    show_affinity();
    if (cpu_to_trace != ALL_CPUS) {
        if (set_affinity(cpu_to_trace) < 0) {
            return EXIT_FAILURE;
        }
        printf("CSDEMO: affinity set to CPU #%u\n", cpu_to_trace);
        show_affinity();
    }

    pause_demo();

    /* setup by name if one supplied, otherwise probe board for known device */
    if (strlen(board_name) > 0) {
        if (setup_known_board_by_name(board_name, &board, &devices) < 0) {
            return EXIT_FAILURE;
        }
    } else {
        if (setup_known_board(&board, &devices) < 0) {
            return EXIT_FAILURE;
        }
    }

    if (stage == 0) {
        cs_shutdown();
        return EXIT_SUCCESS;
    }

    pause_demo();


    if (do_configure_trace(board) < 0) {
        return EXIT_FAILURE;
    }

    printf("CSDEMO: Trace configured\n");

    pause_demo();

    set_kernel_trace_dump_range(o_trace_start_address,
                                o_trace_end_address);

    if (itm && devices.itm == NULL) {
        printf("CSDEMO: no ITM/STM in system\n");
        itm = 0;
    }

    printf("dumping config with %s\n", itm ? "ITM enabled" : "No ITM");
    do_dump_config(board, &devices, itm);
    cs_checkpoint();

    pause_demo();

    if (0) {
        cs_cti_diag();
        pause_demo();
    }

    printf("CSDEMO: trace buffer contents: %u bytes\n",
           cs_get_buffer_unread_bytes(devices.etb));

    pause_demo();

    if (itm) {
        for (i = 0; i < 40; ++i) {
            cs_trace_stimulus(devices.itm, (i & 0xF), seed + i);
            usleep(100);
        }
    }

    await_user_stop();

    /* a final ITM stimulus to mark end of test -
     * previous may have been overwritten if buffer wrapped.*/
    if (itm) {
        if (cs_device_get_type(devices.itm) == DEV_STM) {
            /* force a sync  - on STM changing this forces a sync packet - this may
             * be needed if buffer wrapped to allow decoder to re-sync with STM stream */
            cs_trace_swstim_set_sync_repeat(devices.itm, 32);
        }
        cs_trace_stimulus(devices.itm, 0xF, 0xBAADF00D);
    }

    /* Stop collection of trace data by manual flush and stop of formatter.
     * This prevents the subsequent tracing of the disable code from overwriting interesting trace.
     * Flush will also flush upstream devices such as the ETM/PTMs and STM/ITM */
    if (etb_stop_on_flush) {
        cs_etb_flush_and_wait_stop();
    }

    printf("CSDEMO: Disable trace...\n");
    /* now shut down all the sources */
    for (i = 0; i < board->n_cpu; ++i) {
        cs_trace_disable(devices.ptm[i]);
    }

    if (itm) {
        cs_trace_disable(devices.itm);
    }
    cs_sink_disable(devices.etb);
    if (devices.itm_etb != NULL) {
        cs_sink_disable(devices.itm_etb);
    }

    printf("CSDEMO: trace buffer contents: %u bytes\n",
           cs_get_buffer_unread_bytes(devices.etb));

    pause_demo();

    for (i = 0; i < board->n_cpu; ++i) {
        show_etm_config(i);
    }
    pause_demo();

    do_fetch_trace(&devices, itm);
    pause_demo();

    printf("CSDEMO: shutdown...\n");
    cs_shutdown();
    return EXIT_SUCCESS;
}

/* end of tracedemo.c */
