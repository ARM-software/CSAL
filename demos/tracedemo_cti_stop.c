/*
  CoreSight access library demonstrator

  ST-Ericsson Snowball and ARM Versatile Express TC2 boards are currently supported out-of-the-box.

  Copyright (C) ARM Limited, 2013. All rights reserved.

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

#define KERNEL_TRACE_SIZE 0x50000
#define ALL_CPUS -1

static struct cs_devices_t devices;

/* command line options */
static int cpu_to_trace;
static bool itm;
static bool full;
static unsigned int seed = 0x10000000;
static bool verbose;

static bool etb_flush_on_trig;
static unsigned int etb_post_trig_words;

static bool trace_timestamps;
static bool trace_cycle_accurate;
#define BOARD_NAME_LEN 256
static char board_name[BOARD_NAME_LEN];

/* allow easy changing of the channels used for this functions */
static int etb_trig_chan;
static int etm_trig_chan;
static int etm_trace_enable_chan;

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

    /* set to a 'clean' state - clears events & values, retains ctrl and ID */
    if ((rc = cs_etm_clean(dev)) != 0) {
        printf("CSDEMO: Failed to set ETM/PTM into clean state\n");
        return rc;
    }

    /* program up some basic trace control. */
    if (!CS_ETMVERSION_IS_ETMV4(etm_version)) {

        cs_etm_config_init(&config);
        config.flags = CS_ETMC_CONFIG;
        cs_etm_config_get(dev, &config);
        config.trace_enable_event = CS_ETMER_ALWAYS;
        cs_etm_config_put(dev, &config);
    } else {
        /* ETMv4 initialisation */
        cs_etmv4_config_t v4config;

        cs_etm_config_init_ex(dev, &v4config);
        v4config.flags = CS_ETMC_CONFIG;
        cs_etm_config_get_ex(dev, &v4config);


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

/* configure a CPU CTI to attach trigout to ptm extin0 on channel n 
   use to control trace-enable

   Also set up a trigger channel on the other external input.
*/

/* Define some channel numbers for our enable and trigger functionality */
#define TRACE_ENABLE_CHAN 0
#define TRIGGER_CHAN 1

/* v7 cores A8/9/15 have EXTIN[0:3] on ETM connected to ports 1-5 */
#define CS_CTI_TRIGOUT_EXTIN0 1
#define CS_CTI_TRIGOUT_EXTIN1 2

static int do_config_cpu_cti_ptm_extin(int nCpu)
{
    int ret = -1;
    cs_device_t cti;
    unsigned int chan_bitmask = 0x1;
    /* find the CTI for this CPU */
    printf("CSDEMO: Setting CTI for CPU %d\n", nCpu);
    cti = cs_cpu_get_device(nCpu, CS_DEVCLASS_CTI);
    if (cti) {
        /* clear down both channels */
        ret = cs_cti_clear_all_active_channels(cti);

        /* set trigger out for EXTIN0 to be associated with TRACE_ENABLE_CHAN */
        if (ret == 0)
            ret =
                cs_cti_set_trigout_channels(cti, CS_CTI_TRIGOUT_EXTIN0,
                                            (chan_bitmask <<
                                             etm_trace_enable_chan));
        /* set trigger out for EXTIN1 to be associated with TRIGGER_CHAN */
        if (ret == 0)
            ret =
                cs_cti_set_trigout_channels(cti, CS_CTI_TRIGOUT_EXTIN1,
                                            (chan_bitmask <<
                                             (etm_trig_chan)));
        /* enable the CTI */
        if (ret == 0) {
            ret = cs_cti_enable(cti);
        }

    }

    if (ret != 0) {
        printf("CSDEMO: Failed to configure CTI for CPU %d\n", nCpu);
    } else {
        printf("CSDEMO: CTI config complete\n");
    }
    pause_demo();
    return ret;
}

/* activate channel event for all cores using CTI on any one. CTM should transmit this to all CTIs on this channel. */
static int cs_cti_set_channel(int nCpu, int channel)
{
    int ret = -1;
    cs_device_t cti;
    /* find the CTI for this CPU */
    cti = cs_cpu_get_device(nCpu, CS_DEVCLASS_CTI);
    if (cti) {
        /* use the APPSET register to set the event */
        ret = cs_cti_set_active_channel(cti, channel);
    }
    return ret;
}

/* ensure the CTI for a CPU is not driving any events */
static int cs_cti_clear_channels(int nCpu)
{
    int ret = -1;
    cs_device_t cti;
    /* find the CTI for this CPU */
    cti = cs_cpu_get_device(nCpu, CS_DEVCLASS_CTI);
    if (cti) {
        /* use the APPCLEAR register to clear all the events */
        ret = cs_cti_clear_all_active_channels(cti);
    }
    return ret;
}

/* set the CTI trigout port connected to ETB trigin.
   Set the ETB to flush on trigger, halt on flush.
*/
#define CS_CTI_ETB_TRIGIN_PORT 1

static int cs_etb_flush_and_stop_trig(cs_device_t in_cti)
{
    int ret = -1;
    cs_device_t cti;
    cs_device_t dev_list;
    unsigned int ffcr_val;

    printf("CSDEMO: Setting up ETB flush on trigger and stop on flush\n");

    /* if no cti supplied, find the first non-cpu CTI - assume this is attached to the ETB */
    if (in_cti == 0) {
        cti = 0;
        dev_list = cs_device_first();
        while ((dev_list != CS_ERRDESC) && (cti == 0)) {
            if (cs_device_has_class(dev_list, CS_DEVCLASS_CTI)) {
                if (cs_device_get_affinity(dev_list) < 0) {
                    cti = dev_list;
                }
            }
            dev_list = cs_device_next(dev_list);
        }
    } else {
        cti = in_cti;
    }

    /* if we have a CTI then use it to trigger the ETB trigger port on our trigger channel */
    if (cti) {
        ret =
            cs_cti_set_trigout_channels(cti, CS_CTI_ETB_TRIGIN_PORT,
                                        (0x1U << etb_trig_chan));
        if (ret == 0)
            ret = cs_cti_enable(cti);
    }

    if (ret == 0) {
        cs_set_buffer_trigger_counter(devices.etb, etb_post_trig_words);
        if (devices.etb != 0) {
            /* set up some bits in the FFCR - enabling the  ETB later will retain these bits */
            ffcr_val = cs_device_read(devices.etb, CS_ETB_FLFMT_CTRL);
            ffcr_val |=
                CS_ETB_FLFMT_CTRL_TrigEvt | CS_ETB_FLFMT_CTRL_StopFl |
                CS_ETB_FLFMT_CTRL_FOnTrig;
            ret =
                cs_device_write(devices.etb, CS_ETB_FLFMT_CTRL, ffcr_val);
        } else {
            ret = -1;
        }
    }

    if (ret == 0)
        printf("CSDEMO: ETB setup complete\n");
    else
        printf("CSDEMO: ETB setup failed\n");

    return ret;
}

/* clear down any bits for flush, trigger and stop control in the FFCR */
static int cs_etb_clear_flush_stop()
{
    int ret = -1;
    unsigned int ffcr_val;
    ffcr_val = cs_device_read(devices.etb, CS_ETB_FLFMT_CTRL);
    ffcr_val &= 0xF;
    ret = cs_device_write(devices.etb, CS_ETB_FLFMT_CTRL, ffcr_val);
    return ret;
}

static int do_config_etmv3_ptm(int n_core)
{
    cs_etm_config_t tconfig;

    cs_etm_config_init(&tconfig);
    tconfig.flags = CS_ETMC_TRACE_ENABLE;
    cs_etm_config_get(devices.ptm[n_core], &tconfig);
    //   cs_etm_config_print(&tconfig);
    tconfig.flags = CS_ETMC_TRACE_ENABLE;

    /* "To trace all memory:
       - set bit [24] in the ETMTECR1 to 1
       - set all other bits in the ETMTECR1 to 0
       - set the ETMEEVER to 0x6F (TRUE)
       This has the effect of excluding nothing, that is, tracing everything." */
    /* in this case we are tracing when there is not an EXTIN(0) signal - when this appears 
       then tracing will be disabled. */
    tconfig.trace_enable_event = CS_ETME_NOT(CS_ETMER_EXTIN(0));
    tconfig.trace_enable_cr1 = CS_ETMTECR1_EXCLUDE;
    tconfig.trace_enable_cr2 = 0x00000000;
    if (!full) {
        /* Select address comparator #0 as a start address */
        /* Select address comparator #1 as a stop address */
        /* n.b. ETM numbers the comparators from 1. */
        tconfig.flags |= CS_ETMC_ADDR_COMP;
        tconfig.trace_enable_cr1 = 0x1;	//CS_ETMTECR1_EXCLUDE|CS_ETMTECR1_SSEN;
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
    tconfig.counter[0].enable_event = CS_ETMER_SAC(0);
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


    tconfig.flags |= CS_ETMC_CONFIG | CS_ETMC_TRIGGER_EVENT;
    tconfig.cr.raw.c.timestamp_enabled = 0;
    tconfig.cr.raw.c.cycle_accurate = 0;
    /*tconfig.cr.raw.c.branch_output = 1; */
    /* set up a trigger event so we can see an event in the trace */
    tconfig.trigger_event = CS_ETMER_EXTIN(1);

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
/* TBD */
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

    /* clear any active channels on the CTIs */
    cs_cti_clear_channels(0);
    cs_etb_clear_flush_stop();

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
        /* configure each CPU CTI to trigger EXTIN0, EXTIN1 to PTM */
        if (do_config_cpu_cti_ptm_extin(i) < 0) {
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

    printf("CSDEMO: CTI settings....\n");
    cs_cti_diag();

    printf("CSDEMO: Enabling trace...\n");
    if (etb_flush_on_trig)
        cs_etb_flush_and_stop_trig(0);

#if 0
    unsigned int regdata;
    regdata = cs_device_read(devices.etb, CS_ETB_STATUS);
    printf("CSDEMO: ETB.STATUS = 0x%08X\n", regdata);
    regdata = cs_device_read(devices.etb, CS_ETB_FLFMT_STATUS);
    printf("CSDEMO: ETB.FFSR = 0x%08X\n", regdata);
    regdata = cs_device_read(devices.etb, CS_ETB_FLFMT_CTRL);
    printf("CSDEMO: ETB.FFCR = 0x%08X\n", regdata);
    //cs_device_write(devices.etb, CS_ETB_FLFMT_CTRL, 0x2203);
    regdata = cs_device_read(devices.etb, CS_ETB_FLFMT_CTRL);
    printf("CSDEMO: ETB.FFCR = 0x%08X\n", regdata);
    cs_device_write(devices.etb, CS_ETB_CTRL, 0x1);
    regdata = cs_device_read(devices.etb, CS_ETB_STATUS);
    printf("CSDEMO: ETB.STATUS = 0x%08X\n", regdata);
    cs_device_write(devices.etb, CS_ETB_CTRL, 0x0);
    regdata = cs_device_read(devices.etb, CS_ETB_STATUS);
    printf("CSDEMO: ETB.STATUS = 0x%08X\n", regdata);

    pause_demo();
#endif

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
    printf("-cycle-accurate\tEnable Cycle Accurate tracing\n");
    printf("-timestamps\tEnable trace timestamps\n");
    printf
        ("-filter\tShow restricted amount of trace - enables extraction of memory area for decode\n");
    printf("-fon-trig\tEnable flush on trigger.\n");
    printf
        ("-etb-words <words>\tIf fon-trig, sets post trigger words. Default 0\n");
    printf("-pause\tRun the demo with a pause after each step.\n");
    return EXIT_FAILURE;
}


int main(int argc, char **argv)
{
    /* Defaults */
    int stage = 2;
    cpu_to_trace = ALL_CPUS;	// no CPU affinity selected (yet), trace all CPUs
    itm = false;
    full = true;
    etb_flush_on_trig = 0;
    etb_post_trig_words = 0;
    verbose = false;
    trace_timestamps = false;
    trace_cycle_accurate = false;
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
                if (strncmp(opt, "c", 1) == 0) {
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
                } else if (strncmp(opt, "itm", 3) == 0) {
                    printf("Enabling ITM\n");
                    itm = true;
                } else if (strncmp(opt, "timestamps", 3) == 0) {
                    printf("Enabling trace timestamps\n");
                    trace_timestamps = true;
                } else if (strncmp(opt, "cycle-accurate", 3) == 0) {
                    printf("Enabling cycle accurate trace\n");
                    trace_cycle_accurate = true;
                } else if (strncmp(opt, "fon-trig", 8) == 0) {
                    printf("Enabling FlushOnTrigger\n");
                    etb_flush_on_trig = true;
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

    /* set the CTM channels numbers
     * TRACE_ENABLE_CHAN 0
     * TRIGGER_CHAN 1
     */
    etb_trig_chan = TRIGGER_CHAN;	/* channel for ETB TRIGIN */
    etm_trig_chan = TRIGGER_CHAN;	/* channel used for EXTIN[1], used as a trigger event on the cores */
    etm_trace_enable_chan = TRACE_ENABLE_CHAN;	/* channel used for EXTIN[0], used inverted as a TraceEnable event */

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
            cs_trace_stimulus(devices.itm, (i & 31), seed + i);
            usleep(100);
        }
    }

    await_user_stop();

    printf("CSDEMO: Disable trace...\n");
    /* set trigger event - something to look for in the trace stream */
    /* also triggers ETB stop if in use */
    cs_cti_set_channel(0, TRIGGER_CHAN);

    /* first halt trace on cores using CTM, first core, channel 0 */
    if (cs_cti_set_channel(0, TRACE_ENABLE_CHAN) < 0)
        printf("CSDEMO: Failed to halt core trace using CTM\n");


    if (etb_flush_on_trig) {
        unsigned int regval;

        /* wait for collection to stop */
        if (verbose) {
            printf("CSDEMO: wait for ETB collection to stop...\n");
            regval = cs_device_read(devices.etb, CS_ETB_FLFMT_CTRL);
            printf("CSDEMO: ETB FFCR=0x%08X\n", regval);
        }

        if (cs_device_wait
            (devices.etb, CS_ETB_FLFMT_STATUS,
             CS_ETB_FLFMT_STATUS_FtStopped, CS_REG_WAITBITS_ALL_1, 0,
             &regval) == 0) {
            if (verbose)
                printf("CSDEMO: ETB collection stopped\n");
        } else {
            if (verbose)
                printf("CSDEMO: ETB FFSR=0x%08X\n", regval);
            printf
                ("CSDEMO: Warning ETB collection not stopped on flush on trigger\n");
        }
    }

    pause_demo();

    /* now shut down all the sources */
    for (i = 0; i < board->n_cpu; ++i) {
        cs_trace_disable(devices.ptm[i]);
    }
    if (itm) {
        cs_trace_disable(devices.itm);	/* do we need a Flush-but-not-disable operation for ITM? */
    }

    /*printf("Address of set channel routine: 0x%08lX\n",(unsigned long)cs_cti_set_channel); */


    /* finally shut down all the sinks */
    cs_sink_disable(devices.etb);
    if (devices.itm_etb != NULL) {
        cs_sink_disable(devices.itm_etb);
    }

    printf("CSDEMO: CTI settings....\n");
    cs_cti_diag();
    pause_demo();

    /* clean up the CTIs and ETB stop/flush settings */
    cs_cti_clear_channels(0);
    cs_etb_clear_flush_stop();


    printf("CSDEMO: trace buffer contents: %u bytes\n",
           cs_get_buffer_unread_bytes(devices.etb));

    pause_demo();

    for (i = 0; i < board->n_cpu; ++i) {
        show_etm_config(i);
    }
    pause_demo();

    do_fetch_trace(&devices, itm);
    /*do_fetch_trace(devices.etb, "core", "cstrace.bin");
      if (devices.itm_etb != NULL) {
      do_fetch_trace(devices.itm_etb, "ITM/STM", "cstraceitm.bin");
      } */

    pause_demo();

    printf("CSDEMO: shutdown...\n");
    cs_shutdown();
    return EXIT_SUCCESS;
}

/* end of tracedemo.c */
