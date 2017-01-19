/*
CoreSight trace-based application profiler. 

Copyright (C) ARM Ltd. 2016.  All rights reserved.

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
#include "csregisters.h"
#include "cs_utility.h"
#include "cs_demo_known_boards.h"
#include "tns.h"

#include <sys/types.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <pthread.h>
#include <execinfo.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>

#include <time.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#define USE_PERF_EVENT 1
#if USE_PERF_EVENT
#include <linux/perf_event.h>
#include <asm/unistd.h>
#endif

#define USE_PTRACE 1
#if USE_PTRACE
#include <elf.h>          /* For NT_PRSTATUS */
#include <sys/ptrace.h>
#endif


/*
Command-line options and other global parameters
*/
static int o_verbose = 0;        /* 1: basic messages, 2: progress messages */
static char const *o_cmdname;    /* command name we're invoked as - set from argv[0] */

static int o_monitor_cpu = -1;   /* default to -1: means "not specified" */

/*
User-selected trace options, covering all aspects of what and where we
want ETM to trace.
*/
typedef struct etm_trace_options {
  int cycle_accurate:1;      /* Cycle count on every waypoint */
  int branch_broadcast:1;    /* Branch target on every waypoint */
  int return_stack:1;        /* Enable use of the ETM return stack */
  int cxid:1;                /* Trace changes of CONTEXTIDR */
  int cxfilter:1;            /* Filter trace to only include traced thread */
  int ts_enabled:1;          /* Trace global timestamp */
  int strobe:1;              /* Pulse trace on and off to capture slices of execution */
  int trace_data:1;          /* Capture data access when available */
  int kernel:1;              /* Trace kernel code */
  int userspace:1;           /* Trace userspace code */
  unsigned int ts_cycles;    /* Cycle interval for timestamp packets */
  unsigned int n_pmu_events; /* ETMv4: number of PMU events to be traced */
  unsigned int pmu_events[4];/* ETMv4: PMU events to be traced (bus signal number) */
} etm_trace_options_t;


/*
Default options for ETM.
*/
static etm_trace_options_t o_cs = {
  .ts_cycles = 10000,
  .cycle_accurate = 1,
  .ts_enabled = 1,
  .cxid = 1,
  .cxfilter = 1,
  .userspace = 1
};

static int o_trace = 1;          /* use ETM trace */
static int o_trace_itm = 0;      /* generate ITM/STM packets to mark trace events */
static unsigned int o_cs_sleep = 200;    /* ms to sleep in between trace collections */
static int o_cs_formatted = 1;   /* Use trace formatting to embed IDs in trace */

static int o_pc_sample = 0;      /* use PC-sampling */
static int o_halt = 0;           /* use halted-debug probing (risky) */

/* Filtering options */
static int o_sos = 1;            /* include (standard) shared libraries */

static int o_disable_ASLR = 0;   /* disable process ASLR */
#if USE_PERF_EVENT
static int o_use_perf = 1;       /* use perf to collect mmap events */
#endif /* USE_PERF_EVENT */
#if USE_PTRACE
static int o_use_ptrace = 1;     /* use ptrace() to monitor program behavior */
#endif /* USE_PTRACE */
static int o_mmap_pages = 16;    /* size of buffer for perf records */
static int o_capture_memory = 1; /* capture remote memory from mmap events */

static char const *o_profile_fn = "cstrace.bin";
static FILE *o_profile_fd = NULL;


static const struct board *g_board;
static struct cs_devices_t g_devices;
static unsigned int g_etb_countdown;
static cs_pmu_t g_pmu_config;

static volatile sig_atomic_t terminating = 0;


/*
Describe a CPU that we're monitoring.
*/
struct target_cpu {
  int cpu;
  cs_device_t debug;
  cs_device_t pmu;
  cs_device_t etm;
  unsigned int highcycles;
};

/*
Describe the overall target of monitoring - a process (or in future several)
on a group of CPUs.
*/
typedef struct target_thread {
  pid_t tid;          /* OS thread identifier (as in 'kill' command) */
  int mem_fd;         /* File handle for /proc/<pid>/mem - TBD remove now we're using process_vm_readv */
  int release_fd;     /* File handle for thread release pipe */
} target_thread_t;

typedef struct target {
  /* Scope of the system we're monitoring - CPUs and their trace devices */
  cpu_set_t child_cpus;
  unsigned int n_target_cpus;
  struct target_cpu target_cpu[LIB_MAX_CPU_DEVICES];
  /* Scope of the software we're monitoring - process(es) and thread(s) */
  target_thread_t thread;
} target_t;


/*
Release a process that we started, by writing to its pipe.
*/
static int target_release(target_t *t)
{
  if (t->thread.release_fd != 0) {
    /* Release the child */
    if (write(t->thread.release_fd, "X", 1) <= 0) {
      perror("write-pipe");
      return -1;
    }
    close(t->thread.release_fd);
    t->thread.release_fd = 0;
  }
  return 0;
}


static ns_delta_t time_etb_read;
static ns_delta_t time_data_write;

static unsigned long total_trace_collected;
static unsigned int n_trace_buffers_collected;


/*
Command-line options are vaguely modelled after existing commands, e.g.
  perf stat
  taskset
  setarch
  strace
*/
static int usage(void)
{
  fprintf(stderr,
      "\n"
      " usage: %s [<options>] <command>\n"
      "\n"
      "    -c, --cpu-list <cpus>       specify CPUs to run program-under-test\n"
      "    -e, --event <event>         PMU event selector for sampling\n"
      "    -et, --event-trace <event>  PMU event selector for trace (ETMv4)\n"
      "    -h, --help                  print this help summary\n"
      "    -m, --monitor <cpu>         use specified CPU as monitor\n"
      "    -t, --tid <tid>             collect trace from existing thread id\n"
      "    -R, --addr-no-randomize     disable randomization of process address space\n"
      "    -n, --null                  don't generate trace file\n"
      "    -K, --[no-]kernel           include kernel trace (%c)\n"
      "        --[no-]libs             include userspace shared libraries (%c)\n"
      "    -o, --output <file>         trace output file\n"
      "        --append                append to the trace output file\n"
      "    -r, --repeat <n>            repeat command n times\n"
      "    -v, --verbose               be more verbose\n"
      "\n",
      o_cmdname,
      (o_cs.kernel ? 'y' : 'n'),
      (o_sos ? 'y' : 'n'));
  return 1;
}

static void show_backtrace(void)
{
  void *stack[64];
  int depth = backtrace(stack, sizeof stack / sizeof stack[0]);
  if (depth > 0) {
    fprintf(stderr, "backtrace depth %u\n", depth);
    backtrace_symbols_fd(stack, depth, fileno(stderr));
  }
}

static void handle_sigsegv(int sig)
{
  signal(SIGSEGV, SIG_DFL);
  signal(SIGABRT, SIG_DFL);
  fprintf(stderr, "Signal %u\n", sig);
  show_backtrace();
  abort();
}


#if USE_PERF_EVENT
static long
perf_event_open(struct perf_event_attr *pea,
                pid_t pid, int cpu, int gfd, unsigned long flags)
{
  return syscall(__NR_perf_event_open, pea, pid, cpu, gfd, flags);
}
#endif


static unsigned long kernel_virtual_address(void)
{
  static unsigned long addr = 0;
  if (!addr) {
    FILE *fd = fopen("/proc/kallsyms", "r");
    if (fd) {
      /* Pick the address of whichever kernel symbol happens to be first,
         and round down to a page boundary */
      if (fscanf(fd, "%lx", &addr) == 1) {
        addr &= ~0xfff;   /* assume 4K pages */
      }
      fclose(fd);
    }
  }
  return addr;
}



/*
Set up one ETM according to the user-selected trace options.
*/
static int etmv4_configure_trace(cs_device_t, etm_trace_options_t const *);
static int etm_configure_trace(cs_device_t dev, etm_trace_options_t const *cfg)
{
  int debug = (o_verbose >= 2);
  cs_etm_config_t config;

  if (CS_ETMVERSION_IS_ETMV4(cs_etm_get_version(dev))) {
    /* ETMv4 has a different config structure, so the whole
       configuration routine needs to be duplicated. */
    return etmv4_configure_trace(dev, cfg);
  }
  /* Get the starting configuration */
  if (debug) {
    fprintf(stderr, "ETM: get initial config\n");
  }
  cs_etm_config_init(&config);
  config.flags = CS_ETMC_CONFIG;
  cs_etm_config_get(dev, &config);

  if (debug) {
    fprintf(stderr, "ETM: got config:\n");
    cs_etm_config_print(&config);
  }
  config.cr.raw.c.cycle_accurate = cfg->cycle_accurate;
  config.cr.raw.c.branch_output = cfg->branch_broadcast;
  config.cr.raw.c.ret_stack = cfg->return_stack;
  config.cr.raw.c.cxid_size = cfg->cxid ? 3 : 0;
  config.cr.raw.c.timestamp_enabled = cfg->ts_enabled;
  /* Cause the timestamp to be output... we want some control over this
     to make sure we get regular timestamps but not so frequent that
     they overwhelm the trace.  [PFT] says "Typically, you program
     the Timestamp Event Register to cause the PTM to insert a
     timestamp in the trace stream periodically.  You can do this by
     programming one of the PTM counters to decrement every cycle,
     and programming the ETMTSEVR so that the timestamp event occurs
     each time the counter reaches zero. */
  if (cfg->ts_cycles == 0) {
    config.timestamp_event = CS_ETME_NEVER;
  } else {
    /* Generate timestamp every N cycles */
    config.timestamp_event = CS_ETME_WHEN(CS_ETMER_CZERO(0));
    config.counter[0].value = cfg->ts_cycles;
    config.counter[0].reload_event = CS_ETME_WHEN(CS_ETMER_CZERO(0));
    config.counter[0].reload_value = cfg->ts_cycles;
    config.counter[0].enable_event = CS_ETME_WHEN(CS_ETMER_ALWAYS);
    config.counter_mask = 0x01;   /* set counter 0 */
    config.flags |= CS_ETMC_COUNTER;
  }
  config.flags |= CS_ETMC_TS_EVENT;
  config.flags |= CS_ETMC_TRACE_ENABLE;
  config.trace_enable_event = CS_ETME_WHEN(CS_ETMER_ALWAYS);
  config.trace_enable_cr1 = CS_ETMTECR1_EXCLUDE;
  config.trace_enable_cr2 = 0x00000000;
  if (cfg->strobe) {
    /* Experiment with enabling trace intermittently. */
    /* We have two counters running.  Counter 0 is the
       'long' counter and determines the sampling interval -
       this is supposed to be decremented when the program
       under test is running, but we might have to decrement
       it continuously if we can't hook it up to a suitable
       ETM resource.
       The reload value of the sampling interval is limited
       by the capacity of an ETM counter - currently 16 bits.
       Counter 1 is the 'short' counter and determines the
       sample duration.  The sample starts when counter 1
       reaches zero, so its programming value is the number
       of cycles to delay before counting.  In this mode,
       we'll get timestamps when we start sampling, so we
       don't need the periodic timestamping.  This allows
       us to work on ETMs with only two counters. */
    config.trace_enable_event = CS_ETME_WHEN(CS_ETMER_CZERO(1));
    config.counter[0].value = 0;
    config.counter[1].value = 0;
    config.counter[0].reload_value = 50000;   /* long count */
    config.counter[1].reload_value = config.counter[0].reload_value - 50;
    config.counter[0].enable_event = CS_ETME_WHEN(CS_ETMER_ALWAYS);
    config.counter[1].enable_event = CS_ETME_WHEN(CS_ETMER_ALWAYS);
    config.counter[0].reload_event = CS_ETME_AND(CS_ETMER_CZERO(0), CS_ETMER_CZERO(1));
    config.counter[1].reload_event = CS_ETME_AND(CS_ETMER_CZERO(0), CS_ETMER_CZERO(1));
    config.counter_mask |= 0x03;   /* set counters 0 and 1 */
    config.timestamp_event = CS_ETME_NEVER;
    config.flags |= CS_ETMC_COUNTER;
  }

  /* Configure data trace, if available */
  if (cfg->trace_data) {
    /* For some ETMs (e.g. PFT, ETMv4 A-profile) this won't be possible. */
    /* TBD: the following test is broken for ETMv4 R-profile.  We should test
       explicitly whether data trace is supported. */
    if (CS_ETMVERSION_IS_ETMV3(cs_etm_get_version(dev))) {
      config.vdata_event = CS_ETME_WHEN(CS_ETMER_ALWAYS);
      config.vdata_ctl3 |= 0x00010000;  /* Exclude */
      config.cr.raw.c.data_access = 3;  /* TBD: document */
    } else {
      fprintf(stderr, "%s: data trace not available\n", o_cmdname);
    }
  } else {
    config.cr.raw.c.data_access = 0;
  }

  /* Set up address range filtering.  We should arrange to trace 
        userspace inc. libs
        userspace exc. libs
        userspace inc. libs + kernel
        userspace exc. libs + kernel
     Also we might filter on contextid, but this is set up later.
  */
  config.addr_comp_mask = 0;
  if (!cfg->kernel || !cfg->userspace) {
    /* Exclude kernel or userspace from the trace.  This could mean one of two things:
         - exclude trace in the relevant address range (whatever that is)
         - exclude trace in the wrong state
       Currently we interpret it as the latter.
    */
    /* Use address comparator to filter instruction address type */
    /* Set the flag telling CSAL to program the address comparator(s). */
    config.flags |= CS_ETMC_ADDR_COMP;
    /* Program the first address comparator pair. */
    config.addr_comp_mask |= 0x03;
    config.addr_comp[0].access_type = 0x00003c01;  /* User only */
    config.addr_comp[0].access_type = 0x00003001;  /* Kernel only */
    config.addr_comp[0].address = 0x00000000;
    config.addr_comp[1].access_type = config.addr_comp[0].access_type;
    config.addr_comp[1].address = 0xffffffff;
    /* Select address range comparator 1 (i.e. [0]) for exclude */
    config.trace_enable_cr1 |= 1;
  }
  if (!o_sos) {
    /* Exclude dynamic libraries - by the crude expedient of
       excluding code between 0x40000000 and the kernel base address. */
    config.flags |= CS_ETMC_ADDR_COMP;
    config.addr_comp_mask |= 0x0c;
    config.addr_comp[2].access_type = 0x00003c01;  /* User only */
    config.addr_comp[2].address = 0x40000000;   /* high enough to only be libs? */
    config.addr_comp[3].access_type = config.addr_comp[2].access_type;
    config.addr_comp[3].address = kernel_virtual_address();
    config.trace_enable_cr1 |= 2;
  }

  /* Finally, write back the updated trace configuration. */
  if (debug) {
    fprintf(stderr, "ETM: config about to be written back:\n");
    cs_etm_config_print(&config);
    fprintf(stderr, "ETM: writing back config...\n");
  }
  cs_etm_config_put(dev, &config);

  if (o_verbose) {
    printf("----\n");
    printf("Programmed trace source #%u:\n", cs_get_trace_source_id(dev));
    printf("  ETMCR     = %08x\n", cs_device_read(dev, CS_ETMCR));
    printf("  ETMTECR1  = %08x\n", cs_device_read(dev, CS_ETMTECR1));
    printf("  ETMTECR2  = %08x\n", cs_device_read(dev, CS_ETMTECR2));
    printf("  ETMTACxR0 = %08x %08x\n", cs_device_read(dev, CS_ETMACVR(0)), cs_device_read(dev, CS_ETMACTR(0)));
    printf("  ETMTACxR1 = %08x %08x\n", cs_device_read(dev, CS_ETMACVR(1)), cs_device_read(dev, CS_ETMACTR(1)));
    printf("  ETMTSEVR  = %08x\n", cs_device_read(dev, CS_ETMTSEVR));
    /* Get and display a fresh copy of the current ETM configuration */
    memset(&config, 0, sizeof config);
    config.flags = CS_ETMC_ALL;
    config.counter_mask = 0xf;
    config.addr_comp_mask = 0xf;
    cs_etm_config_get(dev, &config);
    cs_etm_config_print(&config);
    printf("----\n");
  }
  /* We could adjust the synchronization frequency, to ensure that
     A-sync, I-sync and T-sync packets are output often enough to
     recover sufficient trace from the buffer. */
  if (0) {
    uint32_t freq = cs_device_read(dev, CS_ETMSYNCFR);
    printf("Sync frequency: %u\n", freq);
    cs_device_write(dev, CS_ETMSYNCFR, freq);
  }
  if (debug) {
    memset(&config, 0, sizeof config);
    config.flags = CS_ETMC_ALL;
    cs_etm_config_get_ex(dev, &config);
    cs_etm_config_print_ex(dev, &config);
  }
  return 0;   /* 0 indicates success */
}


static int etmv4_configure_trace(cs_device_t dev, etm_trace_options_t const *cfg)
{
  int debug = (o_verbose >= 2);
  cs_etmv4_config_t config;
  
  cs_etm_config_init_ex(dev, &config);
  config.flags = CS_ETMC_TRACE_ENABLE | CS_ETMC_CONFIG | CS_ETMC_EVENTSELECT | CS_ETMC_RES_SEL;
  cs_etm_config_get_ex(dev, &config);
  if (debug) {
    fprintf(stderr, "ETMv4: got config:\n");
    cs_etm_config_print_ex(dev, &config);
  }

  /* Set up the trace configuration.  Selecting cycle-accurate mode is done via
     a separate API call. */
  config.victlr = 0x201;   /* ViewInst - trace all */
  if (!cfg->kernel) {
    /* mask out everything except NS EL0 (n.b. NS EL3 and S EL2 are n.imp.) */
    config.victlr |= 0x006b0000;
  }
  if (!cfg->userspace) {
    /* mask out NS EL0 */
    config.victlr |= 0x00100000;
  }
  config.syncpr = 0xC;     /* Sync every 4K bytes */
  config.configr.bits.cid = cfg->cxid;
  config.configr.bits.bb = cfg->branch_broadcast;
  /* MODE=0,RANGE=0 excludes no ranges - i.e. enables BB for the entire map. */
  config.bbctlr = (cfg->branch_broadcast ? 0x000 : 0x100);
  config.configr.bits.rs = cfg->return_stack;
  config.configr.bits.ts = cfg->ts_enabled;
  /* TBD: timestamp rate */
 
  /* Trace selected PMU events */
  {
    unsigned int i;
    config.eventctlr0r = 0;
    config.eventctlr1r = 0;
    config.extinselr = 0;
    assert(cfg->n_pmu_events <= 4);
    for (i = 0; i < cfg->n_pmu_events; ++i) {
      config.extinselr |= (cfg->pmu_events[i] << (8*i));   /* ext[i] := selected PMU event */
      config.rsctlr[i+2] = i;                  /* resource[i+2] = ext[i] */
      config.rsctlr_acc_mask |= (1U << (i+2));
      config.eventctlr0r |= ((i+2) << (8*i));  /* event[i] := resource[i+2] */
      config.eventctlr1r |= (1U << i);     /* generate event in inst stream */
    }
  }
  /* data trace not available on A-profile */

  if (debug) {
    fprintf(stderr, "ETMv4: config about to be written back:\n");
    cs_etm_config_print_ex(dev, &config);
    fprintf(stderr, "ETMv4: writing back config...\n");
  }
  cs_etm_config_put_ex(dev, &config);
  cs_trace_enable_cycle_accurate(dev, cfg->cycle_accurate);

  if (o_verbose) {
    printf("Programmed trace source #%u:\n", cs_get_trace_source_id(dev));
  }
  
  return 0;
}


/*
Set up a trace source to only allow trace from a given thread id.
This relies on the kernel having been configured with
CONFIG_PID_IN_CONTEXIDR=y.
Unfortunately, it looks like current behavior is to put the
(lightweight) TID in there, rather than the (old school) PID,
which corresponds to the address space.
A fully general solution would
  (a) allow tracing to be restricted to a group of processes/asids
  (b) use the context id register to distinguish address spaces
      within that group, to allow for decode.
That suggests a CONTEXIDR scheme along the lines of
  <group-id>:<id-within-group>
where the id-within-group uniquely identifies an asid within a group,
and the group-id is used for ETM masking.  But that would need a 
change to the kernel.

Once we have a suitable value and mask, we need to enable the filter.

It's tempting to create a CSAL builtin to filter on the CXID, but this
would require CSAL to manage usage of the trace-enable selectors in
a way that it currently doesn't.
*/
static int etm_configure_trace_cxid_filter(cs_device_t dev, unsigned int tid)
{
  int rc;
  unsigned int basev;
  cs_etm_config_t config;

  if (CS_ETMVERSION_IS_ETMV4(cs_etm_get_version(dev))) {
    /* TBD: this needs to be done for ETMv4. */
    return 0;
  }
  config.flags = CS_ETMC_CXID_COMP|CS_ETMC_TRACE_ENABLE|CS_ETMC_COUNTER;
  config.cxid_comp_mask = 0x01;   /* Just the first CXID comparator */
  config.counter_mask = 0x03;
  cs_etm_config_get(dev, &config);
  config.cxid_comp[0].cxid = tid << 8;      /* thread id is in bits 31..8 */
  config.cxid_mask = 0x000000ff;            /* ignore the ASID in low byte */
  /* Adjust our previous filter setup. */
  basev = config.trace_enable_event & 0x7f; /* get the previous event 'A' */
  if (config.trace_enable_event != CS_ETME_AND(basev, CS_ETMER_CXID(0))) {
    assert((config.trace_enable_event & 0x0001c000) == 0);  /* must be single event now */
    config.trace_enable_event = CS_ETME_AND(basev, CS_ETMER_CXID(0));
  }
  config.counter[0].enable_event = CS_ETME_WHEN(CS_ETMER_CXID(0));
  config.counter[1].enable_event = CS_ETME_WHEN(CS_ETMER_CXID(0));
  rc = cs_etm_config_put(dev, &config);
  if (o_verbose) {
    printf("Trace source configured to filter for TID=%u:\n", tid);
    cs_etm_config_print(&config);
  }
  return rc;
}


/*
Configure the cross-trigger.
*/
static int etm_configure_cross_trigger(void)
{
  cs_channel_t chan;
  /* Discard all channels - this is quite global, and takes no account of
     any other internal/external client who might be using cross-trigger
     for other purposes. */
  cs_ect_reset();
  chan = cs_ect_get_channel();
  cs_ect_add_trigsrc(chan, cs_trigsrc(g_devices.etb, CS_TRIGOUT_ETB_FULL));
  cs_ect_add_trigdst(chan, cs_trigdst(g_devices.etb, CS_TRIGIN_ETB_TRIGIN));
  if (o_verbose >= 2) {
    cs_ect_diag(chan);
  }
  cs_ect_configure(chan);
  if (o_verbose >= 2) {  
    cs_cti_diag();
  }
  g_etb_countdown = cs_get_buffer_size_bytes(g_devices.etb) / 2;
  cs_device_set(g_devices.etb, CS_ETB_FLFMT_CTRL, CS_ETB_FLFMT_CTRL_StopTrig);
  return 0;
}

/*
A buffer big enough to hold captured trace.
*/
typedef struct tbuf {
  struct tbuf *next;       /* Next trace buffer */
  /* Static information */
  cs_device_t dev;         /* CoreSight ETB device */
  unsigned int ram_size;   /* Trace buffer capacity (bytes) */
  unsigned char *buffer;   /* Our buffer for retrieving the data */
  /* Per-capture information */
  unsigned int len;        /* Length of data actually in the buffer (bytes) */
  ns_epoch_t time_capture_start; /* Time when the capture was started */
  ns_epoch_t time_read_start;    /* Time: start to read from the ETB */
  ns_epoch_t time_read_end;      /* Time: finish reading the ETB */
} tbuf_t;


/*
Allocate a RAM buffer sufficient to contain the trace that we're
going to collect from the CoreSight buffer.
*/
static tbuf_t *tbuf_alloc(cs_device_t dev)
{
  tbuf_t *b = (tbuf_t *)malloc(sizeof(tbuf_t));       /* CoreSight trace buffer collection object */
  b->next = NULL;
  b->dev = dev;
  b->ram_size = cs_get_buffer_size_bytes(dev);
  b->buffer = (unsigned char *)malloc(b->ram_size);   /* for ETB buffer retrieval */
  b->len = 0;
  return b;
}


/*
Collect an ETB buffer's worth of trace into a RAM trace buffer.
*/
static int tbuf_collect(tbuf_t *b)
{
  int rc;
  ns_delta_t tget;

  assert(b->len == 0);
  //cs_sink_disable(b->dev);
  b->time_read_start = tns_now();
  b->len = cs_get_buffer_unread_bytes(b->dev);
  assert(b->len <= b->ram_size);
  if (o_cs_formatted) {
    assert((b->len % 16) == 0);
  }
  rc = cs_get_trace_data(b->dev, b->buffer, b->len);
  if (rc < 0) {
    fprintf(stderr, "** failed to retrieve trace\n");
    return rc;
  }
  b->time_read_end = tns_now();
  tget = (b->time_read_end - b->time_read_start);
  time_etb_read += tget;
  if (b->len == 32 && !memcmp(b->buffer, "\01\0\0\0\0\0\0\0" "\0\0\0\0\0\0\0\0" "\0\0\0\0\0\0\0\0" "\0\0\0\0\0\0\0\0", 32)) {
    /* No data (immediately selects stream id 0x00) */
    if (o_verbose >= 2) {
      fprintf(stderr, "ETB empty\n");
    }
    /* Make the buffer reusable */
    b->len = 0;
    /* Return an error so that the caller knows we can reuse this buffer */
    return -1;
  }
  if (o_verbose >= 2 || (b->len <= 64)) {
    int i;
    fprintf(stderr, "ETB collected %d bytes (%.02fs):",
        b->len, (float)tget / 10e9);
    for (i = 0; i < 32; ++i) {
      if (i >= b->len) break;
      fprintf(stderr, " %02X", b->buffer[i]);
    }
    fprintf(stderr, "\n");
  }
  total_trace_collected += b->len;
  ++n_trace_buffers_collected;
  assert(cs_get_buffer_unread_bytes(b->dev) == 0);
  return 0;
}


static void write2(unsigned short x)
{
  fwrite(&x, sizeof x, 1, o_profile_fd);
}

static void write4(unsigned int x)
{
  fwrite(&x, sizeof x, 1, o_profile_fd);
}

static void write8(unsigned long long x)
{
  fwrite(&x, sizeof x, 1, o_profile_fd);
}


enum {
  TREC_CSTRACE = 1,
  TREC_CSMETA = 2,
  TREC_MMAP = 3,
  TREC_FILE = 4,
  TREC_MEM = 5,
  TREC_MAX
};

/*
Write out an accumulated trace buffer.
*/
static int tbuf_write(tbuf_t const *b)
{
  unsigned short hdr_len;
  unsigned int total_len;

  assert(o_profile_fd != NULL);
  /* Measure how long it takes us to do this... just so we can track
     the overhead of writing out the trace. */
  ns_epoch_t write_start = tns_now();
  /* Now marshal the buffer details.  The format here allows us to add more
     metadata to each packet (e.g. timestamps) in future */
  hdr_len = 4 + 2 + 2 + 8 + 4;
  total_len = hdr_len + b->len;
  write4(total_len);
  write2(TREC_CSTRACE);    /* packet type, indicates CoreSight trace */
  write2(hdr_len);
  write8(b->time_read_end);
  write4(b->len);
  fwrite(b->buffer, b->len, 1, o_profile_fd);
  ns_epoch_t write_end = tns_now();
  time_data_write += (write_end - write_start);
  return 0;
}


/**
 *  Write the trace source metadata into the captured trace file.
 *  The metadata describes the configuration of all the trace sources,
 *  sufficient to decode to packet boundary level.
 *  A record is generated for each trace source.
 */
static int write_metadata(cpu_set_t const *child_cpus)
{
  int i;
  assert(o_profile_fd);
  ns_epoch_t const now = tns_now();
  for (i = 0; i < LIB_MAX_CPU_DEVICES; ++i) {
    if (CPU_ISSET(i, child_cpus)) {
      char buf[8192];
      char name[16];
      int n;
      cs_device_t d = g_devices.ptm[i];
      n = cs_get_trace_metadata(CS_METADATA_INI, d, cs_get_trace_source_id(d), buf, sizeof buf, name, 16);
      if (n < 0) {
        continue;
      }
      {
        unsigned int const hdr_len = 4 + 2 + 2 + 8 + 4;
        unsigned int const total_len = hdr_len + n;
        write4(total_len);
        write2(TREC_CSMETA);
        write2(hdr_len);
        write8(now);
        write4(n);
        fwrite(buf, n, 1, o_profile_fd);
      }
    }
  }
  return 0;
}


/*
Create a trace stream record indicating a memory mapping has been added.
The name is an ELF file.
*/
static int write_memory_mapping(ns_epoch_t map_time, unsigned long addr, unsigned long size, unsigned long offset, char const *name)
{
  unsigned int total_len, hdr_len, metadata_len;
  unsigned int namelen;

  assert(name != NULL);
  assert(o_profile_fd);
  namelen = strlen(name);
  metadata_len = 8 + 4 + 4 + namelen + 1;
  hdr_len = 4 + 2 + 2 + 8 + 4;
  total_len = hdr_len + metadata_len;
  write4(total_len);
  write2(TREC_MMAP);
  write2(hdr_len);
  write8(map_time);
  write4(metadata_len);
  write8(addr);
  write4(size);
  write4(offset);
  fwrite(name, namelen + 1, 1, o_profile_fd);
  return 0;
}


/*
Create a trace stream record for a raw binary blob representing memory at a given address.
The name is a file containing raw data.
*/
static int write_memory_dump(unsigned long addr, unsigned long size, char const *name)
{
  unsigned int total_len, hdr_len, metadata_len, namelen;

  assert(name != NULL);
  assert(o_profile_fd);
  namelen = strlen(name);
  metadata_len = 8 + 4 + namelen + 1;
  hdr_len = 4 + 2 + 2 + 8 + 4;
  total_len = hdr_len + metadata_len;
  write4(total_len);
  write2(TREC_FILE);
  write2(hdr_len);
  write8(tns_now());
  write4(metadata_len);
  write8(addr);
  write4(size);
  fwrite(name, namelen + 1, 1, o_profile_fd);
  return 0;
}


/*
Create a trace stream record for raw memory data.
*/
static int write_memory_data(unsigned long addr, unsigned long size, void const *data)
{
  unsigned int total_len, hdr_len, metadata_len;

  assert(data != NULL);
  assert(size > 0);
  metadata_len = 8 + size;
  hdr_len = 4 + 2 + 2 + 8 + 4;
  total_len = hdr_len + metadata_len;
  write4(total_len);
  write2(TREC_MEM);
  write2(hdr_len);
  write8(tns_now());
  write4(metadata_len);
  write8(addr);
  fwrite(data, size, 1, o_profile_fd);
  return 0;
}


static void tbuf_free(tbuf_t *b)
{
  if (b) {
    free(b->buffer);
    free(b);
  }
}


/*
Input:
  monitor_cpu: either a specified monitor CPU, or -1 for unspecified
  child_cpu: either a set of target CPUs, or empty set for unspecified
Constraints:
  monitor_cpu, if specified, must not be in child_cpu
  child_cpu must not comprise all the CPUs - it must leave one free for monitor
Output:
  monitor_cpu: the monitor CPU, to which we are now pinned
  child_cpu: the set of child CPUs, which does not include monitor_cpu
TBD:
  consider whether monitor_cpu should also be a set of CPUs, as this
  may be more efficient when the monitor process is multi-threaded.
*/
static int set_affinity(int *monitor_cpu, cpu_set_t *child_cpus)
{
  int rc, i;
  cpu_set_t parent_cpus;
  int child_specified;
  unsigned int N = sysconf(_SC_NPROCESSORS_CONF);   /* Maximum possible CPU */

  if (*monitor_cpu != -1 && CPU_ISSET(*monitor_cpu, child_cpus)) {
    fprintf(stderr, "CPU #%u requested as monitor but also in target set\n",
        *monitor_cpu);
    return -1;
  } 
  /* Get the set of CPUs that we and our subprocesses can run on */
  rc = sched_getaffinity(/*calling process*/0, sizeof parent_cpus, &parent_cpus);
  if (rc < 0) {
    perror("sched_getaffinity");
    return rc;
  }
  if (*monitor_cpu == -1) {
    /* pick one CPU to be the monitor */
    for (i = 0; i < N; ++i) {
      if (CPU_ISSET(i, &parent_cpus) && !CPU_ISSET(i, child_cpus)) {
        *monitor_cpu = i;
        fprintf(stderr, "csprofile: CPU #%u chosen as monitor\n", i);
        break;
      }
    }
    if (*monitor_cpu == -1) {
      fprintf(stderr, "no CPU free for monitor\n");
      return -1;
    }
  }
  /* If no child CPUs are specified, form a child set out of the parent set
     minus the monitor */
  child_specified = 0;
  for (i = 0; i < N; ++i) {
    if (CPU_ISSET(i, child_cpus)) {
      child_specified = 1;
      break;
    }
  }
  if (!child_specified) {
    for (i = 0; i < N; ++i) {
      if (CPU_ISSET(i, &parent_cpus) && i != *monitor_cpu) {
        CPU_SET(i, child_cpus);
        child_specified = 1;
      }
    }
    if (!child_specified) {
      fprintf(stderr, "no CPU(s) free for program under test\n");
      return -1;
    } 
  }
  /* At this point, monitor CPU and child CPUs are fully specified */
  CPU_ZERO(&parent_cpus);
  CPU_SET(*monitor_cpu, &parent_cpus);   /* singleton */
  rc = sched_setaffinity(/*calling process*/0, sizeof parent_cpus, &parent_cpus);
  return rc;
}


/*
Convert a human-readable string list of CPUs, into a cpu_set_t - like taskset
*/
int get_cpu_set(char const *s, cpu_set_t *cpus)
{
  int cpu = -1;
  int from = -1;
  while (1) {
    if (*s == ',' || *s == '\0') {
      if (cpu == -1) {
        return 0;
      }
      if (from == -1) {
        CPU_SET(cpu, cpus);
      } else if (from <= cpu) {
        int i;
        for (i = from; i <= cpu; ++i) {
          CPU_SET(i, cpus);
        }
      }
      if (!*s) break;
      cpu = -1;
      from = -1;
    } else if ('0' <= *s && *s <= '9') {
      if (cpu == -1) cpu = 0;
      cpu = (cpu * 10) + (*s - '0');
    } else if (*s == '-') {
      if (cpu == -1 || from != -1) return 0;
      from = cpu;
      cpu = -1;
    }
    ++s;
  }
  return 1;  /* success */
}


#if USE_PERF_EVENT
/*
Manage a perf recording session to get memory map events so we can resolve
sampled or traced program counters (PCs) back to objects and sources.
This routine just handles the interface to perf, it doesn't manage the mapping.

  mapper_create()
    -> mapper_open()
       -> mapper_get()
    -> mapper_close()
  -> mapper_free()
*/
struct mapping {
  struct mapping *next;
  uint64_t time;
  uint64_t addr;
  uint64_t size;
  uint64_t pgoff;
  char filename[];
};

struct mapper {
  /* Configuration */
  target_t *target;
  size_t data_size;
  uint32_t sample_type;
  /* Status */
  int perf_fd;                        /* perf_event_open handle for mmap events */
  size_t map_size;                    /* Size of the whole map */
  struct perf_event_mmap_page *meta;  /* Metadata at start of perf area */
  unsigned char *perf_data;           /* Start of data area (ring buffer) */
  uint64_t data_tail;                 /* Where we've read up to (offset) */
  /* List of mappings that we've collected */
  struct mapping *event_head;
  struct mapping **event_tail;
};


struct mapper *mapper_create(void)
{
  struct mapper *m = (struct mapper *)malloc(sizeof(struct mapper));
  m->data_size = o_mmap_pages*4096;    /* set from --mmap-pages like perf record */
  m->sample_type = PERF_SAMPLE_TIME;
  m->meta = NULL;
  m->perf_fd = -1;
  return m;
}


int mapper_open(struct mapper *m, target_t *target)
{
  void *pmap;
  struct perf_event_attr pea;
  pid_t pid = target->thread.tid;

  m->target = target;
  memset(&pea, 0, sizeof pea);
  pea.type = PERF_TYPE_SOFTWARE;
  pea.size = sizeof pea;
  pea.config = PERF_COUNT_SW_DUMMY;
  pea.sample_type = m->sample_type;
  pea.mmap = 1;            /* collect PROT_EXEC mappings */
  if (1) {
    /* we don't need these events - but if we do collect them, we must
       make sure not to report them as code mappings. */
    pea.mmap2 = 1;
    pea.mmap_data = 1;
  }
  pea.sample_id_all = 1;   /* get timestamp etc. in the mmap events */
  m->perf_fd = perf_event_open(&pea, pid, /*cpu=*/-1, /*group_fd=*/-1, /*flags=*/0);
  if (m->perf_fd < 0) {
    perror("perf");
    return 0;
  } else {
    /* "The mmap size should be 1 + 2^n pages" where n is up to you... */
    m->map_size = sysconf(_SC_PAGESIZE) + m->data_size;
    /* The perf buffer is specific to this perf session but we must
       map it MAP_SHARED otherwise we get EINVAL... */
    pmap = mmap(NULL, m->map_size, PROT_READ, MAP_SHARED, m->perf_fd, 0);
    if (pmap == MAP_FAILED) {
      perror("mmap for perf");
      return 0;
    }
    m->meta = (struct perf_event_mmap_page *)pmap;
    if (o_verbose) {
      fprintf(stderr, "Allocated perf buffer at %p, version=%u\n", pmap, m->meta->version);
    }
    m->perf_data = (unsigned char *)m->meta + (m->map_size - m->data_size);
    m->data_tail = 0;
  }
  m->event_head = NULL;
  m->event_tail = &m->event_head;
  return 1;
}


int mapper_close(struct mapper *m)
{
  if (m->meta != NULL) {
    munmap(m->meta, m->map_size);
    m->meta = NULL;
  }
  if (m->perf_fd >= 0) {
    close(m->perf_fd);
    m->perf_fd = -1;
  }
  return 0;
}


void mapper_free(struct mapper *m)
{
  mapper_close(m);
  free(m);
}


/*
Test if data is available to be collected.
Note that this is not necessarily the records we want -
e.g. we seem to get PERF_RECORD_EXIT whatever happens.
*/
int mapper_poll(struct mapper *m)
{
  return m->data_tail < m->meta->data_head;
}


/*
Create a memory-mapping record and add it to the set of collected mappings.
This indicates that a mapping was made to a file or a pseudo file, e.g. "[vdso]".
*/
struct mapping *
mapper_add(struct mapper *m, uint64_t time, uint64_t addr, uint64_t size, uint64_t offset, char const *name, size_t ssize)
{
  struct mapping *e = (struct mapping *)malloc(sizeof(struct mapping) + ssize);
  e->time = time;
  e->addr = addr;
  e->size = size;
  e->pgoff = offset;
  memcpy(e->filename, name, ssize);
  e->next = NULL;
  *(m->event_tail) = e;
  m->event_tail = &e->next;
  return e;
}


/*
Print a mapping record in the style of /proc/<pid>/maps.
*/
void
mapper_print_mapping(struct mapping const *e, FILE *fd)
{
  if (!fd) {
    fd = stdout;
  }
  fprintf(fd, "%08llx-%08llx --xp %08llx 00:00 %-10llu %s\n",
          (unsigned long long)e->addr, (unsigned long long)e->addr+e->size,
          (unsigned long long)e->pgoff,
          (unsigned long long)0,
          e->filename);
}


/*
Print a /proc/<pid>/maps style output from a sequence of mapping events.
Really we should sort the events into order, avoid overlaps etc.
But printing a static mapping from dynamic events is imperfect anyway...
all we're really aiming for here is a cumulative mapping representing
the state of the process after the dynamic loader has finished.
*/
void mapper_print_proc_maps(struct mapper const *m, char const *fn)
{
  struct mapping *e;
  FILE *fd = fopen(fn, "w");
  if (!fd) {
    perror(fn);
    return;
  }
  /* Note that e->time is not used */
  for (e = m->event_head; e != NULL; e = e->next) {
    mapper_print_mapping(e, fd);
  }
  fclose(fd);
}


/*
Write out a mapping record to the profile trace stream.
*/
void profile_write_mapping(struct mapping const *e)
{
  if (o_verbose) {
    mapper_print_mapping(e, NULL);
  }
  write_memory_mapping(e->time, e->addr, e->size, e->pgoff, e->filename);
}


/*
Get the next memory-mapping event record from the perf subsystem
and add it to the set of collected mappings.
Non-blocking.  Return NULL if no record available.
*/
struct mapping *
mapper_get(struct mapper *m)
{
  int verbose = o_verbose;
  if (!m->meta) {
    return NULL;
  }
  while (mapper_poll(m)) {
    struct perf_event_header const *eh;
    struct mapping *me = NULL;

    /* Extract the next perf record from the buffer. */
    if ((m->meta->data_head + sizeof(struct perf_event_header)) > m->data_size) {
      /* It's wrapped. TBD (only safe way is to use the write pointer?) */
      fprintf(stderr, "perf data has wrapped\n");
      return NULL;
    }
    eh = (struct perf_event_header const *)(m->perf_data + m->data_tail);
    {
      /* The event header is at 'eh'.  That is followed by a payload
         specific to the event type.  Finally there are optional 
         context fields (timestamp etc.) as determined by sample_type. */
      unsigned char const *se = (unsigned char const *)((char *)eh + eh->size);
      ns_epoch_t sample_time = 0;
      if (m->sample_type & PERF_SAMPLE_TIME) {
        /* Timestamp is from the kernel's local_clock() - same as CLOCK_MONOTONIC.
           Relative to boot time, unlike CLOCK_REALTIME which is relative to the Epoch. */
        se -= 8;
        sample_time = tns_from_perf(*((uint64_t const *)se));
        if (verbose) {
          printf("  TS=%016llx ", (unsigned long long)sample_time);
        }
      }
      if (verbose) {
        printf("%3u  %04x ", eh->type, eh->misc);
      }
      if (eh->type == PERF_RECORD_MMAP) {
        struct PEMM {
          struct perf_event_header header;
          uint32_t pid, tid;
          uint64_t addr;
          uint64_t len;
          uint64_t pgoff;
          /* Note: no protection information for PERF_RECORD_MMAP */
          char filename[];
        } const *e = (struct PEMM const *)eh;
        int could_be_executable = !(eh->misc & PERF_RECORD_MISC_MMAP_DATA);
        if (could_be_executable) {
          me = mapper_add(m, sample_time, e->addr, e->len, e->pgoff, e->filename, strlen(e->filename)+1);
        }
        if (verbose) {
          printf("    PERF_RECORD_MMAP: %u/%u [0x%llx(0x%llx) @ %llx]: %c %s\n",
              e->pid, e->tid,
              (unsigned long long)e->addr, (unsigned long long)e->len, (unsigned long long)e->pgoff,
              (could_be_executable ? 'x' : ' '),
              e->filename);
        }
      } else if (eh->type == PERF_RECORD_MMAP2) {
        /* like PERF_RECORD_MMAP but with inode data */
        struct PEMM2 {
          struct perf_event_header header;
          uint32_t pid, tid;
          uint64_t addr;        /* Start virtual address of mapping */
          uint64_t len;         /* Size of mapping */
          uint64_t pgoff;       /* Offset within file */
          uint32_t maj, min;    /* Major/minor inode */
          uint64_t ino, ino_generation;
          uint32_t prot, flags;
          char filename[];
        } const *e = (struct PEMM2 const *)eh;
        int could_be_executable = (e->prot & PROT_EXEC) != 0;
        if (!could_be_executable && !strcmp(e->filename, "[vdso]")) {
          /* For some reason, the perf event for mapping [vdso] and other pseudo files,
             doesn't have the prot flags set. */
          could_be_executable = 1;
        }
        if (could_be_executable) {
          me = mapper_add(m, sample_time, e->addr, e->len, e->pgoff, e->filename, strlen(e->filename)+1);
        }
        if (verbose) {
          /* Print in /proc/pid/maps format */
          printf("%08llx-%08llx %c%c%c%c %08llx %02x:%02x %-10llu %s\n",
            (unsigned long long)e->addr, (unsigned long long)e->addr+e->len,
            ((e->prot & PROT_READ) ? 'r' : '-'),
            ((e->prot & PROT_WRITE) ? 'w' : '-'),
            ((e->prot & PROT_EXEC) ? 'x' : '-'),
            ((e->flags & MAP_PRIVATE) ? 'p' : '-'),
            (unsigned long long)e->pgoff,
            e->maj, e->min,
            (unsigned long long)e->ino,
            e->filename);
        }
        if (verbose) {
          printf("    PERF_RECORD_MMAP2: %u/%u [0x%llx(0x%llx) @ %llx]: prot=%02x:flags=%02x %-9lu %c %s\n",
              e->pid, e->tid,
              (unsigned long long)e->addr, (unsigned long long)e->len, (unsigned long long)e->pgoff,
              e->prot, e->flags,
              (unsigned long)e->ino,
              ((eh->misc & PERF_RECORD_MISC_MMAP_DATA) ? ' ' : 'x'),
              e->filename);
        }
      } else if (eh->type == PERF_RECORD_EXIT) {
        struct PEEX {
          struct perf_event_header header;
          uint32_t pid, ppid;
          uint32_t tid, ptid;
          uint64_t time;
        } const *e = (struct PEEX const *)eh;
        if (verbose) {
          printf("    exit %u/%u %u/%u\n", e->pid, e->ppid, e->tid, e->ptid);
        }
      } else {
        if (verbose) {
          printf("    event: %u\n", eh->type);
        }
      }
    }
    m->data_tail += eh->size;
    /* We could now write m->data_tail back to perf_meta->data_tail */
    /* If we got a record and created a mapping, return it now. */
    if (me) {
      return me;
    }
    /* otherwise we got a record but didn't create a mapping,
       carry on and see if there's another one. */
  }
  return NULL;
}


/*
Handle memory mappings, by creating trace records that will tell the decoder to
retrieve the memory contents from the file.

We can also directly retrieve the contents of the target process's memory,
in case we're not sure the decoder will be able to get it from the file.
*/
static void
mapper_process_pending_mappings(struct mapper *m)
{
  for (;;) {
    struct mapping *e = mapper_get(m);
    if (!e) break;
    /* Write out the mappings now */
    if (o_profile_fd) {      
      profile_write_mapping(e);
      /* Optionally, collect the data directly from the target address space.
         We definitely have to do that for [vdso] unless we can rely on having
         vdso.so somewhere in the file system. */
      int capture_memory = (o_capture_memory || e->filename[0] == '[');
      if (capture_memory) {
        int rc;
        struct iovec local, remote;
        char *buf = (char *)malloc(e->size);
        local.iov_base = buf;
        local.iov_len = e->size;
        remote.iov_base = (void *)e->addr;
        remote.iov_len = e->size;
        /* Permissions are same as for PTRACE_ATTACH */
        rc = process_vm_readv(m->target->thread.tid, &local, 1, &remote, 1, 0);
        if (rc < 0) {
          perror("process_vm_readv");
        } else {
          if (o_verbose >= 2) {
            unsigned int i;
            fprintf(stderr, "target pid #%u: acquired memory at %#lx:", m->target->thread.tid, e->addr);
            for (i = 0; i < 16; ++i) {
              fprintf(stderr, " %02x", buf[i]);
            }
            fprintf(stderr, " ...\n");
          }
          /* It's implicit that the memory is from the (single) target process. */
          write_memory_data(e->addr, e->size, buf);
        }
        free(buf);
      }
    }
  }
}
#endif /* USE_PERF_EVENTS */


/*
Disable ASLR (address space randomization) on the current process.
*/
static int disable_ASLR(void)
{
  int rc;
  int prev = personality(0xffffffff);
  if (prev == -1) {
    perror("personality");
    rc = prev;
  } else {
    prev |= ADDR_NO_RANDOMIZE;
    rc = personality(prev);
    if (rc == -1) {
      perror("personality (disable ASLR)");
    }
  }
  return rc;
}


/*
Return the current status of a given process
  '?': can't obtain status
  'R': running
  'S': sleeping in interruptible wait
  'T': stopped
  't': trace stopped (2.6.33 on)
  'Z': zombie
*/
static char get_process_status(pid_t pid)
{
  char name[30];
  char buf[200];  /* TBD do this better */
  size_t n;
  char state = '?';
  char const *p;
  FILE *fd;
  sprintf(name, "/proc/%u/stat", (unsigned int)pid);
  fd = fopen(name, "r");
  if (!fd) {
    perror(name);
    return '?';
  }
  /* Read as much as we can, allowing space for trailing NUL */
  n = fread(buf, 1, sizeof buf - 1, fd);
  buf[n] = '\0';
  p = buf;
  while (*p && *p != ' ') ++p;
  while (*p == ' ') ++p;
  if (*p == '(') {
    while (*p && *p != ')') ++p;
    if (*p == ')') ++p;
    while (*p == ' ') ++p;
    state = *p;
    if (state == '\0' || (state >= '0' && state <= '9')) {
      state = '?';
    }
  }
  fclose(fd);
  return state;
}


/*
Return the name of a syscall.  We're not aiming to duplciate the
functionality of strace(1) here, just diagnose some essential
syscalls that we need to track for ETM tracing.
*/
static char const *syscall_name(unsigned int sn)
{
  switch (sn) {
    case __NR_read:           return "read";
#ifdef __NR_open
    case __NR_open:           return "open";
#endif
#ifdef __NR_close
    case __NR_close:          return "close";
#endif
#ifdef __NR_fork
    case __NR_fork:           return "fork";
#endif
    case __NR_clone:          return "clone";
    case __NR_brk:            return "brk";
    case __NR_wait4:          return "wait4";
#ifdef __ARM_NR_cacheflush
    case __ARM_NR_cacheflush: return "cacheflush";
#endif
    default:                  return "?";
  }
}


static int syscall_is_interesting(int sn)
{
  switch (sn) {
    case __NR_clone:    
#ifdef __NR_fork
    case __NR_fork:
#endif
#ifdef __ARM_NR_cacheflush
    case __ARM_NR_cacheflush
#endif
      return 1;
    default:
      return 0;
  }
}


static int monitor_process(target_t *target);
static int onerun(char **argv, target_t *target);


/*
This signal handler is meant to pick up requests to terminate, that should
cause the profiler to shut down gracefully and dump any profile information
it's been capturing from a running workload.  The termination request
could come from
  - ctrl-C
  - the 'timeout' command timing out
As of now, timeout doesn't seem to work - although we get a signal,
it seems timeout terminates us abruptly before we can tidy up.
*/
static void handle_sigterm(int sig)
{
  signal(sig, SIG_DFL);
  terminating = 1;
}


int main(int argc, char **argv)
{
  int rc = 0;
  int n_runs = 1;
  int i;
  int o_append = 0;
  int child_cpus_specified = 0;
  int use_coresight;
  target_t target;
  unsigned int n_perf_events = 0;
  struct sigaction action;
 
  memset(&target, 0, sizeof target);
  CPU_ZERO(&target.child_cpus);

  o_cmdname = argv[0];

  memset(&action, 0, sizeof action);
  action.sa_handler = handle_sigterm;

  signal(SIGSEGV, handle_sigsegv);
  signal(SIGABRT, handle_sigsegv);
  sigaction(SIGINT, &action, 0);
  sigaction(SIGTERM, &action, 0);
  sigaction(SIGHUP, &action, 0);

  while (*++argv) {
    char const *arg = *argv;
    if (arg[0] != '-') {
      break;
    }
    ++arg;
    if (!strcmp(arg, "v") || !strcmp(arg, "-verbose")) {
      o_verbose += 1;
    } else if (!strcmp(arg, "-")) {
      /* passing an argument of "--" terminates the options list */
      ++argv;
      break;
    } else if (!strcmp(arg, "r") || !strcmp(arg, "-repeat")) {
      char const *iters = *++argv;
      if (!iters) {
        return usage();
      }
      n_runs = atoi(iters);
    } else if (!strcmp(arg, "c") || !strcmp(arg, "-cpu-list")) {
      char const *childspec = *++argv;
      if (!childspec) {
        return usage();
      }
      if (!get_cpu_set(childspec, &target.child_cpus)) {
        return usage();
      }
      child_cpus_specified = 1;
    } else if (!strcmp(arg, "m") || !strcmp(arg, "-monitor")) {
      char const *moncpuspec = *++argv;
      if (!moncpuspec) {
        return usage();
      }
      o_monitor_cpu = atoi(moncpuspec);
    } else if (!strcmp(arg, "e") || !strcmp(arg, "-event")) {
      char const *eventspec = *++argv;
      unsigned int event;
      if (!eventspec) {
        return usage();
      }
      event = atoi(eventspec);
      g_pmu_config.eventtypes[n_perf_events++] = event;
    } else if (!strcmp(arg, "et") || !strcmp(arg, "-event-trace")) {
      /* Specify an event to be traced on ETM.  Currently these are specified as
         a bus signal number, as in the core's TRM.  This may be core-specific,
         and hence problematic on heterogeneous systems. */
      /* Note that to trace events on ETM, we need to tell the PMU to export
         the event bus, by setting PMCR.X (bit 4). */
      char const *eventspec = *++argv;
      unsigned int event;
      if (o_cs.n_pmu_events == 4) {
        fprintf(stderr, "%s: maximum of 4 events can be traced in ETM\n", o_cmdname);
        exit(EXIT_FAILURE);
      }
      if (!eventspec) {
        return usage();
      }
      if (sscanf(eventspec, "%x", &event) != 1) {
        fprintf(stderr, "%s: invalid event specifier \"%s\"\n", o_cmdname, eventspec);
      }
      o_cs.pmu_events[o_cs.n_pmu_events++] = event;
    } else if (!strcmp(arg, "-halt")) {
      o_halt = 1;
    } else if (!strcmp(arg, "-sample")) {
      o_pc_sample = 1;
    } else if (!strcmp(arg, "K") || !strcmp(arg, "-kernel")) {
      o_cs.kernel = 1;
    } else if (!strcmp(arg, "-no-kernel")) {
      o_cs.kernel = 0;
    } else if (!strcmp(arg, "-libs")) {
      o_sos = 1;
    } else if (!strcmp(arg, "-no-libs")) {
      o_sos = 0;
    } else if (!strcmp(arg, "t") || !strcmp(arg, "-tid")) {
      arg = *++argv;
      if (!arg) {
        return usage();
      }
      target.thread.tid = atoi(arg);
      if (!target.thread.tid) {
        return usage();
      }
    } else if (!strcmp(arg, "-strobe")) {
      o_cs.strobe = 1;
    } else if (!strcmp(arg, "-no-strobe")) {
      o_cs.strobe = 0;
    } else if (!strcmp(arg, "-cs-ts-cycles")) {
      arg = *++argv;
      if (!arg) {
        return usage();
      }
      o_cs.ts_cycles = atoi(arg);
    } else if (!strcmp(arg, "-cs-cycle-accurate")) {
      o_cs.cycle_accurate = 1;
    } else if (!strcmp(arg, "-no-cs-cycle-accurate")) {
      o_cs.cycle_accurate = 0;
    } else if (!strcmp(arg, "-cs-timestamp-enabled")) {
      o_cs.ts_enabled = 1;
    } else if (!strcmp(arg, "-no-cs-timestamp-enabled")) {
      o_cs.ts_enabled = 0;
    } else if (!strcmp(arg, "-cs-contexid")) {
      o_cs.cxid = 1;
    } else if (!strcmp(arg, "-no-cs-contextid")) {
      o_cs.cxid = 0;
    } else if (!strcmp(arg, "-cs-filter-contextid")) {
      o_cs.cxfilter = 1;
    } else if (!strcmp(arg, "-no-cs-filter-contextid")) {
      o_cs.cxfilter = 0;
    } else if (!strcmp(arg, "-cs-branch-broadcast")) {
      o_cs.branch_broadcast = 1;
    } else if (!strcmp(arg, "-no-cs-branch-broadcast")) {
      o_cs.branch_broadcast = 0;
    } else if (!strcmp(arg, "-cs-return-stack")) {
      o_cs.return_stack = 1;
    } else if (!strcmp(arg, "-cs-no-return-stack")) {
      o_cs.return_stack = 0;
    } else if (!strcmp(arg, "-cs-trace-data")) {
      o_cs.trace_data = 1;
    } else if (!strcmp(arg, "-cs-sleep")) {
      arg = *++argv;
      if (!arg) {
        return usage();
      }
      o_cs_sleep = atoi(arg);
    } else if (!strcmp(arg, "-no-itm")) {
      o_trace_itm = 0;
    } else if (!strcmp(arg, "R") || !strcmp(arg, "-addr-no-randomize")) {
      /* same opts as setarch */
      o_disable_ASLR = 1;
    } else if (!strcmp(arg, "n") || !strcmp(arg, "-null") || !strcmp(arg, "-no-etm")) {
      o_trace = 0;
    } else if (!strcmp(arg, "-no-ptrace")) {
#if USE_PTRACE
      o_use_ptrace = 0;
#endif
    } else if (!strcmp(arg, "-mmap-pages")) {
      arg = *++argv;
      if (!arg) {
        return usage();
      }
      o_mmap_pages = atoi(arg);
      if (o_mmap_pages == 0) {
        return usage();
      }
    } else if (!strcmp(arg, "o") || !strcmp(arg, "-output")) {
      char const *fn = *++argv;
      if (!fn) {
        return usage();
      }
      o_profile_fn = fn;
    } else if (!strcmp(arg, "-append")) {
      o_append = 1;
    } else if (!strcmp(arg, "h") || !strcmp(arg, "-help")) {
      return usage();
    } else {
      fprintf(stderr, "%s: invalid option: '%s'\n", o_cmdname, arg);
      return usage();
    }
  }

  /* To have something to profile, we need exactly one of
      - command and arguments
      - target tid/pid
  */
  if (((argv[0] != NULL) +
       (target.thread.tid != 0)) != 1) {
    return usage();
  }
 
  if (target.thread.tid != 0 && (o_disable_ASLR || (n_runs != 1))) {
    /* If we're attaching to an existing process, we can't use options that
       change the process startup. */
    return usage();
  }

  /* Set monitor process affinity, and get the CPU set for the
     child process. */
  if (target.thread.tid != 0 && !child_cpus_specified) {
    rc = sched_getaffinity(target.thread.tid, sizeof target.child_cpus, &target.child_cpus);
    if (rc < 0) {
      perror("sched_getaffinity");
      /* Most likely, target process terminated */
      return EXIT_FAILURE;
    }
    if (o_verbose) {
      int i;
      fprintf(stderr, "Thread %u has affinity to these CPUs:", target.thread.tid);
      for (i = 0; i < 32; ++i) {
        if (CPU_ISSET(i, &target.child_cpus)) {
          fprintf(stderr, " %u", i);
        }
      }
      fprintf(stderr, "\n");
    }
  }
  set_affinity(&o_monitor_cpu, &target.child_cpus);
  assert(o_monitor_cpu != -1);
  assert(!CPU_ISSET(o_monitor_cpu, &target.child_cpus));

  /* If we're going to be using memory-mapped debug access,
     either ETM trace or non-invasive PC/PMU sampling, then we need
     to set up the CoreSight access library. */
  use_coresight = o_trace || o_pc_sample;

  if (use_coresight) {
    if (o_verbose >= 2) {
      registration_verbose = 2;    /* Include confirmation messages */
      cs_diag_set(1);
    } else {
      registration_verbose = 1;    /* Errors only */
      cs_diag_set(0);
    }
    if (setup_known_board(&g_board, &g_devices) < 0) {
      fprintf(stderr, "%s: cannot set up CoreSight on this board\n", o_cmdname);
      return 1;
    }
  }

  /* Build the target array - this is more convenient than having to
     keep iterating through a cpu_set_t testing bits. */
  assert(target.n_target_cpus == 0);
  for (i = 0; i < LIB_MAX_CPU_DEVICES; ++i) {
    if (CPU_ISSET(i, &target.child_cpus)) {
      target.target_cpu[target.n_target_cpus].cpu = i;
      ++target.n_target_cpus;
    }
  }
  assert(target.n_target_cpus > 0);

  if (o_pc_sample) {
    /* Set up memory-mapped access for PC/PMU sampling */
    /* Complete the PMU configuration, to be used for all CPUs */
    g_pmu_config.version = CS_PMU_VERSION_1;
    g_pmu_config.div64 = 0;
    g_pmu_config.mask = (1U << n_perf_events) - 1;
    /* eventtypes will already be filled in */
    for (i = 0; i < target.n_target_cpus; ++i) {
      struct target_cpu *const tcpu = &target.target_cpu[i];
      cs_device_t debug, pmu;
      tcpu->debug = debug = cs_cpu_get_device(tcpu->cpu, CS_DEVCLASS_DEBUG);

#ifdef USING_V7_DBG_HALT
      cs_debug_moe_t reason;
      if (cs_debug_is_halted(debug, &reason)) {
        fprintf(stderr, "** CPU #%u was halted (reason=%u), restarted\n", tcpu->cpu, reason);
        cs_debug_restart(debug);
        if (cs_debug_is_halted(debug, &reason)) {
          fprintf(stderr, "** CPU #%u re-entered debug state, reason=%u\n", tcpu->cpu, reason);
          if (reason == CS_DEBUG_MOE_EXTERNAL) {
             /* External debug being held high? */
            cs_cti_diag();
          }
          exit(EXIT_FAILURE);
        }
      }
      assert(!cs_debug_is_halted(debug, NULL));
#endif

      tcpu->pmu  = pmu = cs_cpu_get_device(tcpu->cpu, CS_DEVCLASS_PMU);
      if (pmu) {
        /* Set up the PMU - ignore what 'perf' might have done with this CPU! */
        cs_pmu_write_status(pmu, CS_PMU_DIV64|CS_PMU_EVENTTYPES, &g_pmu_config);
        cs_pmu_reset(pmu, CS_PMU_CYCLES|CS_PMU_OVERFLOW|CS_PMU_ENABLE);
        tcpu->highcycles = 0;
      }
    }
  }

  if (o_trace && o_cs.n_pmu_events) {
    /* Export the PMU event bus to the ETM. */
    for (i = 0; i < target.n_target_cpus; ++i) {
      struct target_cpu *const tcpu = &target.target_cpu[i];
      /* Perhaps this should be an API call on the ETM. */
      cs_device_t pmu = cs_cpu_get_device(tcpu->cpu, CS_DEVCLASS_PMU);
      cs_pmu_bus_export(pmu, /*enable=*/1);
      fprintf(stderr, "%u PMCR now 0x%08x\n", tcpu->cpu, cs_device_read(pmu, CS_PMCR));
    }
  }

  if (o_trace) {
    /* Disable the TPIU to avoid backpressure - really CSAL should
       take care of this without us having to understand the topology */
    cs_disable_tpiu();
    cs_sink_disable(g_devices.etb);
    /* Empty the CoreSight trace buffer so we don't pick
       up residual trace from before this session. */
    cs_empty_trace_buffer(g_devices.etb);
    /* The ETB is disabled and has just been emptied - we expect the
       buffer to be empty, unwrapped and with both pointers at zero. */
    {
      int len = cs_get_buffer_unread_bytes(g_devices.etb);
      int wrapped = cs_buffer_has_wrapped(g_devices.etb);
      if (len > 0 || wrapped) {
        fprintf(stderr, "** Tried to empty ETB but %u bytes in buffer (%swrapped)\n",
            len, (wrapped ? "" : "not "));
      } else {
        if (o_verbose) {
          fprintf(stderr, "Trace buffer empty, ready to collect trace\n");
        }
      }
    }
    if (o_profile_fn) {
      /* If we're setuid root, is this a security hole? */
      o_profile_fd = fopen(o_profile_fn, (o_append ? "ab" : "wb"));
      if (!o_profile_fd) {
        perror(o_profile_fn);
        return -1;
      }
    }
    /* If we're tracing the kernel, dump out current kernel memory contents -
       which may be slightly different from the contents of the kernel ELF image. */
    if (o_profile_fd && o_trace && o_cs.kernel) {
      unsigned long kstart = kernel_virtual_address();
      unsigned long kend = kstart + 0x1000000;
      char const *kfn = "kernel_dump.bin";
      dump_kernel_memory(kfn, kstart, kend);
      write_memory_dump(kstart, kend-kstart, kfn);
    }
    for (i = 0; i < target.n_target_cpus; ++i) {
      struct target_cpu *const tcpu = &target.target_cpu[i];
      tcpu->etm = cs_cpu_get_device(tcpu->cpu, CS_DEVCLASS_SOURCE);
      if (!tcpu->etm) {
        fprintf(stderr, "Could not get ETM for CPU #%u\n", tcpu->cpu);
        return -1;
      }
      g_devices.ptm[tcpu->cpu] = tcpu->etm;  /* for get_etm_metadata */
      cs_set_trace_source_id(tcpu->etm, 0x10 + tcpu->cpu);
      rc = etm_configure_trace(tcpu->etm, &o_cs);
      if (rc) {
        fprintf(stderr, "Failed to configure ETM trace for CPU #%u\n", tcpu->cpu);
      }
    }
    if (o_trace_itm) {
      if (!g_devices.itm) {
        fprintf(stderr, "warning: no ITM/STM device available\n");
        o_trace_itm = 0;
      } else {
        cs_set_trace_source_id(g_devices.itm, 0x08);
        cs_trace_disable(g_devices.itm);  /* disable before programming */
        cs_trace_enable_timestamps(g_devices.itm, 1);
        cs_trace_swstim_enable_all_ports(g_devices.itm);
        cs_trace_enable(g_devices.itm);
      }
    }
    write_metadata(&target.child_cpus);
    etm_configure_cross_trigger();
  }

  if (use_coresight) {
    cs_checkpoint();
    if (cs_error_count() > 0) {
      fprintf(stderr, "** Failed to configure CoreSight trace subsystem\n");
      return 1;
    }
    if (o_verbose) {
      fprintf(stderr, "** Configured CoreSight subsystem\n");
    }
  }

  tns_init();
 
  if (target.thread.tid != 0) {
    /* Monitoring an existing process. */
    rc = sched_setaffinity(target.thread.tid, sizeof target.child_cpus, &target.child_cpus);
    rc = monitor_process(&target);
  } else {
    /* Run the program-under-test, perhaps several times.
       Address-space randomization could cause a problem here...
       the address will be different for each run. */ 
    for (i = 1; i <= n_runs; ++i) {
      rc = onerun(argv, &target);
      if (rc != 0 && n_runs > 1) {
        fprintf(stderr, "** terminated after %u run(s)\n", i);
        break;
      }
    }
  }

  if (0 && o_trace && o_cs.n_pmu_events) {
    /* Check PMU event bus is still exported to ETM - TBD delete this. */
    for (i = 0; i < target.n_target_cpus; ++i) {
      struct target_cpu *const tcpu = &target.target_cpu[i];
      cs_device_t pmu = cs_cpu_get_device(tcpu->cpu, CS_DEVCLASS_PMU);
      fprintf(stderr, "after run, %u PMCR now 0x%08x\n", tcpu->cpu, cs_device_read(pmu, CS_PMCR));
    }
  }
  /* Close everything down. */
  /* All our sub-threads should have terminated by this point. */
  cs_shutdown();
  if (o_profile_fd) {
    fclose(o_profile_fd);
  }
  return rc;
}


/*
When tracing a multithreaded or multiprocess application (e.g. hackbench),
we need to keep track of all the various threads.
*/
struct thread_info {
  struct thread_info *next;
  pid_t pid;
  int in_syscall:1;         /* Is thread currently executing a syscall? */
  int show_syscall:1;       /* Is syscall interesting? */
  unsigned int syscall;     /* Number of syscall currently executing */
};

#define THREAD_MAP_BUCKETS 32
struct thread_map {
  struct thread_info *active[THREAD_MAP_BUCKETS];
  struct thread_info *freelist;
};


void thread_map_allocate(struct thread_map *map)
{
  int i;
  const int N = 10;
  struct thread_info *blocks;
  blocks = (struct thread_info *)malloc(N*sizeof(struct thread_info));
  memset(blocks, 0, N*sizeof(struct thread_info));
  for (i = 0; i < N; ++i) {
    struct thread_info *b = &blocks[i];
    b->pid = 0;
    b->next = map->freelist;
    map->freelist = b;
  }
}


void thread_map_init(struct thread_map *map)
{
  memset(map, 0, sizeof(struct thread_map));
  thread_map_allocate(map);
}

/*
Find or create a thread info block.  This isn't thread-safe
as we assume we're calling it from the single-threaded
monitor process.
*/
struct thread_info *thread_map_get(struct thread_map *map, pid_t pid)
{
  struct thread_info *b;
  unsigned int bn = pid % THREAD_MAP_BUCKETS;
  for (b = map->active[bn]; b != NULL; b = b->next) {
    if (b->pid == pid) {
      break;
    }
  }
  if (!b) {
    if (map->freelist == NULL) {
      thread_map_allocate(map);
      assert(map->freelist != NULL);
    }
    b = map->freelist;
    map->freelist = b->next;
    b->pid = pid;
    b->next = map->active[bn];
    map->active[bn] = b;
  }
  assert(b != NULL);
  assert(b->pid == pid);
  return b;
}


/*
Periodically collect the contents of the ETB.
*/
static tbuf_t *tb_top;
static volatile sig_atomic_t cs_collecting;
static pthread_t etb_collector_tid;
static tbuf_t *tb_free;

/* Preallocate some buffers and put them on a free-list */
static void tbuf_prealloc(unsigned int n)
{
  while (n > 0) {
    tbuf_t *tb = tbuf_alloc(g_devices.etb);
    assert(tb != NULL);
    tb->next = tb_free;
    tb_free = tb;
    --n;
  }
}

static void *etb_collector_thread(void *arg_unused)
{
  unsigned int n_collected = 0;
  tbuf_t **tb_nextp = &tb_top;   /* Where to add the next item */
  tbuf_t *tb_current = NULL;
  tb_top = NULL;
  assert(o_trace);
  /* Main loop of collector thread:
   *   Enable ETB
   *   Wait for a while
   *   Disable ETB
   *   Retrieve trace from ETB
   */
  while (cs_collecting && !terminating) {
    int rc;
    rc = cs_set_buffer_trigger_counter(g_devices.etb, g_etb_countdown);
    rc = cs_sink_enable(g_devices.etb);
    if (rc < 0) {
      fprintf(stderr, "ETB collector: couldn't enable ETB\n");
    }
    assert(cs_sink_is_enabled(g_devices.etb));
    if (!tb_current) {
      if (tb_free) {
        tb_current = tb_free;
        tb_free = tb_current->next;
        tb_current->next = NULL;
      } else {
        tb_current = tbuf_alloc(g_devices.etb);
      }
    }
    /* Pause the collector thread to give the program under test
       time to generate some trace */
    if (o_cs_sleep > 0) {
      usleep(o_cs_sleep);
    }
    /* Now disable the ETB and collect the trace */
    if (cs_sink_is_enabled(g_devices.etb)) {
      cs_sink_disable(g_devices.etb);
    } else {
      if (o_verbose) {
        fprintf(stderr, "ETB was already disabled\n");
      }
    }
    if (o_verbose >= 2) {
      int len = cs_get_buffer_unread_bytes(g_devices.etb);
      int wrapped = cs_buffer_has_wrapped(g_devices.etb);
      unsigned int wrptr = cs_device_read(g_devices.etb, 0x018);
      printf("ETB [%u] has %d bytes, wrapped=%d, wrptr=%u\n", n_collected, len, wrapped, wrptr*4);
    }
    if (tbuf_collect(tb_current) == 0) {
      ++n_collected;
      *tb_nextp = tb_current;        
      tb_nextp = &tb_current->next;
      tb_current = NULL;
    }
  }
  if (o_verbose) {
    tbuf_t *tb;
    unsigned long total_trace = 0;
    unsigned int n = 0;
    for (tb = tb_top; tb != NULL; tb = tb->next) {
      ++n;
      total_trace += tb->len;
    }
    assert(n == n_collected);
    fprintf(stderr, "ETB: collected %lu bytes in %u buffers\n",
        total_trace, n_collected);
  }
  return 0;
}


/*
Collect trace from an existing process - either one that was already
running or a child that we've just forked.
*/
static int monitor_process(target_t *target)
{
  int rc = 0;
  const pid_t pid = target->thread.tid;

    int i;
    unsigned int n;
#if 0
    tbuf_t *tb_top = NULL;         /* Head of list of collected tbuf's */
    tbuf_t **tb_nextp = &tb_top;   /* Where to add the next item */
    tbuf_t *tb_current = NULL;
    tbuf_t *tb_free = NULL;
    for (n = 0; n < 10; ++n) {
      tbuf_t *tb = tbuf_alloc(g_devices.etb);
      tb->next = tb_free;
      tb_free = tb;
    }
#endif
    ns_epoch_t time_start, time_end;
#if USE_PERF_EVENT
    struct mapper *amap = mapper_create();
#endif /* USE_PERF_EVENT */
    struct thread_map tmap;

  assert(pid != 0);
  if (o_verbose) {
    fprintf(stderr, "** Monitoring process %u\n", pid);
  }

    if (o_trace && o_cs.cxfilter) {
      /* Now set the CXID filter on the trace sources - which we can only do when
         we know the problem-program thread id. */
      if (o_verbose) {
        fprintf(stderr, "Setting ETM trace filter for TID=%u\n", pid);
      }
      for (i = 0; i < target->n_target_cpus; ++i) {
        etm_configure_trace_cxid_filter(target->target_cpu[i].etm, pid);
      }
    }

    /* Set up the thread map that we'll use to keep track
       of the child process's threads. */
    thread_map_init(&tmap);
    /* Now we (the trace monitor process) are pinned to one CPU
       while the program under test is pinned to a set of different CPUs.
       This should allow us to sample and trace the program
       non-invasively. */

#if USE_PERF_EVENT
    if (o_use_perf) {
      char name[20];
      sprintf(name, "/proc/%u/mem", pid);      
      target->thread.mem_fd = open(name, O_RDONLY);
      if (target->thread.mem_fd < 0) {
        perror("open /proc/pid/mem");
      }
      mapper_open(amap, target); 
    }
#endif /* USE_PERF_EVENT */

    if (o_trace) {
      /* CoreSight trace is already configured and filtering -
         enable it */
      if (cs_error_count() > 0) {
        /* Diagnostics already printed by CSAL */
        return -1;
      }
      if (o_verbose) {
        fprintf(stderr, "enabling CPU trace\n");
      }
      for (i = 0; i < target->n_target_cpus; ++i) {
        cs_trace_enable(target->target_cpu[i].etm);
      }
      if (cs_error_count() > 0) {
        if (o_verbose) {
          fprintf(stderr, "CoreSight access errors detected\n");
        }
        return -1;
      }
    }
    if (o_trace) {
      pthread_attr_t collector_attr;
      pthread_attr_init(&collector_attr);
      cs_collecting = 1;
      if (o_verbose) {
        fprintf(stderr, "Starting ETB collector thread...\n");
      }
      tbuf_prealloc(50);
      pthread_create(&etb_collector_tid, &collector_attr, etb_collector_thread, 0);
      if (o_verbose) {
        fprintf(stderr, "  ... started\n");
      }
    }
    /* CoreSight trace is now running on the target cores. */
    if (target_release(target) < 0) {
      return -1;
    }
    /* From this point on, the child is running, initially in the
       remainder of our post-fork child code, then in the execv()
       system call and finally in the target program.
       So any verbosity messages etc. we print from here on,
       will likely be mingled with command-under-test output. */
#if USE_PTRACE
    if (o_use_ptrace) {
      /* Let the child advance to its first syscall. */
      ptrace(PTRACE_SYSCALL, pid, 0, 0);
    }
#endif

    time_start = tns_now();
    /* This is the main monitoring loop. */
    for (n = 1; ; ++n) {
      pid_t p;     /* child process test */
#define SIGINFO
#ifdef SIGINFO
      siginfo_t status;
#else
      int status;  /* status from waitpid */
#endif
      if (0) {
        char state = get_process_status(pid);
        if (state != 'R') {
          fprintf(stderr, "pid #%u state = '%c'\n", pid, state);
        }
      }
      /* If collecting ETM trace, re-enable trace collection.
         The trace sources are continuously enabled. */
      if (o_trace) {
#if 0
        assert(tb_current == NULL);
        if (tb_free) {
          tb_current = tb_free;
          tb_free = tb_free->next;
          tb_current->next = NULL;
        } else {
          tb_current = tbuf_alloc(g_devices.etb);
        }
        cs_set_buffer_trigger_counter(g_devices.etb, g_etb_countdown);
        cs_sink_enable(g_devices.etb);
#endif
        if (o_trace_itm) {
          /* With ITM, this is really just a demonstration of how to
             write a software instrumentation message.  We can't get a
             useful timestamped trace record. */
          cs_trace_stimulus(g_devices.itm, 0, 0);
        } 
      }
      /* If using PC-sampling, take samples from each of the CPUs.
         They might or might not currently be running the process
         under test. */
      if (o_pc_sample) {
        for (i = 0; i < target->n_target_cpus; ++i) {
          struct target_cpu *const tcpu = &target->target_cpu[i];
          cs_virtaddr_t pc = 0xCCCCCCCC;
          unsigned int cxid = 0xCCCCCCCC;
          unsigned int apsr = 0xCCCCCCCC;
          unsigned int code[10];
          unsigned int cycle_lo;
          unsigned long long cycles;
          unsigned int counts[6];
          cs_pmu_mask_t overflow;
          cs_device_t pmu = tcpu->pmu;
          cs_device_t cpu_debug = tcpu->debug;

          if (pmu) {
            /* Read the cycle counter and its overflow flag, destructively. */
            unsigned int mask = CS_PMU_MASK_CYCLES | g_pmu_config.mask;
            cs_pmu_get_counts(pmu, mask, &cycle_lo, counts, &overflow);
            if (overflow & CS_PMU_MASK_CYCLES) {
              ++tcpu->highcycles;
            }
            cycles = ((unsigned long long)tcpu->highcycles << 32) | cycle_lo;
          }
          if (cpu_debug) {
            if (o_halt) {
#ifdef USING_V7_DBG_HALT
              memset(code, '\xCC', sizeof code);
              assert(!cs_debug_is_halted(cpu_debug, NULL));
              /* Now extract other state of the CPU by briefly halting it and
                 injecting read-out instructions.  To minimize the chance that
                 we are pre-empted while having halted the CPU, we do a
                 sched_yield() here.  We could also consider doing mlockall().
              */
              sched_yield();
              /* We can sample the PC without halting the core. */
              cs_debug_get_pc_sample(cpu_debug, &pc, &cxid, NULL);
              if (cs_debug_halt(cpu_debug, 0)) {
                fprintf(stderr, "** failed to halt CPU #%u\n", tcpu->cpu);
              } else {
                cs_debug_read_sysreg(cpu_debug, CS_SYSREG_APSR, &apsr);
                /* Read some code from around the program counter.  Note that we took
                   the PC sample before we halted the target core, so its PC might have
                   moved on a bit... or even changed ASID.  We could get the PC again here. */
                cs_debug_read_memory(cpu_debug, (pc - 8) & ~3, code, sizeof code);
                cs_debug_restart(cpu_debug);
              }
#else
              /* If we're not using halted-debug probing, get the PC anyway */
              cs_debug_get_pc_sample(cpu_debug, &pc, &cxid, NULL);
#endif
            } else {
              /* If we're not using halted-debug probing, get the PC anyway */
              cs_debug_get_pc_sample(cpu_debug, &pc, &cxid, NULL);
            }
          }
          if (0) {
            printf("  #%u: cycles=%016llX (of=%u) counts=%08X,%08X PC=%08lX APSR=%08X CXID=%08X code=%08X %08X %08X %08X...\n", i,
                 cycles, ((overflow & CS_PMU_MASK_CYCLES) != 0),
                 counts[0], counts[1],
                 (unsigned long)pc,
                 apsr, cxid, code[0], code[1], code[2], code[3]);
          }
        } /* for each target CPU */
      } /* if PC/PMU sampling */
      if (0 && o_trace) {
        /* Wait a bit for the ETB trace buffer to fill up with ETM trace
           from the child CPUs */
        usleep(o_cs_sleep * 1000);
      }
#if USE_PERF_EVENT
      /* Collect pending performance events from the perf events
         subsystem into our holding structure.  We'll combine and
         dump them at the end. */
      if (amap) {
        mapper_process_pending_mappings(amap);
      }
#endif /* USE_PERF_EVENT */
      /* See if the child process has terminated - but when rapidly PC-sampling,
         don't do this every time */
#ifndef SIGINFO
      status = 0xCCCCCCCC;
#endif
      /* Wait for target process.
         We could use WNOHANG for non-blocking, but must then handle ECHILD
         (no child processes ready). */
      if (1 || o_trace || (n & 0xFF) == 0) {
#ifdef SIGINFO
        p = waitid(P_PID, pid, &status, WSTOPPED|WEXITED);
#else
        p = waitpid(pid, &status, 0);
#endif
      } else {
        p = 0;    /* act as if not stopped */
      }
      if (terminating) {
        if (o_verbose) {
          fprintf(stderr, "Terminating...\n");
        }
        break;
      }
      if (p < 0 && errno == ECHILD) {
        /* No child process ready */
      } else if (p < 0) {
#ifdef SIGINFO
        perror("waitid");
#else
        perror("waitpid");
#endif
        fprintf(stderr, "error waiting for PID=%u\n", pid);
        break;
      }
      if (o_trace) {
       // cs_sink_disable(g_devices.etb);
      }
#ifdef SIGINFO
      p = status.si_pid;
#endif
      if (p == 0) {
        /* No information available - returned because WNOHANG */
      } else {
        if (o_verbose >= 2) {
#ifdef SIGINFO
          fprintf(stderr, "waitid pid #%u (target pid #%u)", p, pid);
          if (status.si_code == CLD_STOPPED) {
            fprintf(stderr, ": stopped at signal %u", status.si_signo);
          } else if (status.si_code == CLD_TRAPPED) {
            fprintf(stderr, ": trapped");
          } else if (status.si_code == CLD_EXITED) {
            fprintf(stderr, ": exited, rc=%u", status.si_status);
          }
#else
          fprintf(stderr, "waitpid pid #%u (target pid #%u) status 0x%x", p, pid, status);
          if (WIFSTOPPED(status)) {
            fprintf(stderr, ": stopped at signal %u", WSTOPSIG(status));
            switch (WSTOPSIG(status)) {
              case SIGTRAP:
                fprintf(stderr, " (SIGTRAP)");
                break;
              case SIGSTOP:
                fprintf(stderr, " (SIGSTOP)");
                break;
            }
          } else if (WIFEXITED(status)) {
            fprintf(stderr, ": exited, rc=%u", WEXITSTATUS(status));
          }
#endif
          fprintf(stderr, "\n");
        }
#if USE_PTRACE
#ifdef SIGINFO
        if (status.si_code == CLD_STOPPED || status.si_code == CLD_TRAPPED) {
          if (status.si_code == CLD_TRAPPED) {
#else
        if (WIFSTOPPED(status)) {
          if (WSTOPSIG(status) == SIGTRAP) {
#endif
            /* The target process is stopped for tracing.  Since we're
               tracing syscalls, it may have stopped for one of two reasons:
                - it is about to execute a syscall
                - it has just returned from a syscall               
            */
            int rc;
            unsigned int sn;
            struct thread_info *ti = thread_map_get(&tmap, p);
            struct iovec iov;

            /* Find out about the system call.
               Get the user registers.  This is supposed to retrieve to a
               'user_regs_struct' but there doesn't seem to be a useful
               definition for ARM.  So provide enough space for all the
               user registers on 32-bit and 64-bit, as well as extras
               like PSR etc.  TBD: check cross-32/64 tracing. */
            unsigned long uregs[36];
            memset(&uregs, 0xCC, sizeof uregs);
            uregs[35] = 0xDEAD;
#ifdef PTRACE_GETREGSET
            iov.iov_len = sizeof uregs;
            iov.iov_base = &uregs;
            /* NT_PRSTATUS gets the elf_gregset_t struct */
            rc = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
#else            
            rc = ptrace(PTRACE_GETREGS, pid, 0, &uregs);
#endif
            if (rc < 0) {
              if (errno == ESRCH) {
                /* No such process - problem-program has terminated */
                fprintf(stderr, "Child process #%u has terminated\n", pid);
              } else {
                perror("ptrace(PTRACE_GETREGS)");
              }
            }
            if (uregs[35] != 0xDEAD) {
              fprintf(stderr, "ptrace overflowed buffer - program corrupt!\n");
              break;
            }
            if (!ti->in_syscall) {
              /* syscall number is in R7 (or x8 on ARM64??)
                 for meaning see arch/arm/include/asm/unistd.h */
              sn = uregs[7];
              ti->show_syscall = syscall_is_interesting(sn);
              if (ti->show_syscall) {
                printf("%5u: syscall(%u=%s,0x%lx/%lu,0x%lx/%lu,0x%lx/%lu,...)",
                    p, sn, syscall_name(sn),
                    uregs[8], uregs[8], uregs[9], uregs[9], uregs[10], uregs[10]);
              }
              ti->in_syscall = 1;
              ti->syscall = sn;
            } else {
              /* Get the syscall return code */
              if (ti->show_syscall) {
                printf(" = 0x%lx\n", uregs[0]);
              }
              ti->in_syscall = 0;
            }
            /* Either execute the syscall, or carry on to the next syscall */
            ptrace(PTRACE_SYSCALL, p, 0, 0);
          } else {
            /* Stopped for some other reason e.g. raise(SIGSTOP) */
            ptrace(PTRACE_SYSCALL, p, 0, 0);
          }
        }
#endif
      }
      /* Retrieve the trace buffer contents */
      if (o_trace) {
#if 0
        if (o_verbose) {
          int len = cs_get_buffer_unread_bytes(g_devices.etb);
          int wrapped = cs_buffer_has_wrapped(g_devices.etb);
          unsigned int wrptr = cs_device_read(g_devices.etb, 0x018);
          printf("ETB has %d bytes, wrapped=%d, wrptr=%u\n", len, wrapped, wrptr*4);
        }
        tbuf_collect(tb_current);
        *tb_nextp = tb_current;        
        tb_nextp = &tb_current->next;
        tb_current = NULL;
#endif
      }
#ifdef SIGINFO
      if (p == pid && status.si_code == CLD_EXITED) {
        /* The child process has terminated */
        rc = status.si_status;
        break;
      }
#else
      if (p == pid && WIFEXITED(status)) {
        /* The child process has terminated */
        rc = WEXITSTATUS(status);
        break;
      }
#endif
    }
    /* finished the main loop */

    time_end = tns_now();
    if (o_verbose) {
      fprintf(stderr, "Finished program under test\n");
    }
    if (o_trace) {
      void *res;
      cs_collecting = 0;
      if (o_verbose) {
        fprintf(stderr, "Waiting for ETB collector thread to terminate...\n");
      }
      pthread_join(etb_collector_tid, &res);
      if (o_verbose) {
        fprintf(stderr, "... ETB collector thread terminated\n");
      }
    }
    if (o_trace && o_profile_fd) {
      tbuf_t *tb;
      int count = 0;
      for (tb = tb_top; tb != NULL; tb = tb->next) {
        tbuf_write(tb);
        ++count;
      }
    }
    if (o_verbose) {
      ns_delta_t total = time_end - time_start;
      unsigned long nsint = (unsigned long)(total / n);
      fprintf(stderr, "captured %u samples (approx interval %luns)\n", n, nsint);
      fprintf(stderr, "  total time:              %.02f\n", (float)total / 10e9);
      if (o_trace) {
        fprintf(stderr, "  time spent reading ETB:  %.02f\n", (float)time_etb_read / 10e9);
      }
      fprintf(stderr, "  time spent writing data: %.02f\n", (float)time_data_write / 10e9);
    }
    if (1) {
      /* Write out individual files
          <fn>.raw    - the raw trace file (one buffer)
          <fn>.map    - the /proc/<pid>/maps file
          <fn>.ini    - the metadata, DS-5 snapshot style
      */
      if (o_verbose) {
        fprintf(stderr, "Writing separate trace files to %s.{raw,map,ini}...\n", o_profile_fn);
      }
      if (o_trace && tb_top != NULL) {
        tbuf_t *tb = tb_top;   /* Use the first buffer */
        FILE *fd;
        char *fn = (char *)malloc(strlen(o_profile_fn) + 5);
        sprintf(fn, "%s.raw", o_profile_fn);
        if (o_verbose) {
          fprintf(stderr, "writing trace buffer (%u bytes) to %s\n", tb->len, fn);
        }
        assert(tb != NULL);
        assert(tb->buffer != NULL);
        fd = fopen(fn, "wb");
        if (!fd) {
          perror(fn);
        } else {
          fwrite(tb->buffer, tb->len, 1, fd);
          fclose(fd);
        }
        free(fn);
      }
#if USE_PERF_EVENT
      if (0) {
        char *fn = (char *)malloc(strlen(o_profile_fn) + 5);
        sprintf(fn, "%s.map", o_profile_fn);
        if (o_verbose) {
          fprintf(stderr, "writing proc map to %s\n", fn);
        }
        mapper_print_proc_maps(amap, fn);
        free(fn);
      }
#endif /* USE_PERF_EVENT */
      if (0 && o_trace) {
        FILE *fd;
        char *meta = 0; // get_etm_metadata(&target->child_cpus);
        char *fn = (char *)malloc(strlen(o_profile_fn) + 5);
        assert(meta != NULL);
        sprintf(fn, "%s.ini", o_profile_fn);
        if (o_verbose) {
          fprintf(stderr, "writing trace metadata to %s\n", fn);
        }
        fd = fopen(fn, "w");
        if (!fd) {
          perror(fn);
        } else {
          fputs(meta, fd);
          fclose(fd);
        }
        free(fn);
        free(meta);
      }
    }
#if USE_PERF_EVENT
    if (o_verbose) {
      fprintf(stderr, "Closing perf_events map\n");
    }
    mapper_close(amap);
#endif /* USE_PERF_EVENT */
    if (o_trace) {      
      fprintf(stderr, "csprofile: collected %lu bytes of CoreSight trace in %u buffers\n",
          total_trace_collected, n_trace_buffers_collected);
      while (tb_top != NULL) {
        tbuf_t *tb = tb_top;
        tb_top = tb->next;
        tbuf_free(tb);
      }
    }
  return rc;
}


static int onerun(char **argv, target_t *target)
{
  pid_t pid;
  int rc;
  int pfd[2];
  
  /* Create a pipe so that our master process can talk to our setup
     code in the subprocess before we exec the command under test. */
  rc = pipe(pfd);
  if (rc < 0) {
    perror("pipe");
    return rc;
  }
  /* Create the subprocess. */
  pid = fork();
  if (pid == 0) {
    char buf[1];
    /* We are now the child process */
    /* The profiler may be setuid root or have other privileges to allow
       it to access the CoreSight trace.  Ensure that we revert to the
       real uid before switching to the command under test. */
    rc = seteuid(getuid());
    if (rc < 0) {
      perror("seteuid");
      exit(1); /* seteuid failed */
    } 
    /* We only read from the master, so close the writing side. */
    close(pfd[1]);
    if (o_verbose) {
      fprintf(stderr, "child about to exec <%s>\n", argv[0]);
    }
    if (o_disable_ASLR) {
      (void)disable_ASLR();
    }
#if USE_PTRACE
    if (o_use_ptrace) {
      int rc = ptrace(PTRACE_TRACEME, 0, 0, 0);
      if (rc < 0) {
        perror("ptrace(PTRACE_TRACEME)");
      }
      raise(SIGSTOP);
    }
#endif
    /* Wait for the master to release us. */
    rc = read(pfd[0], buf, 1);
    if (rc != 1) {
      if (rc == 0) {
        /* parent crashed? */
        exit(1);
      }
      perror("read");
      fprintf(stderr, "failed to read: %d\n", rc);
      exit(1);
    }
    if (buf[0] == 'N') {
      if (o_verbose) {
        fprintf(stderr, "child will not exec\n");
        exit(1);
      }
    }
    /* Switch to the command-under-test. */
    rc = execvp(argv[0], argv);
    /* If we're still here, execvp() failed. */
    perror(argv[0]);
    exit(1);
  } else if (pid > 0) {
    /* Parent process */
    close(pfd[0]);
    if (o_verbose) {
      fprintf(stderr, "pid %u (pgid=%u) forked pid %d (pgid=%u)\n",
              getpid(), getpgid(0), pid, getpgid(pid));
    }
    /* Pin the child thread to the target CPUs so we can trace it there */
    rc = sched_setaffinity(pid, sizeof target->child_cpus, &target->child_cpus);
    if (rc < 0) {
      perror("sched_setaffinity(child)");
    }
    /* The child will progress until it blocks in our post-fork code -
       either via ptrace(TRACEME) or by waiting on a pipe. */
    target->thread.tid = pid;
    target->thread.release_fd = pfd[1];
    rc = monitor_process(target);
    target->thread.tid = 0;
  } else {
    perror("failed to fork");
    rc = pid;    /* return code from fork() */
  }
  return rc;
}

/* end */


