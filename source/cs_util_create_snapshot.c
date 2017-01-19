/*
  CoreSight Access Library Utilities
   
  Set of auxiliary functions that are used by demo code but re-useable in 
  user applications. The functions cover board detection and libary registration,
  and extraction of trace data and creation of a snapshot for DS-5.

  
  Copyright (C) ARM Limited, 2015-2016. All rights reserved.

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

#include <sched.h>     /* for CPU_* family, requires glibc 2.6 or later */
#include <unistd.h>    /* for usleep() */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>


#include "csaccess.h"
#include "cs_utility.h"

#if UNIX_USERSPACE
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#endif /* UNIX_USERSPACE */



#define INVALID_ADDRESS 1   /* never a valid address */
static unsigned long snapshot_trace_start_address = INVALID_ADDRESS;
static unsigned long snapshot_trace_end_address = INVALID_ADDRESS;

static const char* get_core_name(unsigned int cpu_id)
{
    switch (cpu_id)
    {
    case 0xC05: return "Cortex-A5";
    case 0xC07: return "Cortex-A7";
    case 0xC08: return "Cortex-A8";
    case 0xC09: return "Cortex-A9";
    case 0xC0D: return "Cortex-A17";
    case 0xC0E: return "Cortex-A17";
    case 0xC0F: return "Cortex-A15";
    case 0xD03: return "Cortex-A53";
    case 0xD07: return "Cortex-A57";
    case 0xD08: return "Cortex-A72";
    }

    return "unknown";
}


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
                if(registration_verbose)
                    printf("Found kernel symbol @ 0x%lX as kernel VA\n", addr);
            }
            fclose(fd);
        }
    }
    return addr;
}

static void create_dump_ini(int index, cs_device_t device, bool zeroindex, char* name_buf, size_t name_buf_size)
{
    char buf[8192];
    char filename[32];
    sprintf(filename,"device_%d.ini",index);
    FILE* fd = fopen(filename, "w");
    if (!fd) {
        perror("can't open trace metadata output file");
    } else {
        int n;
        if (zeroindex == true) {  // handle the case of ITM_0
            n = cs_get_trace_metadata(CS_METADATA_INI, device, 0, buf, sizeof buf, name_buf, name_buf_size);
        } else {
            n = cs_get_trace_metadata(CS_METADATA_INI, device, index, buf, sizeof buf, name_buf, name_buf_size);
        }
        if (n < sizeof buf) {
            fprintf(fd, "%s", buf);
            fclose(fd);
        }
    }
}


/* Returns the physical base address of the "Kernel code" entry in "/proc/iomem".  A return value of 1 indicates failure */
#define IOMEM_BUF_SIZE 128
static unsigned long physical_kernel_code_base_address(void)
{
    FILE *fd_iomem;
    char buf[IOMEM_BUF_SIZE];
    char *next;

    if (!(fd_iomem = fopen("/proc/iomem", "r"))) {
        printf("can't open /proc/iomem\n");
        return 1;
    }

    while (fgets(buf, IOMEM_BUF_SIZE, fd_iomem))
        if (strstr(buf, "Kernel code"))
            break;

    if (feof(fd_iomem)) {
        fclose(fd_iomem);
        printf("/proc/iomem doesn't contain an entry for 'Kernel code'\n");
        return 1;
    }

    fclose(fd_iomem);

    unsigned long start = strtoul(buf, &next, 16);
    //end will be = strtoul(next + 1, NULL, 16);

    if(registration_verbose)
        printf("Kernel code entry in /proc/iomem starts at 0x%lx\n", start);

    return start;
}


int dump_kernel_memory(char const *fn, unsigned long start, unsigned long end)
{
    int err = 0;
    FILE *fd_kernel_dump;
    unsigned char *local;
    unsigned long size = end - start;

#if UNIX_USERSPACE
    int fd_mem;
    unsigned long mapstart = start & ~0xfff;
    unsigned long mapend = (end + 0xfff) & ~0xfff;
    unsigned long mapsize = mapend - mapstart;

    if (registration_verbose) {
        printf("Attempting to dump kernel memory from 0x%lX to 0x%lX\n", mapstart, mapend);
    }

    fd_mem = open("/dev/kmem", O_RDONLY);
    if (fd_mem >= 0) {
        local = (unsigned char *)mmap(0, mapsize, PROT_READ, MAP_SHARED, fd_mem, mapstart);
    } else {
        printf("can't open /dev/kmem, trying /dev/mem instead...\n");
        unsigned long pkcba = physical_kernel_code_base_address();
        if (pkcba == 1) {
            printf("can't read the physical kernel code base address from /proc/iomem\n");
            local = MAP_FAILED;
        } else {
            fd_mem = open("/dev/mem", O_RDONLY);
            if (fd_mem >= 0) {
                unsigned long kernel_va = kernel_virtual_address();
                if(registration_verbose)
                    printf("Using 0x%lX as mapping address, 0x%lX size\n",(mapstart-kernel_va+pkcba), mapsize );
                local = (unsigned char *)mmap(0, mapsize, PROT_READ, MAP_SHARED, fd_mem, (mapstart-kernel_va+pkcba));
                close(fd_mem);
            } else {
                printf("can't open /dev/mem either\n");
                local = MAP_FAILED;
            }
        }
    }

    if (local == MAP_FAILED) {
        printf("Cannot mmap device at 0x%lx, errno=%d\n", mapstart, errno);
        printf("so cannot dump kernel memory automatically to the file kernel_dump.bin.\n");
        printf("This may be because the kernel has been built with CONFIG_STRICT_DEVMEM set.\n");
        printf("Try rebuilding the kernel without this flag, alternatively:\n");
        printf("1) Use DS-5 Debugger to dump this kernel memory from the target\n");
        printf("2) Extract this kernel memory from the kernel Image\n");
        printf("Program execution will now continue to generate the other necessary files...\n\n");
        err = 1;
    } else {  /* mmap() succeeded */
        fd_kernel_dump = fopen(fn, "wb");
        if (fd_kernel_dump) {
            fwrite(local + (start & 0xfff), size, 1, fd_kernel_dump);
            fclose(fd_kernel_dump);
        } else {
            err = 1;
        }
    }
    close(fd_mem);

#else /* for bare-metal */
    local = (unsigned char *)start;
    fd_kernel_dump = fopen(fn, "wb");
    if (fd_kernel_dump) {
        fwrite(local, size, 1, fd_kernel_dump);
        fclose(fd_kernel_dump);
    } else {
        err = 1;
    }
#endif /* UNIX_USERSPACE */
    return err;
}


static void do_fetch_trace_etb(cs_device_t etb, char const *name, char const *file_name)
{
    int len, n;

    if (file_name == NULL) {
        file_name = "cstrace.bin";
    }
    if(registration_verbose)
        printf("CSUTIL: Fetching trace from %s ETB:\n", name);
    len = cs_get_buffer_unread_bytes(etb);
    if(registration_verbose) {
        printf("  Buffer RAM size: %d\n", cs_get_buffer_size_bytes(etb));
        printf("  Bytes to read in buffer: %d\n", len);
        printf("  Buffer has wrapped: %d\n", cs_buffer_has_wrapped(etb));
    }
    unsigned char *buf = (unsigned char *)malloc(len);
    n = cs_get_trace_data(etb, buf, len);
    if (n <= 0) {
        fprintf(stderr, "** failed to get trace, rc=%d\n", n);
    } else if (n < len) {
        fprintf(stderr, "** got incomplete trace, %d < %d\n", n, len);
    } else {
        FILE *fd;
        int i;
        int todo = n;
        if (todo > 256) {
            todo = 256;
        }
        if(registration_verbose) {
            printf("** %d bytes of trace\n", n);
            printf("The first %d bytes of trace are:\n", todo);
            for (i = 0; i < todo; ++i) {
                printf(" %02X", ((unsigned char *)buf)[i]);
                if ((i % 32) == 31 || (i == todo-1))
                    printf("\n");
                else if ((i % 32) == 15)
                    printf(" ");
            }
        }

        fd = fopen(file_name, "wb");
        if (!fd) {
            perror("can't open trace output");
        } else {
            fwrite(buf, n, 1, fd);
            fclose(fd);
        }
    }
}

/********************** API functions *****************************/

void do_dump_config(const struct board *board, const struct cs_devices_t *devices, int do_dump_swstim)
{
    int i, index = 0;
    int aarch64;
    unsigned int CPSR_VAL, SCTLR_EL1_val;
    int dumped_kernel;
    int separate_itm_buffer;

#ifdef CS_VA64BIT
    aarch64 = 1;
    CPSR_VAL = 0x1C5;
    SCTLR_EL1_val = 0x1007;   /* fake value to let debugger figure memory endianness (little in this case) */
#else
    aarch64=0;
    CPSR_VAL = 0x1D3;
    SCTLR_EL1_val = 0;    /* not really used here */
#endif

    // Top level contents file
    FILE *fdContents = fopen("snapshot.ini", "w");

    fputs("[snapshot]\n", fdContents);
    fputs("version=1.0\n\n", fdContents);

    fputs("[device_list]\n", fdContents);

    dumped_kernel = !dump_kernel_memory("kernel_dump.bin", snapshot_trace_start_address, snapshot_trace_end_address);

    // CPU state
    // Create separate files for each device
    for (i = 0; i < board->n_cpu; ++i) {
        FILE *fdCore;
        char fname[20];
        fprintf(fdContents, "device%u=cpu_%u.ini\n", index, i);
        index++;
        sprintf(fname, "cpu_%u.ini", i);
        fdCore = fopen(fname, "w");
        fputs("[device]\n", fdCore);
        fprintf(fdCore, "name=cpu_%u\n", i);
        fputs("class=core\n", fdCore);
        fprintf(fdCore, "type=%s\n\n", get_core_name(devices->cpu_id[i]));
        fputs("[regs]\n", fdCore);    /* Some basic register information is needed */
        if(aarch64) {
            fprintf(fdCore, "PC(size:64)=0x%lX\n", snapshot_trace_start_address);
            fputs("SP(size:64)=0\n", fdCore);
            fprintf(fdCore, "SCTLR_EL1=0x%X\n", SCTLR_EL1_val);
        }
        else {
            fprintf(fdCore, "R15=0x%lX\n", snapshot_trace_start_address);
            fputs("R13=0\n", fdCore);
        }
        fprintf(fdCore, "CPSR=0x%X\n", CPSR_VAL);

        if (dumped_kernel) {
            fputs("\n[dump1]\n",fdCore);
            fputs("file=kernel_dump.bin\n",fdCore);
            fprintf(fdCore, "address=0x%08lX\n", snapshot_trace_start_address);
            fprintf(fdCore, "length=0x%08lX\n\n", snapshot_trace_end_address - snapshot_trace_start_address);
        }

        fclose(fdCore);
    }

    // CPU PTMs
    char ptm_names[LIB_MAX_CPU_DEVICES][32];
    for (i = 0; i < board->n_cpu; ++i) {
        create_dump_ini(index, devices->ptm[i], false, ptm_names[i], 32);
        fprintf(fdContents, "device%d=device_%d.ini\n", index, index);
        index++;
    }

    // ITM/STM
    char itm_name[32];
    if (do_dump_swstim) {
        create_dump_ini(index,devices->itm, false, itm_name, 32);
        fprintf(fdContents, "device%d=device_%d.ini\n", index, index);
        index++;
    }
    fputs("\n", fdContents);

    // Add trace dump to snapshot.ini
    fputs("\n[trace]\n",fdContents);
    fputs("metadata=trace.ini\n", fdContents);

    fclose(fdContents);

    // Assumes single ETB for all cores
    FILE* fd_trace_ini = fopen("trace.ini","w");

    // Generate comma separated list of buffers
    separate_itm_buffer = (devices->itm_etb != NULL && do_dump_swstim);
    fputs("[trace_buffers]\n", fd_trace_ini);
    fputs("buffers=buffer0", fd_trace_ini);
    if (separate_itm_buffer) {
        fputs(",buffer1", fd_trace_ini);
    }
    fputs("\n\n", fd_trace_ini);

    // Trace buffers
    fputs("[buffer0]\n", fd_trace_ini);
    fputs("name=ETB_0\n", fd_trace_ini);
    fputs("file=cstrace.bin\n", fd_trace_ini);
    fputs("format=coresight\n\n", fd_trace_ini);

    if (separate_itm_buffer) {
        fputs("[buffer1]\n", fd_trace_ini);
        fputs("name=ETB_1\n", fd_trace_ini);
        fputs("file=cstraceitm.bin\n", fd_trace_ini);
        fputs("format=coresight\n\n", fd_trace_ini);
    }

    // source to buffer mapping
    fputs("[source_buffers]\n", fd_trace_ini);
    for (i = 0; i < board->n_cpu; ++i) {
        fprintf(fd_trace_ini, "%s=%s\n", ptm_names[i], "ETB_0");
    }
    if (do_dump_swstim) {
        if (devices->itm_etb != NULL) {
            fprintf(fd_trace_ini, "%s=ETB_1\n", itm_name);
        }
        else {
            fprintf(fd_trace_ini, "%s=ETB_0\n", itm_name);
        }
    }
    fputs("\n", fd_trace_ini);

    // core to source mapping
    fputs("[core_trace_sources]\n", fd_trace_ini);
    for (i = 0; i < board->n_cpu; ++i) {
        fprintf(fd_trace_ini, "cpu_%d=%s\n", i, ptm_names[i]);
    }

    fclose(fd_trace_ini);

    if(registration_verbose)
        printf("CSUTIL: Created trace configuration export files\n");
}

void do_fetch_trace(const struct cs_devices_t *devices, int do_dump_swstim)
{
    if(devices->etb != NULL) {
        do_fetch_trace_etb(devices->etb, "core", "cstrace.bin");
    }
    if ((devices->itm_etb != NULL) && (do_dump_swstim != 0)) {
        do_fetch_trace_etb(devices->itm_etb, "ITM/STM", "cstraceitm.bin");
    }
}

void set_kernel_trace_dump_range(unsigned long start, unsigned long end)
{
    snapshot_trace_start_address = start;
    snapshot_trace_end_address = end;
}
