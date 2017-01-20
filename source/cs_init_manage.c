/*
  On-target userspace CoreSight access library implementation

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

#include "csaccess.h"
/* Now one of UNIX_USERSPACE, UNIX_KERNEL or BAREMETAL will have been defined. */

#include "csregisters.h"

/* Include all the common internal types and function declarations */
#include "cs_access_cmnfns.h"


/* *** init and management API *** */
int cs_init(void)
{
    memset(&G, 0, sizeof(struct global));

#ifdef UNIX_USERSPACE
    int fd = open("/dev/mem", O_RDWR);
    if (fd < 0) {
        G.mem_fd = -1;
        return cs_report_error("can't open /dev/mem");
    }
    G.mem_fd = fd;
#endif				/* UNIX_USERSPACE */
    G.init_called = 1;
    G.registration_open = 1;
    G.force_writes = 1;		/* While we're debugging it... */
#if CHECK
    G.diag_checking = 1;
#else
    G.diag_checking = 0;
#endif				/* CHECK */

    G.diag_tracing_default = 0;	/* tracing off by default */

#ifdef LPAE
    G.phys_addr_lpae = 1;	/* 1 if built with LPAE */
#else
    G.phys_addr_lpae = 0;
#endif

#ifdef CS_VA64BIT
    G.virt_addr_64bit = 1;
#else
    G.virt_addr_64bit = 0;
#endif

    return 0;
}

int cs_diag_set(int n)
{
#ifdef DIAG
    G.diag_tracing_default = n;
#endif				/* DIAG */
    return 0;
}


/*
  Call this when the library is unloaded.  This doesn't generally disable
  all trace devices, but it may lock them.
*/
int cs_shutdown(void)
{
    if (G.init_called) {
        /* Do anything that needs memory-mapped access */
        cs_checkpoint();
#ifdef UNIX_USERSPACE
        /* Now remove memory-mapped access */
        close(G.mem_fd);
        G.mem_fd = 0;
#endif				/* UNIX_USERSPACE */
        G.init_called = 0;
        G.registration_open = 0;
    }
    while (G.device_top != NULL) {
        struct cs_device *d = G.device_top;
        G.device_top = d->next;
        if (d->ops.unregister)
            d->ops.unregister(d);
        free(d);
    }
    while (G.exclusions != NULL) {
        struct addr_exclude *a = G.exclusions;
        G.exclusions = a->next;
        free(a);
    }
    return 0;
}

int cs_release(void)
{
    /* Release all CoreSight devices.  The system is now in a state where
       an external debugger has complete control (at least over trace devices
       and cross-triggering, not necessarily CPU hardware breakpoints). */
    struct cs_device *d;
    for (d = G.device_top; d != NULL; d = d->next) {
        if (_cs_isclaimed(d, CS_CLAIM_INTERNAL)) {
            if (DTRACE(d)) {
                diagf("!unclaiming device at %" CS_PHYSFMT "",
                      d->phys_addr);
            }
            _cs_unclaim(d, CS_CLAIM_INTERNAL);
        }
    }
    return 0;
}

unsigned int cs_error_count(void)
{
    return G.n_api_errors;
}

/*
  Device programming
*/
int cs_checkpoint(void)
{
    struct cs_device *d;
    for (d = G.device_top; d != NULL; d = d->next) {
        if (!cs_device_is_non_mmio(d) && !d->is_permanently_unlocked) {
            _cs_lock(d);
        }
    }
    return 0;
}

unsigned short cs_library_version()
{
    return (((unsigned short) CS_LIB_VERSION_MAJ & 0xFF) << 8) |
        ((unsigned short) CS_LIB_VERSION_MIN & 0xFF);
}


/* *** ==================== *** */

/* end of csaccess.c */
