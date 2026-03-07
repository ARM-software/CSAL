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

#ifdef UNIX_USERSPACE
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#endif /* UNIX_USERSPACE */


/* *** init and management API *** */
int cs_init(void)
{
    memset(&G, 0, sizeof(struct cs_global));

#ifdef UNIX_USERSPACE
#ifndef USE_DEVMEMD
    {
        int fd = open("/dev/mem", O_RDWR);
        if (fd < 0) {
            G.mem_fd = -1;
            return cs_report_error("can't open /dev/mem");
        }
        G.mem_fd = fd;
    }
#else
    devmemd_init();
#endif
#endif /* UNIX_USERSPACE */
    G.init_called = 1;
    G.registration_open = 1;
    G.force_writes = 1; /* While we're debugging it... */
#if CHECK
    G.diag_checking = 1;
#else
    G.diag_checking = 0;
#endif /* CHECK */
#ifndef CS_EXTERNAL
    G.claim_external = 0;
#else
    G.claim_external = CS_EXTERNAL;
#endif /* CS_EXTERNAL */

    G.diag_tracing_default = 0; /* tracing off by default */

#ifdef LPAE
    G.phys_addr_lpae = 1; /* 1 if built with LPAE */
#else
    G.phys_addr_lpae = 0;
#endif

#ifdef CS_VA64BIT
    G.virt_addr_64bit = 1;
#else
    G.virt_addr_64bit = 0;
#endif

#ifdef CSAL_MEMAP
    G.memap_default = NULL;
#endif

    return 0;
}

int cs_diag_set(int n)
{
#ifdef DIAG
    G.diag_tracing_default = n;
    if (n > 0) {
        diagf("CSAL: tracing set to level %d\n", n);
    }
#else  /* !DIAG */
    if (n > 0) {
        /* Attempts to enable diagnostics when not compiled in -
           we might not have I/O, but we can at least return a fault indication. */
        return -1;
    }
#endif /* DIAG */
    return 0;
}


#ifdef __STDC_HOSTED__
int cs_diag_set_fd(FILE *fd)
{
#ifdef DIAG
    G.diag_fd = fd;
#endif
    return 0;
}
#endif


#ifdef CSAL_MEMAP
void cs_set_default_memap(cs_device_t dev)
{
    if (dev) {
        assert(cs_device_has_class(dev, CS_DEVCLASS_MEMAP));
        if (DTRACEG) {
            diagf("!Set default MEM-AP\n");
        }
        _cs_claim(DEV(dev));
    }
    G.memap_default = dev;
}
#endif


/*
  Call this when the library is unloaded.  This doesn't generally disable
  all trace devices, but it may lock them and release claim-tags.
*/
int cs_shutdown(void)
{
#ifdef DIAG
    if (DTRACEG) {
        diagf("!shutdown\n");
    }
#endif
    if (G.init_called) {
        /* Do anything that needs memory-mapped access */
        cs_release();    /* claim tags released here */
        cs_checkpoint(); /* devices relocked here */
#ifdef UNIX_USERSPACE
        /* Now remove memory-mapped access */
        close(G.mem_fd);
        G.mem_fd = 0;
#endif /* UNIX_USERSPACE */
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


/* There are conflicting claim tag conventions in use - see csregisters.h.
   Return the appropriate internal claim tag for the given device. */
uint32_t _cs_device_claim_tag(struct cs_device *d)
{
    if (cs_device_has_class(d, CS_DEVCLASS_MEMAP)) {
        return G.claim_external ? CS_CLAIM_AP_EXTERNAL : CS_CLAIM_AP_INTERNAL;
    } else {
        return G.claim_external ? CS_CLAIM_DEV_EXTERNAL : CS_CLAIM_DEV_INTERNAL;
    }
}


int _cs_claim(struct cs_device *d)
{
    int rc = 0;
    if (!d->is_claimed) {
        rc = _cs_claim_tag(d, _cs_device_claim_tag(d));
        d->is_claimed = 1;
    }
    return rc;
}


int _cs_unclaim(struct cs_device *d)
{
    int rc = 0;
    if (d->is_claimed) {
        rc = _cs_unclaim_tag(d, _cs_device_claim_tag(d));
        d->is_claimed = 0;
    }
    return rc;
}


/*
 * Check if this device is powered.
 * For some devices types, in some configurations, we can inspect
 * an always-on register.
 *  - CPU debug, without FEAT_DoPD, we can read DBGPRSR
 *  - ETM/ETE, without FEAT_DoPD
 * Return -1 if power status is unknown.
 */
int _cs_device_is_powered(struct cs_device *d)
{
    if (cs_device_has_class(d, CS_DEVCLASS_DEBUG)) {
        uint32_t edprsr = _cs_read(d, CS_DBGPRSR);
        return (edprsr & 1) == 1;
    } else if (cs_device_has_class(d, CS_DEVCLASS_SOURCE | CS_DEVCLASS_CPU)) {
        uint32_t edpdsr = _cs_read(d, CS_ETMPDSR);
        return (edpdsr & 1) == 1;
    } else {
        return CS_POWER_UNKNOWN;
    }
}


int cs_device_is_powered(cs_device_t dev)
{
    return _cs_device_is_powered(DEV(dev));
}


int cs_release(void)
{
    /* Release all CoreSight devices.  The system is now in a state where
       an external debugger has complete control (at least over trace devices
       and cross-triggering, not necessarily CPU hardware breakpoints). */
#ifdef DIAG
    if (DTRACEG) {
        diagf("!device release\n");
    }
#endif
    struct cs_device *d;
    for (d = G.device_top; d != NULL; d = d->next) {
        if (!d->is_claimed) {
            /* Nothing to do, and don't try to access the device,
               as the caller may have cleaned up and established a
               situation where device access is not permitted */
            continue;
        }
        /* For certain devices, we might have been able to create
           the device object, but then found that the device is
           powered down. E.g. CPU debug interfaces. In this case,
           reading the claim tag will likely lock up. */
        if (_cs_device_is_powered(d) == CS_POWER_OFF) {
            continue;
        }
        _cs_unclaim(d);
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
#ifdef DIAG
    if (DTRACEG) {
        diagf("!device re-lock\n");
    }
#endif
    for (d = G.device_top; d != NULL; d = d->next) {
        if (cs_device_is_non_mmio(d)) {
            continue;
        }
        if (d->is_permanently_unlocked) {
            continue;
        }
        if (!d->is_unlocked) {
            continue;
        }
        _cs_lock(d);
    }
    return 0;
}

unsigned short cs_library_version()
{
    return (((unsigned short)CS_LIB_VERSION_MAJ & 0xFF) << 8) |
           ((unsigned short)CS_LIB_VERSION_MIN & 0xFF);
}


/* *** ==================== *** */

/* end of cs_init_manage.c */
