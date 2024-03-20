/*!
 * \file       cs_map_local.c
 * \brief      CS Access Library - map devices into local memory - not exposed through API
 *
 * \copyright  Copyright (C) ARM Limited, 2014-2024. All rights reserved.
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


#include "cs_access_cmnfns.h"

#ifdef UNIX_USERSPACE
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#endif /* UNIX_USERSPACE */

#define UNUSED_PARAMETER(x) ((void)(x))


/*
  Map a region (generally 4K) of physical memory, returning an address
  usable by the caller - a virtual address in the case of non-baremetal.
  Return NULL if unsuccessful.
*/
void *io_map(cs_physaddr_t addr, unsigned int size, int writable)
{
    void *localv;
    assert(size > 0);
    assert((addr % 4096) == 0);
#ifdef UNIX_USERSPACE
#ifndef USE_DEVMEMD
    cs_physaddr_t addr_to_map = addr;   /* may be rounded down to phys page size */
    {
        unsigned int pagesize = sysconf(_SC_PAGESIZE);
        if (size < pagesize) {
             size = pagesize;
        }
        if ((addr % pagesize) != 0) {
            addr_to_map -= (addr % pagesize);
        }
    }
    localv = mmap(0, size, (writable ? (PROT_READ | PROT_WRITE) : PROT_READ),
         MAP_SHARED, G.mem_fd, addr_to_map);
    if (localv == MAP_FAILED) {
        return NULL;
    }
    localv = (unsigned char *) localv + (addr - addr_to_map);
#else
    /* When using devmemd, the local address is not used, but must be non-zero. */
    localv = (unsigned char *)0xBAD;
#endif
#elif defined(UNIX_KERNEL)
    UNUSED_PARAMETER(writable);
    localv = ioremap(addr, size);
#else
    /* Bare-metal: the caller directly accesses the physical memory.
       Note that the combination of BAREMETAL and LPAE is not supported
       with a 32-bit target, and will likely error here when trying to
       cast a 64-bit cs_physaddr_t to a pointer. */
    UNUSED_PARAMETER(writable);
    UNUSED_PARAMETER(size);
    localv = (void *)addr;
#endif
    return localv;
}


int _cs_map(struct cs_device *d, int writable)
{
    d->local_addr = (unsigned char volatile *)io_map(d->phys_addr, 4096, writable);
    return d->local_addr != NULL;
}


void io_unmap(void volatile *addr, unsigned int size)
{
#ifdef UNIX_USERSPACE
#ifndef USE_DEVMEMD
    (void)munmap((void *)addr, size);
#endif
#elif defined(UNIX_KERNEL)
    UNUSED_PARAMETER(size);
    iounmap(addr);
#else
    UNUSED_PARAMETER(addr);
    UNUSED_PARAMETER(size);
    /* do nothing */
#endif
}


void _cs_unmap(struct cs_device *d)
{
    if (d->local_addr) {
        io_unmap(d->local_addr, 4096);
    }
}

/* end of cs_map_local.c */
