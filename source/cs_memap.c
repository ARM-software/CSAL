/*!
 * \file       cs_memap.c
 * \brief      CS Access API - access MEM-AP devices
 *
 * Only basic features of MEM-AP are provided, primarily aimed at when
 * we need to access other CoreSight devices via a MEM-AP.
 *
 * \copyright  Copyright (C) ARM Limited, 2021. All rights reserved.
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
#include "cs_memap.h"

/*
 * Prepare to read from or write to an address in the MEM-AP's address space,
 * and return a suitable register offset.
 *
 * Note: this deals with word-aligned access only.
 */
static unsigned int cs_memap_prepare(struct cs_device *d, cs_physaddr_t addr)
{
    cs_physaddr_t base;
    unsigned int reg;
    if (0 && DTRACE(d)) {
        diagf("!MEM-AP 0x%lx\n", (unsigned long)addr);
    }
    if (d->v.memap.DAR_present) {
        /* Use one of the 256 Direct Access Registers */
        base = addr & ~0x3ff;
        reg = CS_MEMAP_DAR0 + (addr - base);
    } else {
        /* Use one of the four banked data registers */
        base = addr & ~0xf;
        reg = CS_MEMAP_BD0 + (addr - base);
    }
    if (!d->v.memap.TAR_valid || d->v.memap.cached_TAR != base) {
        cs_memap_write_TAR(d, base);
    }
    return reg;
}


void cs_memap_invalidate_TAR(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    d->v.memap.TAR_valid = 0;
}


/*
 * Read from a memory location, via a MEM-AP.
 */
uint32_t cs_memap_read32(cs_device_t dev, cs_physaddr_t addr)
{
    struct cs_device *d = DEV(dev);
    unsigned int reg = cs_memap_prepare(d, addr);
    return _cs_read(d, reg);
}

/*
 * Write data to a memory location, via a MEM-AP.
 */
void cs_memap_write32(cs_device_t dev, cs_physaddr_t addr, uint32_t data)
{
    struct cs_device *d = DEV(dev);
    unsigned int reg = cs_memap_prepare(d, addr);
    _cs_write(d, reg, data);
}



/*
 * Get the current value of the TAR
 */
cs_physaddr_t cs_memap_read_TAR(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    cs_physaddr_t tar = _cs_read(d, CS_MEMAP_TAR);
#ifdef LPAE
    if (d->v.memap.memap_LPAE) {
        tar |= (((cs_physaddr_t)_cs_read(d, CS_MEMAP_TARHI)) << 32);
    }
#endif
    return tar;
}


/*
 * Set the current value of the TAR
 */
void cs_memap_write_TAR(cs_device_t dev, cs_physaddr_t addr)
{
    struct cs_device *d = DEV(dev);
    _cs_write(d, CS_MEMAP_TAR, addr);
#ifdef LPAE
    if (d->v.memap.memap_LPAE) {
        _cs_write(d, CS_MEMAP_TARHI, (addr >> 32));
    }
#endif
    d->v.memap.cached_TAR = addr;
    d->v.memap.TAR_valid = 1;
}


/*
 * Check for, and optionally reset, a transfer error
 */
int cs_memap_check_error(cs_device_t dev, int reset)
{
    struct cs_device *d = DEV(dev);
    uint32_t trr = _cs_read(d, CS_MEMAP_TRR);
    int error_logged = (trr & CS_MEMAP_TRR_ERR);
    if (reset && error_logged) {
        _cs_write(d, CS_MEMAP_TRR, CS_MEMAP_TRR_ERR);   /* write the flag to clear it */
    }
    return error_logged;
}

/* end of cs_memap.c */
