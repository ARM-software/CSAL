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

static int cs_memap_set_access_size_bytes(struct cs_device *d, unsigned int size)
{
    uint32_t csw, ncsw, csw_size;

    assert(size == 4 || size == 8);
    if (size == 8 && !d->v.memap.data_64bit) {
        return cs_report_device_error(d, "MEM-AP does not support 64-bit transfers");
    }
    if (d->v.memap.access_size_valid && d->v.memap.current_access_size == size) {
        return 0;
    }

    csw_size = size == 8 ? CS_MEMAP_CSW_SIZE_64 : CS_MEMAP_CSW_SIZE_32;
    csw = _cs_read(d, CS_MEMAP_CSW);
    ncsw = (csw & ~CS_MEMAP_CSW_SIZE_MASK) | csw_size;
    if (ncsw != csw) {
        int rc = _cs_write(d, CS_MEMAP_CSW, ncsw);
        if (rc) {
            d->v.memap.access_size_valid = 0;
            return rc;
        }
    }

    d->v.memap.current_access_size = size;
    d->v.memap.access_size_valid = 1;
    return 0;
}

/*
 * Prepare to read from or write to an address in the MEM-AP's address space,
 * and return a suitable register offset.
 *
 * Note: this deals with 32-bit and 64-bit aligned accesses only.
 */
static int cs_memap_prepare(struct cs_device *d, cs_physaddr_t addr,
                             unsigned int access_size, unsigned int *p_reg)
{
    cs_physaddr_t base;
    unsigned int reg;
    int rc;

    if ((addr & (access_size - 1)) != 0) {
        return cs_report_device_error(d,
                                      "unaligned MEM-AP %u-bit access at %" CS_PHYSFMT,
                                      access_size * 8, addr);
    }
    rc = cs_memap_set_access_size_bytes(d, access_size);
    if (rc) {
        return rc;
    }
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
        rc = cs_memap_write_TAR(d, base);
        if (rc) {
            return rc;
        }
    }
    *p_reg = reg;
    return 0;
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
    unsigned int reg;
    if (cs_memap_prepare(d, addr, 4, &reg)) {
        return 0;
    }
    return _cs_read(d, reg);
}


uint64_t cs_memap_read64(cs_device_t dev, cs_physaddr_t addr)
{
    struct cs_device *d = DEV(dev);
    if (!d->v.memap.data_64bit) {
        uint32_t lo = cs_memap_read32(dev, addr);
        uint32_t hi = cs_memap_read32(dev, addr + 4);
        return ((uint64_t)hi << 32) | lo;
    } else {
        unsigned int reg;
        if (cs_memap_prepare(d, addr, 8, &reg)) {
            return 0;
        }
        return _cs_read64(d, reg);
    }
}


/*
 * Write data to a memory location, via a MEM-AP.
 */
int cs_memap_write32(cs_device_t dev, cs_physaddr_t addr, uint32_t data)
{
    struct cs_device *d = DEV(dev);
    unsigned int reg;
    if (cs_memap_prepare(d, addr, 4, &reg)) {
        return -1;
    }
    return _cs_write(d, reg, data);
}


int cs_memap_write64(cs_device_t dev, cs_physaddr_t addr, uint64_t data)
{
    struct cs_device *d = DEV(dev);
    unsigned int reg;

    if (!d->v.memap.data_64bit) {
        int rc = cs_memap_write32(dev, addr, (uint32_t)data);
        if (rc) {
            return rc;
        }
        return cs_memap_write32(dev, addr + 4, (uint32_t)(data >> 32));
    }
    if (cs_memap_prepare(d, addr, 8, &reg)) {
        return -1;
    }
    return _cs_write64(d, reg, data);
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
int cs_memap_write_TAR(cs_device_t dev, cs_physaddr_t addr)
{
    int rc;
    struct cs_device *d = DEV(dev);
    rc = _cs_write(d, CS_MEMAP_TAR, addr);
    if (rc) {
        return rc;
    }
#ifdef LPAE
    if (d->v.memap.memap_LPAE) {
        rc = _cs_write(d, CS_MEMAP_TARHI, (addr >> 32));
        if (rc) {
            d->v.memap.TAR_valid = 0;
            return rc;
        }
    }
#endif
    d->v.memap.cached_TAR = addr;
    d->v.memap.TAR_valid = 1;
    return 0;
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
        _cs_write(d, CS_MEMAP_TRR, CS_MEMAP_TRR_ERR); /* write the flag to clear it */
    }
    return error_logged;
}

/* end of cs_memap.c */
