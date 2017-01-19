/*
  Memory-mapped access to CPU PMU registers.

  Copyright (C) 2014-2016 ARM Ltd. All rights reserved.

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

#include "cs_access_cmnfns.h"
#include "cs_pmu.h"
#include "cs_topology.h"

int cs_pmu_n_counters(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    assert(cs_device_has_class(dev, CS_DEVCLASS_PMU));
    return d->v.pmu.n_counters;
}


static cs_pmu_mask_t cs_pmu_mask(struct cs_device const *d)
{
    return CS_PMU_MASK_CYCLES |
        (((cs_pmu_mask_t) 1U << d->v.pmu.n_counters) - 1);
}


int cs_pmu_get_counts(cs_device_t dev, unsigned int mask,
                      unsigned int *cycles, unsigned int *counts,
                      unsigned int *overflow)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_CPU_PMU);
    if (cycles != NULL) {
        if (d->v.pmu.map_scale == 2) {
            *cycles = _cs_read(d, CS_PMCCNTR);
        } else {
            /* The architecture doesn't guarantee single-copy atomic access,
               and recommends a high-low-high read sequence. */
            *cycles = (unsigned int) _cs_read64(d, CS_PMEVCNTR64(31));
        }
    }
    if (overflow != NULL) {
        /* Read the overflow bits first.  Our assumption is that counters
           are sampled reasonably frequently and the overflow flag is reset
           once seen.  So if we see an overflow then we expect the count
           to be near zero.  (We could check for this.)
           The problem with reading it the other way round is we end up
           reading a sequence such as
           count=0xFFFFE000
           overflow=0
           count=0xFFFFF000
           (overflows between reading the count and the flags)
           overflow=1
           which looks like we've read more than 2**32 counts. */
        unsigned int oflow = _cs_read(d, CS_PMOVSR);
        *overflow = oflow;
        if (oflow != 0) {
            /* Write these flags back, to reset the overflow flags.
               This requires the PMU to be in unlocked state. */
            _cs_write_wo(d, CS_PMOVSR, oflow);
            if ((_cs_read(d, CS_PMOVSR) & oflow) != 0) {
                /* If we failed to reset some of those flags, then we might not have
                   write access to the PMU. */
                _cs_unlock(d);
                _cs_write_wo(d, CS_PMOVSR, oflow);
                assert((_cs_read(d, CS_PMOVSR) & oflow) == 0);
                /* As we're likely to be repeatedly sampling the PMU, we don't
                   re-lock it, so we should take the fast path next time. */
            }
        }
    }
    if (counts != NULL) {
        unsigned int i, j;
        mask &= (1U << d->v.pmu.n_counters) - 1;
        for (i = 0, j = 0; mask != 0; ++i) {
            if ((mask & 1) != 0) {
                counts[j++] =
                    _cs_read(d, CS_PMEVCNTR(i, d->v.pmu.map_scale));
            }
            mask >>= 1;
        }
    }
    return 0;
}


int cs_pmu_read_status(cs_device_t dev, unsigned int flags,
                       cs_pmu_t * status)
{
    struct cs_device *d = DEV(dev);
    unsigned int pmcr = 0;

    assert(d->type == DEV_CPU_PMU);
    if (flags & (CS_PMU_DISABLE | CS_PMU_DIV64 | CS_PMU_ENABLE)) {
        pmcr = _cs_read(d, CS_PMCR);
        if (flags & CS_PMU_DISABLE) {
            _cs_write(d, CS_PMCR, pmcr & ~CS_PMCR_E);
        }
    }
    if (flags & CS_PMU_CYCLES) {
        if (d->v.pmu.map_scale == 2) {
            status->cycles = _cs_read(d, CS_PMCCNTR);
        } else {
            status->cycles = _cs_read64(d, CS_PMEVCNTR64(31));
        }
    }
    if (flags & CS_PMU_DIV64) {
        status->div64 = (pmcr & CS_PMCR_D) != 0;
    }
    if (flags & CS_PMU_OVERFLOW) {
        status->overflow = _cs_read(d, CS_PMOVSR);
    }
    /* Mask off the unimplemented counters bits - but leave the cycle counter. */
    status->mask &= cs_pmu_mask(d);
    if (flags & (CS_PMU_EVENTTYPES | CS_PMU_COUNTS)) {
        unsigned int i;
        cs_pmu_mask_t mask = status->mask;
        for (i = 0; i < 31 && mask != 0; ++i) {
            if (mask & 1) {
                if (flags & CS_PMU_EVENTTYPES) {
                    status->eventtypes[i] = _cs_read(d, CS_PMXEVTYPER(i));
                }
                if (flags & CS_PMU_COUNTS) {
                    status->counts[i] =
                        _cs_read(d, CS_PMEVCNTR(i, d->v.pmu.map_scale));
                }
            }
            mask >>= 1;
        }
    }
    if (flags & CS_PMU_ENABLE) {
        _cs_write(d, CS_PMCR, pmcr | CS_PMCR_E);
    }
    return 0;
}


int cs_pmu_write_status(cs_device_t dev, unsigned int flags,
                        cs_pmu_t const *status)
{
    struct cs_device *d = DEV(dev);
    unsigned int pmcr = 0;	/* Init for compiler benefit only - alwasy read/modify/write */
    assert(d->type == DEV_CPU_PMU);

    _cs_unlock(d);
    if (flags & (CS_PMU_DISABLE | CS_PMU_DIV64 | CS_PMU_ENABLE)) {
        pmcr = _cs_read(d, CS_PMCR);
        if (flags & CS_PMU_DISABLE) {
            _cs_write(d, CS_PMCR, pmcr & ~CS_PMCR_E);
        }
    }
    if (flags & (CS_PMU_EVENTTYPES | CS_PMU_COUNTS)) {
        unsigned int i;
        cs_pmu_mask_t mask = status->mask;
        for (i = 0; i <= 31 && mask != 0; ++i) {
            if (mask & 1) {
                if (flags & CS_PMU_EVENTTYPES) {
                    _cs_write(d, CS_PMXEVTYPER(i), status->eventtypes[i]);
                }
                if (flags & CS_PMU_COUNTS) {
                    _cs_write(d, CS_PMEVCNTR(i, d->v.pmu.map_scale),
                              status->counts[i]);
                }
            }
            mask >>= 1;
        }
    }
    if (flags & CS_PMU_CYCLES) {
        if (d->v.pmu.map_scale == 2) {
            _cs_write(d, CS_PMCCNTR, status->cycles);
        } else {
            _cs_write64(d, CS_PMEVCNTR64(31), status->cycles);
        }
    }
    if (flags & CS_PMU_ENABLE) {
        pmcr |= CS_PMCR_E;
        /* Should we also set CS_PMCNTENSET? */
    }
    if (flags & CS_PMU_DIV64) {
        pmcr = (pmcr & ~0x08) | (status->div64 << 3);
    }
    if (flags & (CS_PMU_ENABLE | CS_PMU_DIV64)) {
        _cs_write(d, CS_PMCR, pmcr);
    }
    return 0;
}


int cs_pmu_reset(cs_device_t dev, unsigned int flags)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_CPU_PMU);
    _cs_unlock(d);
    if (flags & CS_PMU_ENABLE) {
        /* If we're going to enable the PMU, enable all its counters.
           Read-back should show that exactly these counters are now enabled. */
        _cs_write(d, CS_PMCNTENSET, cs_pmu_mask(d));
    }
    if (flags &
        (CS_PMU_CYCLES | CS_PMU_COUNTS | CS_PMU_ENABLE | CS_PMU_DISABLE)) {
        unsigned int pmcr = _cs_read(d, CS_PMCR);
        if (flags & CS_PMU_CYCLES) {
            pmcr |= CS_PMCR_C;
        }
        if (flags & CS_PMU_COUNTS) {
            pmcr |= CS_PMCR_P;
        }
        if (flags & CS_PMU_ENABLE) {
            pmcr |= CS_PMCR_E;
        }
        if (flags & CS_PMU_DISABLE) {
            pmcr &= ~CS_PMCR_E;
        }
        _cs_write_wo(d, CS_PMCR, pmcr);
    }
    if (flags & CS_PMU_OVERFLOW) {
        _cs_write_wo(d, CS_PMOVSR, cs_pmu_mask(d));
    }
    return 0;
}


int cs_pmu_bus_export(cs_device_t dev, int enable)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_CPU_PMU);
    _cs_unlock(d);
    return _cs_set_bit(d, CS_PMCR, CS_PMCR_X, enable);
}


int cs_pmu_is_enabled(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_CPU_PMU);
    return _cs_isset(d, CS_PMCR, CS_PMCR_E);
}

/* end of cspmu.c */
