/*
  Coresight Access Library - API trace source programming functions

  Copyright (C) ARM Limited, 2014. All rights reserved.

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
#include "cs_ts_gen.h"
#include "cs_trace_source.h"

uint64_t _ts_read(struct cs_device * d)
{
    uint32_t rd_r_l, rd_r_h;
    uint32_t val_l, val_h, val_h_next;

    rd_r_l = CS_CNTCVL;
    rd_r_h = CS_CNTCVU;
    if (d->v.ts.config.if_type == TSGEN_INTERFACE_RO) {
        rd_r_l = CS_RO_CNTCVL;
        rd_r_h = CS_RO_CNTCVU;
    }

    val_h = _cs_read(d, rd_r_h);
    val_l = _cs_read(d, rd_r_l);
    val_h_next = _cs_read(d, rd_r_h);

    /* high wrapped while we were reading low */
    if (val_h_next != val_h) {
        val_l = _cs_read(d, rd_r_l);
        val_h = val_h_next;
    }
    return (((uint64_t) val_h << 32) | val_l);
}

int _cs_tsgen_enable(struct cs_device *d, int enable)
{
    uint32_t ctrl;
    if ((d->type == DEV_TS)
        && (d->v.ts.config.if_type != TSGEN_INTERFACE_RO)) {
        ctrl = _cs_read(d, CS_CNTCR);
        if (enable)
            ctrl |= CS_CNTCR_ENA;
        else
            ctrl &= ~CS_CNTCR_ENA;
        _cs_write(d, CS_CNTCR, ctrl);
        return 0;
    }
    return -1;
}

int cs_tsgen_readvalue(cs_device_t dev, uint64_t * value)
{
    struct cs_device *d = DEV(dev);
    if ((d->type == DEV_TS) && (value != NULL)) {
        *value = _ts_read(d);
        return 0;
    }
    return -1;
}

/* global TS value read - moved from cs_trace_source.c */

int cs_get_global_timestamp(unsigned long long *ts)
{
    if (G.timestamp_device != NULL) {
        if (ts != NULL) {
            struct cs_device *d = G.timestamp_device;
            *ts = _ts_read(d);
        }
        return 0;
    }
    /* No timestamp device defined */
    return -1;
}

int cs_tsgen_set_value(cs_device_t dev, uint64_t value)
{
    uint32_t val_h, val_l;
    struct cs_device *d = DEV(dev);
    if ((d->type == DEV_TS)
        && (d->v.ts.config.if_type != TSGEN_INTERFACE_RO)) {
        val_h = (uint32_t) (value >> 32);
        val_l = (uint32_t) (value & 0xFFFFFFFF);
        _cs_write_wo(d, CS_CNTCVL, val_l);	/* write lower */
        _cs_write_wo(d, CS_CNTCVU, val_h);	/* write upper - full 64 bit value transferred to counter on this write */
        return 0;
    }
    return -1;
}

int cs_tsgen_enable(cs_device_t dev, int enable)
{
    struct cs_device *d = DEV(dev);
    return _cs_tsgen_enable(d, enable);
}

int cs_tsgen_set_dbg_halt(cs_device_t dev, int dbg_halt)
{
    struct cs_device *d = DEV(dev);
    if ((d->type == DEV_TS)
        && (d->v.ts.config.if_type != TSGEN_INTERFACE_RO)) {
        _cs_set_bit(d, CS_CNTCR, CS_CNTCR_HDBG, dbg_halt);
        return 0;
    }
    return -1;
}

int cs_tsgen_status_is_dbg_halted(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    if ((d->type == DEV_TS)
        && (d->v.ts.config.if_type != TSGEN_INTERFACE_RO)) {
        if ((_cs_read(d, CS_CNTSR) & CS_CNTSR_DBGH) != 0)
            return 1;
    }
    return 0;
}

int cs_tsgen_set_freq_id(cs_device_t dev, uint32_t freq)
{
    struct cs_device *d = DEV(dev);
    if ((d->type == DEV_TS)
        && (d->v.ts.config.if_type != TSGEN_INTERFACE_RO)) {
        _cs_write(d, CS_CNTFID0, freq);
        return 0;
    }
    return -1;
}

int cs_tsgen_get_freq_id(cs_device_t dev, uint32_t * freq)
{
    struct cs_device *d = DEV(dev);
    if ((freq != NULL) && (d->type == DEV_TS)
        && (d->v.ts.config.if_type != TSGEN_INTERFACE_RO)) {
        *freq = _cs_read(d, CS_CNTFID0);
        return 0;
    }
    return -1;
}

int cs_tsgen_config_as_ro(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    if (d->type == DEV_TS) {
        d->v.ts.config.if_type = TSGEN_INTERFACE_RO;
        return 0;
    }
    return -1;
}
