/*
  Coresight Access Library - API - programming and extraction of data from trace sinks

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
#include "cs_etm.h"
#include "cs_etm_v4.h"

/* ---------- Local functions ------------- */

int _cs_etm_static_config_init(struct cs_device *d)
{
    memset(&(d->v.etm.sc), 0, sizeof(struct cs_etm_static_config));
    assert(d->v.etm.etmidr != 0);

    /* Read in the version - for printing purposes */
    d->v.etm.sc.version = _cs_etm_version(d);

    if (CS_ETMVERSION_MAJOR(_cs_etm_version(d)) >= CS_ETMVERSION_ETMv4) {
        return _cs_etm_v4_static_config_init(d);
    } else {
        /* ETMv3 or PTM */
        /* Read from ETMCCR */
        d->v.etm.sc.ccr.reg = _cs_read(d, CS_ETMCCR);
        /* Read from ETMSCR */
        d->v.etm.sc.scr.raw.reg = _cs_read(d, CS_ETMSCR);
        d->v.etm.sc.scr.max_port_size =
            (d->v.etm.sc.scr.raw.sc3x.max_port_size_3 << 3) | (d->v.etm.sc.
                                                               scr.raw.
                                                               sc3x.
                                                               max_port_size_20);
        /* Read from ETMCCER */
        d->v.etm.sc.ccer.reg = _cs_read(d, CS_ETMCCER);
    }
    return 0;
}

/*
  Return the ETM version in encoded form.  Compare it against one of
  the provided constants.
*/
unsigned int _cs_etm_version(struct cs_device *d)
{
    assert(d->type == DEV_ETM);
    return (d->v.etm.etmidr >> 4) & 0xFF;
}

int _cs_etm_enable_programming(struct cs_device *d)
{
    int rc;

    /* filter anything >= v4 */
    if (CS_ETMVERSION_MAJOR(_cs_etm_version(d)) >= CS_ETMVERSION_ETMv4) {
        return _cs_etm_v4_enable_programming(d);
    }

    _cs_unlock(d);

    /* Manage the ETM OS lock.  "[ETM] In ETMv3.5, when the OS Lock
       is implemented, the OS Lock is always set from an ETM reset" */
    {
        unsigned int oslsr = _cs_read(d, CS_ETMOSLSR);
        unsigned int pdsr;
        //unsigned int lsr = _cs_read(d, CS_ETMLSR);
        /* LSR: bit 1: ETM locked, writes ignored;
           bit 0: access is from an i/f that requires ETM to be unlocked */

        if (_cs_isset(d, CS_ETMCR, CS_ETMCR_PowerDown)) {
            /* ETM power down. "When this bit is set to 1, writes to some registers
               and fields might be ignored." */
            /* Unset power-down state */
            _cs_clear(d, CS_ETMCR, CS_ETMCR_PowerDown);
            _cs_waitnot(d, CS_ETMCR, CS_ETMCR_PowerDown);
        }

        pdsr = _cs_read(d, CS_ETMPDSR);
        if (pdsr & 0x02) {
            /* "In ETMv3.5, the value of this bit has no effect on accesses to the
               ETM Trace Registers." */
            diagf("!%" CS_PHYSFMT
                  ": ETM Trace Registers have been powered down since this register was last read\n",
                  d->phys_addr);
        }

        /* PDSR bit 1: "If the Software Lock mechanism is locked and the ETMPDSR read is
           made through the memory mapped interface, this bit is not cleared." */
        if ((oslsr & 2) != 0) {
            diagf
                ("ETM trace registers are locked. Any access to these registers returns a slave-generated error response.\n");
            /* OS lock is implemented and locked */
            /* ETMOSLSR[3] and ETMOSLSR[0] are specified in [ETM] Table 3-94:
               3.3, 3.4: 0 0   Single Power
               3.3, 3.4: 0 1   Full Support
               3.5:      1 0   SinglePower
               3.5:      1 1   Full Support
               In ETM 3.5 SinglePower implementation:
               - the ETMOSLAR is not implemented and ignores writes
            */
            /* "You set the OS lock by writing the lock key of 0xC5ACCE55 to the ETMOSLAR.
               When the OS Lock is set all PTM functions are disabled." */
            /* "Write any other value to unlock" */
            _cs_write_wo(d, CS_ETMOSLAR, 0x00000000);
            // _cs_write_wo(d, CS_ETMOSLAR, 0xC5ACCE55);
            /* Now see if the registers are unlocked */
            rc = _cs_waitnot(d, CS_ETMOSLSR, 0x02);
            if (rc != 0) {
                return cs_report_device_error(d,
                                              "could not unlock ETM trace registers");
            }
        }
    }

    /* Set ETMCLAIM[1] to indicate the ETM is claimed by software.
       This follows the protocol described in the (not yet released)
       document on external/internal debug coordination. */
    _cs_claim(d, CS_CLAIM_INTERNAL);

    /* [ETM] "When setting the Programming bit, you must not change any other
       bits of the ETM Control Register.  You must only change the value
       of bits other than the Programming bit of the Control Register
       when bit [1] of the Status Register is set to 1." */
    _cs_set(d, CS_ETMCR, CS_ETMCR_ProgBit);
    /* Wait according to the flowchart in [ETM] Figure 3-3 */
    return _cs_wait(d, CS_ETMSTATUS, CS_ETMSR_ProgBit);
}

int _cs_etm_disable_programming(struct cs_device *d)
{
    /* filter anything >= v4 */
    if (CS_ETMVERSION_MAJOR(_cs_etm_version(d)) >= CS_ETMVERSION_ETMv4) {
        return _cs_etm_v4_disable_programming(d);
    }
    /* must be PTM / ETMv3 */
    _cs_clear(d, CS_ETMCR, CS_ETMCR_ProgBit);
    /* Wait according to the flowchart in [ETM] Figure 3-3 */
    return _cs_waitnot(d, CS_ETMSTATUS, CS_ETMSR_ProgBit);
}

#ifndef UNIX_KERNEL
#define EVENT_DESCRIPTION 60	/* Space for event description string */
static char const *edesc(char *buf, unsigned int event)
{
    char *p;
    unsigned int i;
    unsigned int const fn = (event >> 14) & 0x7;
    unsigned int n_resources = (fn <= 1) ? 1 : 2;
    static char const *const fmt[8][3] = {
        {"", "", ""},
        {"NOT(", ")", ""},
        {"", " AND ", ""},
        {"NOT(", ") AND ", ""},
        {"NOT(", ") AND NOT(", ")"},
        {"", " OR ", ""},
        {"NOT(", ") OR ", ""},
        {"NOT(", ") OR NOT(", ")"}
    };

    buf[0] = '\0';
    p = buf;
    if (event == CS_ETME_NEVER) {
        /* Special-case this, otherwise it is "NOT(true)" */
        p += sprintf(p, "%s", "false");
        return buf;
    }

    p += sprintf(p, "%s", fmt[fn][0]);
    for (i = 0; i < n_resources; ++i) {
        unsigned int res = event & 0x7F;
        unsigned int value = res & 0xF;
        unsigned int type = (res >> 4) & 0x7;
        switch (type) {
        case 0:
            p += sprintf(p, "single-addr-comp-%u", value);
            break;
        case 1:
            if (!(value & 8)) {
                p += sprintf(p, "addr-range-comp-%u", value);
            } else {
                p += sprintf(p, "instrumentation-%u", value);
            }
            break;
        case 2:
            p += sprintf(p, "EmbeddedICE-%u", value);
            break;
        case 3:
            p += sprintf(p, "memory-map-%u", value);
            break;
        case 4:
            p += sprintf(p, "counter-zero-%u", value);
            break;
        case 5:
            switch (value) {
            case 0:
            case 1:
            case 2:
                p += sprintf(p, "sequencer-state-%u", value + 1 - 0);
                break;
            case 8:
            case 9:
            case 10:
                p += sprintf(p, "context-id-%u", value - 8);
                break;
            case 11:
                p += sprintf(p, "vmid");
                break;
            case 15:
                p += sprintf(p, "trace-start-stop");
                break;
            default:
                p += sprintf(p, "reserved?-5-%u", value);
                break;
            }
            break;
        case 6:
            switch (value) {
            case 0:
            case 1:
            case 2:
            case 3:
                p += sprintf(p, "external-input-%u", value - 0);
                break;
            case 8:
            case 9:
            case 10:
            case 11:
                p += sprintf(p, "extended-extin-%u", value - 8);
                break;
            case 13:
                p += sprintf(p, "non-secure");
                break;
            case 14:
                p += sprintf(p, "trace-prohibited");
                break;
            case 15:
                p += sprintf(p, "true");
                break;
            default:
                p += sprintf(p, "reserved?-6-%u", value);
                break;
            }
            break;
        case 7:
            p += sprintf(p, "reserved-7-%u", value);
            break;
        }
        p += sprintf(p, "%s", fmt[fn][i + 1]);
        event >>= 7;
    }
    return buf;
}

#endif				/* #ifndef UNIX_KERNEL */

/* ----------- ETMv3/PTM -------------------- */
static void _cs_etm_config_clean(struct cs_etm_config *c)
{
    unsigned int i;
    c->timestamp_event = CS_ETME_NEVER;
    c->flags |= CS_ETMC_TS_EVENT;
    c->trigger_event = CS_ETME_NEVER;
    c->flags |= CS_ETMC_TRIGGER_EVENT;

    c->trace_enable_event = CS_ETME_NEVER;
    c->trace_start_comparators = 0;
    c->trace_stop_comparators = 0;
    c->trace_enable_cr1 = 0;
    c->trace_enable_cr2 = 0;
    c->vdata_event = CS_ETME_NEVER;
    c->flags |= CS_ETMC_TRACE_ENABLE;

    if (c->sc->ccr.s.n_addr_comp_pairs > 0) {
        c->flags |= CS_ETMC_ADDR_COMP;
        /* config init will have zeroed out the values, but we
           do need to change the access type to 001 (Execute),
           as not all ETMs support access type 000 (Fetch) */
        for (i = 0; i < c->sc->ccr.s.n_addr_comp_pairs * 2; ++i) {
            c->addr_comp[i].access_type |= 1;
        }
    }

    if (c->sc->ccr.s.n_data_comp > 0) {
        c->flags |= CS_ETMC_DATA_COMP;
        /* config init will have zeroed out the values */
    }

    if (c->sc->ccr.s.n_counters > 0) {
        c->flags |= CS_ETMC_COUNTER;
        for (i = 0; i < c->sc->ccr.s.n_counters; ++i) {
            c->counter[i].value = 0;
            c->counter[i].reload_value = 0;
            c->counter[i].enable_event = CS_ETME_NEVER;
            c->counter[i].reload_event = CS_ETME_NEVER;
        }
    }

    if (c->sc->ccr.s3x.n_cxid_comp > 0) {
        c->flags |= CS_ETMC_CXID_COMP;
        /* config init will have zeroed out the values */
    }

    if (c->sc->ccr.s.sequencer_present) {
        c->flags |= CS_ETMC_SEQUENCER;
        /* For ETMv3, state 0 is not valid, but state 1 is. */
        c->sequencer.state = 1;
        for (i = 0; i < CS_ETMSEQ_TRANSITIONS; ++i) {
            c->sequencer.transition_event[i] = CS_ETME_NEVER;
        }
    }
    if (c->sc->ccr.s.n_ext_out > 0) {
        c->flags |= CS_ETMC_EXTOUT;
        for (i = 0; i < c->sc->ccr.s.n_ext_out; ++i) {
            c->extout_event[i] = CS_ETME_NEVER;
        }
    }
}


/* ========== API functions ================ */

#define bit(x, n) (((x) >> (n)) & 1)
#define onebits(n) ((1U << (n)) - 1)

/* ----------- ETMv3/PTM -------------------- */
/*
  ETM configuration
*/
/* DEPRECATED - unused in library - do not use as API */
int cs_etm_static_config_init(struct cs_etm_static_config *c)
{
    memset(c, 0, sizeof(struct cs_etm_static_config));
    return 0;
}

int cs_etm_config_init(struct cs_etm_config *c)
{
    memset(c, 0, sizeof(struct cs_etm_config));
    /* By default, all counters etc. are selected */
    c->addr_comp_mask = ~0;
    c->data_comp_mask = ~0;
    c->counter_mask = ~0;
    c->cxid_comp_mask = ~0;
    c->extout_mask = ~0;
    return 0;
}

int cs_etm_config_get(cs_device_t dev, struct cs_etm_config *c)
{
    unsigned int i;
    struct cs_device *d = DEV(dev);
    unsigned int const version = _cs_etm_version(d);
    int const is_ptm = CS_ETMVERSION_IS_PTM(version);
    int const has_data_trace = CS_ETMVERSION_IS_ETMV3(version);

    assert(d->type == DEV_ETM);
    assert(CS_ETMVERSION_MAJOR(version) < CS_ETMVERSION_ETMv4);

    c->sc = &(d->v.etm.sc);
    c->idr = &(d->v.etm.etmidr);

    if (c->flags & CS_ETMC_CONFIG) {
        c->cr.raw.reg = _cs_read(d, CS_ETMCR);
        /* Extract the port mode and port size */
        c->cr.port_size =
            (c->cr.raw.c._port_size_3 << 3) | c->cr.raw.c._port_size_20;
        c->cr.port_mode =
            (c->cr.raw.c._port_mode_2 << 2) | c->cr.raw.c._port_mode_10;
    }

    if (c->flags & CS_ETMC_TRACE_ENABLE) {
        unsigned int trace_start_stop;
        c->trace_enable_event = _cs_read(d, CS_ETMTEEVR);
        trace_start_stop = _cs_read(d, CS_ETMTSSCR);
        c->trace_start_comparators = trace_start_stop & 0xFFFF;
        c->trace_stop_comparators = trace_start_stop >> 16;
        c->trace_enable_cr1 = _cs_read(d, CS_ETMTECR1);
        /* This register is not always implemented i.e. PTM */
        if (!is_ptm) {
            c->trace_enable_cr2 = _cs_read(d, CS_ETMTECR2);
        } else {
            c->trace_enable_cr2 = 0;
        }
        if (has_data_trace) {
            /* Read ViewData registers. These are available only if
               data/address tracing is available.  To detect that, we'd
               need to try programming ETMCR, as described in [ETM 3.5.1].
               Currently that's not done. */
            c->vdata_event = _cs_read(d, CS_ETMVDEVR);
            c->vdata_ctl1 = _cs_read(d, CS_ETMVDCR(0));
            c->vdata_ctl2 = _cs_read(d, CS_ETMVDCR(1));
            c->vdata_ctl3 = _cs_read(d, CS_ETMVDCR(2));
        }
    }
    if (c->flags & CS_ETMC_TRIGGER_EVENT) {
        c->trigger_event = _cs_read(d, CS_ETMTRIGGER);
    }
    if ((c->flags & CS_ETMC_TS_EVENT)
        && version >= CS_ETMVERSION(CS_ETMVERSION_ETMv3, 5)) {
        c->timestamp_event = _cs_read(d, CS_ETMTSEVR);
    }
    //c->addr_comp_mask &= onebits(c->sc.s.n_addr_comp_pairs * 2);
    c->addr_comp_mask &= onebits(c->sc->ccr.s.n_addr_comp_pairs * 2);

    if (c->flags & CS_ETMC_ADDR_COMP) {
        //    for (i = 0; i < c->sc.s.n_addr_comp_pairs * 2; ++i) {
        for (i = 0; i < c->sc->ccr.s.n_addr_comp_pairs * 2; ++i) {
            if (c->addr_comp_mask & (1U << i)) {
                c->addr_comp[i].address = _cs_read(d, CS_ETMACVR(i));
                c->addr_comp[i].access_type = _cs_read(d, CS_ETMACTR(i));
            }
        }
    }

    c->data_comp_mask &= onebits(c->sc->ccr.s.n_data_comp);
    if ((c->flags & CS_ETMC_DATA_COMP) && (!is_ptm)) {
        //    for (i = 0; i < c->sc.s.n_addr_comp_pairs * 2; ++i) {
        for (i = 0; i < c->sc->ccr.s.n_data_comp; ++i) {
            if (c->data_comp_mask & (1U << i)) {
                c->data_comp[i].value = _cs_read(d, CS_ETMDCVR(i));
                c->data_comp[i].data_mask = _cs_read(d, CS_ETMDCMR(i));
            }
        }
    }

    /* When reading counter values, mask out bits corresponding
       to unavailable counters. */
    c->counter_mask &= onebits(c->sc->ccr.s.n_counters);
    if (c->flags & CS_ETMC_COUNTER) {
        for (i = 0; i < c->sc->ccr.s.n_counters; ++i) {
            if (c->counter_mask & (1U << i)) {
                c->counter[i].reload_value =
                    _cs_read(d, CS_ETMCNTRLDVR(i));
                c->counter[i].enable_event = _cs_read(d, CS_ETMCNTENR(i));
                c->counter[i].reload_event =
                    _cs_read(d, CS_ETMCNTRLDEVR(i));
                c->counter[i].value = _cs_read(d, CS_ETMCNTVR(i));
            }
        }
    }
    c->cxid_comp_mask &= onebits(c->sc->ccr.s3x.n_cxid_comp);
    if (c->flags & CS_ETMC_CXID_COMP) {
        c->cxid_mask = _cs_read(d, CS_ETMCIDCMR);
        for (i = 0; i < c->sc->ccr.s3x.n_cxid_comp; ++i) {
            c->cxid_comp[i].cxid = _cs_read(d, CS_ETMCIDCVR(i));
        }
    }
    if (c->flags & CS_ETMC_SEQUENCER) {
        if (c->sc->ccr.s.sequencer_present) {
            unsigned int i;
            c->sequencer.state = _cs_read(d, CS_ETMSQR) + 1;
            for (i = 0; i < CS_ETMSEQ_TRANSITIONS; ++i) {
                c->sequencer.transition_event[i] =
                    _cs_read(d, CS_ETMSQEVRRAW(i));
            }
        } else {
            /* No sequencer configuration/status to read */
            c->flags &= ~CS_ETMC_SEQUENCER;
        }
    }
    c->extout_mask &= onebits(c->sc->ccr.s.n_ext_out);
    if (c->flags & CS_ETMC_EXTOUT) {
        unsigned int i;
        for (i = 0; i < c->sc->ccr.s.n_ext_out; ++i) {
            c->extout_event[i] = _cs_read(d, CS_ETMEXTOUTEVR(i));
        }
    }
    return 0;
}

int cs_etm_config_put(cs_device_t dev, struct cs_etm_config *c)
{
    unsigned int i, atype;
    struct cs_device *d = DEV(dev);
    unsigned int const version = _cs_etm_version(d);
    int const is_ptm = CS_ETMVERSION_IS_PTM(version);
    int const has_data_trace = CS_ETMVERSION_IS_ETMV3(version);

    assert(d->type == DEV_ETM);
    assert(CS_ETMVERSION_MAJOR(version) < CS_ETMVERSION_ETMv4);

    _cs_etm_enable_programming(d);

    if (c->flags & CS_ETMC_CONFIG) {
        /* Extract the port mode and port size and save them back accordingly. */
        c->cr.raw.c._port_size_3 = (c->cr.port_size & (1 << 3)) >> 3;
        c->cr.raw.c._port_size_20 = c->cr.port_size & 0x7;
        c->cr.raw.c._port_mode_2 = (c->cr.port_mode & (1 << 2)) >> 2;
        c->cr.raw.c._port_mode_10 = c->cr.port_mode & 0x3;
        if (!has_data_trace && c->cr.raw.c.data_access != 0) {
            return cs_report_device_error(d,
                                          "attempt to enable data trace when not available");
        }
        _cs_write(d, CS_ETMCR, c->cr.raw.reg);
    }
    if (c->flags & CS_ETMC_TRACE_ENABLE) {
        unsigned int trace_start_stop =
            (c->trace_stop_comparators << 16) | c->trace_start_comparators;
        _cs_write(d, CS_ETMTEEVR, c->trace_enable_event);
        _cs_write(d, CS_ETMTSSCR, trace_start_stop);
        _cs_write(d, CS_ETMTECR1, c->trace_enable_cr1);
        if (!is_ptm) {
            _cs_write(d, CS_ETMTECR2, c->trace_enable_cr2);
        }
        if (has_data_trace) {
            _cs_write(d, CS_ETMVDEVR, c->vdata_event);
            _cs_write(d, CS_ETMVDCR(0), c->vdata_ctl1);
            _cs_write(d, CS_ETMVDCR(1), c->vdata_ctl2);
            _cs_write(d, CS_ETMVDCR(2), c->vdata_ctl3);
        }
    }
    if (c->flags & CS_ETMC_TRIGGER_EVENT) {
        _cs_write(d, CS_ETMTRIGGER, c->trigger_event);
    }
    if ((c->flags & CS_ETMC_TS_EVENT)
        && version >= CS_ETMVERSION(CS_ETMVERSION_ETMv3, 5)) {
        _cs_write(d, CS_ETMTSEVR, c->timestamp_event);
    }
    if (c->flags & CS_ETMC_ADDR_COMP) {
        for (i = 0; i < c->sc->ccr.s.n_addr_comp_pairs * 2; ++i) {
            if (c->addr_comp_mask & (1U << i)) {
                _cs_write(d, CS_ETMACVR(i), c->addr_comp[i].address);
                atype = (c->addr_comp[i].access_type & 7);
                if (is_ptm ?
                    (atype != 1) :
                    (atype == 0
                     && (c->sc->scr.raw.reg & 0x00020000) != 0)) {
                    return cs_report_device_error(d,
                                                  "attempt to program comparator #%u with unsupported Fetch comparison",
                                                  i);
                }
                _cs_write(d, CS_ETMACTR(i), c->addr_comp[i].access_type);
            }
        }
    }
    c->data_comp_mask &= onebits(c->sc->ccr.s.n_data_comp);
    if ((c->flags & CS_ETMC_DATA_COMP) && has_data_trace) {
        //    for (i = 0; i < c->sc.s.n_addr_comp_pairs * 2; ++i) {
        for (i = 0; i < c->sc->ccr.s.n_data_comp; ++i) {
            if (c->data_comp_mask & (1U << i)) {
                _cs_write(d, CS_ETMDCVR(i), c->data_comp[i].value);
                _cs_write(d, CS_ETMDCMR(i), c->data_comp[i].data_mask);
            }
        }
    }
    if (c->flags & CS_ETMC_COUNTER) {
        for (i = 0; i < c->sc->ccr.s.n_counters; ++i) {
            if (c->counter_mask & (1U << i)) {
                if (c->counter[i].reload_value > 0xFFFF ||
                    c->counter[i].value > 0xFFFF) {
                    return cs_report_device_error(d,
                                                  "attempt to program ETM counter #%u with invalid values 0x%08X (reload 0x%08X)",
                                                  i, c->counter[i].value,
                                                  c->counter[i].
                                                  reload_value);
                }
                _cs_write(d, CS_ETMCNTRLDVR(i),
                          c->counter[i].reload_value);
                /* OR the written value with bit 17, to indicate "count enable source".
                   See ETM architecture spec for details. */
                _cs_write(d, CS_ETMCNTENR(i),
                          c->counter[i].enable_event | 0x20000);
                _cs_write(d, CS_ETMCNTRLDEVR(i),
                          c->counter[i].reload_event);
                _cs_write(d, CS_ETMCNTVR(i), c->counter[i].value);
            }
        }
        if (c->counter_mask & ~onebits(c->sc->ccr.s.n_counters)) {
            return cs_report_device_error(d,
                                          "counter mask=0x%x but only %u ETM counters available",
                                          (unsigned int) c->counter_mask,
                                          c->sc->ccr.s.n_counters);
        }
    }
    if (c->flags & CS_ETMC_CXID_COMP) {
        _cs_write(d, CS_ETMCIDCMR, c->cxid_mask);
        for (i = 0; i < c->sc->ccr.s3x.n_cxid_comp; ++i) {
            if (c->cxid_comp_mask & (1U << i)) {
                _cs_write(d, CS_ETMCIDCVR(i), c->cxid_comp[i].cxid);
            }
        }
    }
    if (c->flags & CS_ETMC_SEQUENCER) {
        if (c->sc->ccr.s.sequencer_present) {
            unsigned int i;
            if (c->sequencer.state < 1 || c->sequencer.state > 3) {
                return cs_report_device_error(d,
                                              "attempt to program invalid sequencer state %u",
                                              c->sequencer.state);
            }
            _cs_write(d, CS_ETMSQR, c->sequencer.state - 1);
            for (i = 0; i < CS_ETMSEQ_TRANSITIONS; ++i) {
                _cs_write(d, CS_ETMSQEVRRAW(i),
                          c->sequencer.transition_event[i]);
            }
        } else {
            /* Tried to write sequencer config when no sequencer present */
            c->flags &= ~CS_ETMC_SEQUENCER;
        }
    }
    if (c->flags & CS_ETMC_EXTOUT) {
        unsigned int i;
        for (i = 0; i < c->sc->ccr.s.n_ext_out; ++i) {
            if (c->extout_mask & (1U << i)) {
                _cs_write(d, CS_ETMEXTOUTEVR(i), c->extout_event[i]);
            }
        }
    }
    return 0;
}

/* ----------- ETM generic API -------------------- */

/* top level API - diverts to arch appropriate impl */
int cs_etm_config_init_ex(cs_device_t dev, void *etm_config)
{
    struct cs_device *d = DEV(dev);
    unsigned int etm_version;
    int rc = -1;

    assert(d->type == DEV_ETM);

    etm_version = CS_ETMVERSION_MAJOR(_cs_etm_version(d));
    switch (etm_version) {
    case CS_ETMVERSION_ETMv3:
    case CS_ETMVERSION_PTM:
        rc = cs_etm_config_init((cs_etm_config_t *) etm_config);
        break;

    case CS_ETMVERSION_ETMv4:
        rc = _cs_etm_v4_config_init(d, (cs_etmv4_config_t *) etm_config);
        break;
    }
    return rc;
}

/* top level API - diverts to arch appropriate impl */
int cs_etm_config_get_ex(cs_device_t dev, void *etm_config)
{
    struct cs_device *d = DEV(dev);
    unsigned int etm_version;
    int rc = -1;

    assert(d->type == DEV_ETM);

    etm_version = CS_ETMVERSION_MAJOR(_cs_etm_version(d));
    switch (etm_version) {
    case CS_ETMVERSION_ETMv3:
    case CS_ETMVERSION_PTM:
        rc = cs_etm_config_get(dev, (cs_etm_config_t *) etm_config);
        break;

    case CS_ETMVERSION_ETMv4:
        rc = _cs_etm_v4_config_get(d, (cs_etmv4_config_t *) etm_config);
        break;
    }
    return rc;
}

/* top level API - diverts to arch appropriate impl */
int cs_etm_config_put_ex(cs_device_t dev, void *etm_config)
{
    struct cs_device *d = DEV(dev);
    unsigned int etm_version;
    int rc = -1;

    assert(d->type == DEV_ETM);

    etm_version = CS_ETMVERSION_MAJOR(_cs_etm_version(d));
    switch (etm_version) {
    case CS_ETMVERSION_ETMv3:
    case CS_ETMVERSION_PTM:
        rc = cs_etm_config_put(dev, (cs_etm_config_t *) etm_config);
        break;

    case CS_ETMVERSION_ETMv4:
        rc = _cs_etm_v4_config_put(d, (cs_etmv4_config_t *) etm_config);
        break;
    }
    return rc;
}

#ifndef UNIX_KERNEL
/* top level API - diverts to arch appropriate impl */
int cs_etm_config_print_ex(cs_device_t dev, void *etm_config)
{
    struct cs_device *d = DEV(dev);
    unsigned int etm_version;
    int rc = -1;

    assert(d->type == DEV_ETM);

    etm_version = CS_ETMVERSION_MAJOR(_cs_etm_version(d));
    switch (etm_version) {
    case CS_ETMVERSION_ETMv3:
    case CS_ETMVERSION_PTM:
        rc = cs_etm_config_print((cs_etm_config_t *) etm_config);
        break;

    case CS_ETMVERSION_ETMv4:
        rc = _cs_etm_v4_config_print(d, (cs_etmv4_config_t *) etm_config);
        break;
    }
    return rc;
}
#endif

/* ----------- ETM common -------------------- */

int cs_etm_clean(cs_device_t dev)
{
    int rc;
    struct cs_device *d = DEV(dev);
    struct cs_etm_config c;

    if (CS_ETMVERSION_MAJOR(_cs_etm_version(d)) < CS_ETMVERSION_ETMv4) {
        /* ETM v3 / PTM */
        cs_etm_config_init(&c);
        c.flags = CS_ETMC_CONFIG;
        rc = cs_etm_config_get(dev, &c);
        if (rc) {
            return rc;
        }
        _cs_etm_config_clean(&c);
        rc = cs_etm_config_put(dev, &c);
    } else {
        rc = _cs_etm_v4_clean(d);
    }
    return rc;
}

int cs_etm_enable_programming(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    return _cs_etm_enable_programming(d);
}

int cs_etm_disable_programming(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    return _cs_etm_disable_programming(d);
}

int cs_etm_get_version(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    return d->v.etm.sc.version;
}


#ifndef UNIX_KERNEL

int cs_etm_config_print(struct cs_etm_config *c)
{
    unsigned int i;
    char buf[EVENT_DESCRIPTION];
    char buf2[EVENT_DESCRIPTION];

    printf("ETM static configuration:\n");
    printf("  ETMCCR = %08X\n", c->sc->ccr.reg);
    printf("  ETMCCER = %08X\n", c->sc->ccer.reg);
    printf("  ETMSCR = %08X\n", c->sc->scr.raw.reg);
    printf("  ETMIDR = %08X\n", *c->idr);
    printf("ETM dynamic configuration:\n");
    printf("  ETMCR = %08X\n", c->cr.raw.reg);

    /* Show dynamic configuration only */
    if (c->flags & CS_ETMC_CONFIG) {
        printf("  Cycle accurate: %u\n", c->cr.raw.c.cycle_accurate);
        printf("  Branch output: %u\n", c->cr.raw.c.branch_output);
        printf("  Timestamp enabled: %u\n", c->cr.raw.c.timestamp_enabled);
        printf("  CONTEXTID size: %u bytes\n",
               (1U << c->cr.raw.c.cxid_size) >> 1);
        if (c->cr.raw.c.data_access != 0) {
            printf("  Data access:");
            if (c->cr.raw.c.data_access & 0x01) {
                printf(" data");
            }
            if (c->cr.raw.c.data_access & 0x02) {
                printf(" address");
            }
            printf("\n");
        }
    }
    if (c->flags & CS_ETMC_TRACE_ENABLE) {
        printf("  Trace enable event: %s\n",
               edesc(buf, c->trace_enable_event));
        printf("  Trace enable control: CR1=%08X CR2=%08X\n",
               c->trace_enable_cr1, c->trace_enable_cr2);
        printf("  Trace start comparators: %04X\n",
               c->trace_start_comparators);
        printf("  Trace stop comparators: %04X\n",
               c->trace_stop_comparators);
        if (c->vdata_event != CS_ETME_NEVER) {
            printf("  ViewData event: %s\n", edesc(buf, c->vdata_event));
            printf("  ViewData control 1: %08X\n", c->vdata_ctl1);
            printf("  ViewData control 2: %08X\n", c->vdata_ctl2);
            printf("  ViewData control 3: %08X\n", c->vdata_ctl3);
        }
    }
    if (c->flags & CS_ETMC_TRIGGER_EVENT) {
        printf("  Trigger event: %s\n", edesc(buf, c->trigger_event));
    }
    if (c->flags & CS_ETMC_TS_EVENT) {
        printf("  Timestamp event: %s\n", edesc(buf, c->timestamp_event));
    }
    if (c->flags & CS_ETMC_COUNTER) {
        printf("  Counters: %u\n", c->sc->ccr.s.n_counters);
        for (i = 0; i < c->sc->ccr.s.n_counters; ++i) {
            if (c->counter_mask & (1U << i)) {
                printf
                    ("    #%u: value=%08X enable=%s reload_value=%08X reload_event=%s\n",
                     i, c->counter[i].value, edesc(buf2,
                                                   c->counter[i].
                                                   enable_event),
                     c->counter[i].reload_value, edesc(buf,
                                                       c->counter[i].
                                                       reload_event));
            }
        }
    }
    if (c->flags & CS_ETMC_ADDR_COMP) {
        printf("  Address comparators: %u\n",
               c->sc->ccr.s.n_addr_comp_pairs * 2);
        for (i = 0; i < c->sc->ccr.s.n_addr_comp_pairs * 2; ++i) {
            if (c->addr_comp_mask & (1U << i)) {
                static char const *const tnames[8] = {
                    "fetch", "execute", "ex-pass", "ex-fail",
                    "load/store", "load", "store", "access?"
                };
                static char const *const msnames[4] = {
                    "all", "none", "kernel", "user"
                };
                unsigned int type = c->addr_comp[i].access_type;
                printf("    #%u: address=%08X type=%08X",
                       i,
                       c->addr_comp[i].address,
                       c->addr_comp[i].access_type);
                printf(" (%s)", tnames[type & 7]);
                if ((type & 7) == 0
                    && (c->sc->scr.raw.reg & 0x00020000) != 0) {
                    /* Fetch comparison when not supported */
                    printf("?");
                }
                printf(" (size=%u)", ((type >> 3) & 3) + 1);
                if (type & CS_ETMACT_EXACT)
                    printf(" (exact)");
                /* ETM v3.5 */
                printf(" (S:%s)",
                       msnames[(((type >> 12) & 1) << 1) |
                               ((type >> 10) & 1)]);
                printf(" (NS:%s)",
                       msnames[(((type >> 13) & 1) << 1) |
                               ((type >> 11) & 1)]);
                /* all ETMs */
                if (type & CS_ETMACT_HYP)
                    printf(" (Hyp)");
                if (type & CS_ETMACT_VMID)
                    printf(" (VMID)");
                printf("\n");
            }
        }
    }
    if (c->flags & CS_ETMC_DATA_COMP) {
        printf("  Data comparators: %u\n", c->sc->ccr.s.n_data_comp);
    }
    printf("  Sequencer present: %u\n", c->sc->ccr.s.sequencer_present);
    if ((c->flags & CS_ETMC_SEQUENCER) && c->sc->ccr.s.sequencer_present) {
        unsigned int a, b;
        printf("  Sequencer:\n");
        printf("    Current state: %u\n", c->sequencer.state);
        for (a = 1; a <= 3; ++a) {
            for (b = 1; b <= 3; ++b) {
                if (a != b) {
                    printf("    %u -> %u: %s\n",
                           a, b,
                           edesc(buf,
                                 c->sequencer.
                                 transition_event[CS_ETMSQOFF(a, b)]));
                }
            }
        }
    }
    if (c->flags & CS_ETMC_CXID_COMP) {
        if (c->sc->ccr.s.etmid_present) {
            printf("  CONTEXTID comparators: %u\n",
                   c->sc->ccr.s3x.n_cxid_comp);
            printf("    Mask: %08X\n", c->cxid_mask);
            for (i = 0; i < c->sc->ccr.s3x.n_cxid_comp; ++i) {
                if (c->cxid_comp_mask & (1U << i)) {
                    printf("    #%u: contextid: %08X\n",
                           i, c->cxid_comp[i].cxid);
                }
            }
        }
    }
    if (c->flags & CS_ETMC_EXTOUT) {
        if (c->sc->ccr.s.n_ext_out > 0) {
            printf("  External outputs:\n");
            for (i = 0; i < c->sc->ccr.s.n_ext_out; ++i) {
                printf("    #%u: %s\n", i, edesc(buf, c->extout_event[i]));
            }
        }
    }
    return 0;
}
#endif				/* #ifndef UNIX_KERNEL */

/*
  ETM function Self-tests
*/

#ifdef SELFTEST
static void test_event_descriptions(void)
{
    unsigned int i;
    char buf[EVENT_DESCRIPTION + 1];

    buf[EVENT_DESCRIPTION] = '\001';
    for (i = 0; i < 0x20000; ++i) {
        char const *d = edesc(buf, i);
        assert(d == buf);
        //printf("%05X: %s\n", i, d);
    }
    assert(buf[EVENT_DESCRIPTION] == '\001');
}

static void test_sequencer_offsets(void)
{
    unsigned int mask = 0;
    unsigned int a, b;
    for (a = 1; a <= 3; ++a) {
        for (b = 1; b <= 3; ++b) {
            if (a != b) {
                unsigned int off = CS_ETMSQOFF(a, b);
                printf("  %u -> %u: %u\n", a, b, off);
                mask |= (1U << off);
            }
        }
    }
    assert(mask == 0x3F);
}

int main(void)
{
    test_sequencer_offsets();
    test_event_descriptions();
    return 0;
}
#endif				/* SELFTEST */


/* end of cs_etm.c */
