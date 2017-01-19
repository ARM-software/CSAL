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
#include "cs_trace_source.h"
#include "cs_topology.h"
#include "cs_etm_v4.h"

/* ---------- Local functions ------------- */

int _cs_path_enable(struct cs_device *d, int enabled)
{
    unsigned int n;
    int rc = 0;
    if (DTRACE(d)) {
        diagf("!%sable path from %" CS_PHYSFMT "\n",
              (enabled ? "en" : "dis"), d->phys_addr);
    }
    for (n = 0; n < d->n_out_ports; ++n) {
        struct cs_device *od = d->outs[n];
        if (od != NULL) {
            if (cs_device_is_funnel(od)) {
                unsigned int od_in_port = d->to_in_port[n];
                /* Recursively enable this funnel's output path */
                _cs_path_enable(od, enabled);
                if (DTRACE(d)) {
                    diagf("!%sable input port %u of funnel %" CS_PHYSFMT
                          "\n", (enabled ? "en" : "dis"), od_in_port,
                          od->phys_addr);
                }
                _cs_unlock(od);
                rc = _cs_set_mask(od, CS_FUNNEL_CTRL, (1U << od_in_port),
                                  (enabled << od_in_port));
                if (DTRACE(od)) {
                    diagf("!funnel inputs now %08X\n",
                          _cs_read(od, CS_FUNNEL_CTRL));
                }
                if (rc != 0) {
                    break;
                }
            } else if (cs_device_is_replicator(od)) {
                if (DTRACE(od)) {
                    diagf("!%sable replicator\n",
                          (enabled ? "en" : "dis"));
                }
                /* Scan the replicator's out-ports in case they are funnel inputs */
                _cs_path_enable(od, enabled);
            }
        }
    }
    return rc;
}

/* ========== API functions ================ */

int cs_set_trace_source_id(cs_device_t dev, cs_atid_t id)
{
    int rc;
    struct cs_device *d = DEV(dev);
    assert(cs_device_has_class(dev, CS_DEVCLASS_SOURCE));
    assert(cs_atid_is_valid(id));
    _cs_unlock(d);
    if (cs_device_has_class(dev, CS_DEVCLASS_CPU)) {
        rc = _cs_etm_enable_programming(d);
        if (rc != 0) {
            return rc;
        }
        if (CS_ETMVERSION_MAJOR(_cs_etm_version(d)) >= CS_ETMVERSION_ETMv4) {
            _cs_write(d, CS_ETMV4_TRACEIDR, id);
        } else
            _cs_write(d, CS_ETMTRACEIDR, id);
    } else if ((d->type == DEV_ITM) || (d->type == DEV_STM)) {
        _cs_swstim_set_trace_id(d, id);
    } else {
        return -1;
    }
    /* Trace source ids are worth getting correct, and we don't change them often,
       so do a quick check here. */
    if (cs_get_trace_source_id(dev) != id) {
        return cs_report_device_error(d, "failed to set trace source id");
    }
    return 0;
}

cs_atid_t cs_get_trace_source_id(cs_device_t dev)
{
    cs_atid_t id = (cs_atid_t) (-1);

    struct cs_device *d = DEV(dev);
    assert(cs_device_has_class(dev, CS_DEVCLASS_SOURCE));
    if (cs_device_has_class(dev, CS_DEVCLASS_CPU)) {
        if (CS_ETMVERSION_MAJOR(_cs_etm_version(d)) >= CS_ETMVERSION_ETMv4) {
            id = _cs_read(d, CS_ETMV4_TRACEIDR);
        } else {
            id = _cs_read(d, CS_ETMTRACEIDR);
        }
    } else if (d->type == DEV_ITM) {
        id = (_cs_read(d, CS_ITM_CTRL) >> 16) & 0x7F;
    } else if (d->type == DEV_STM) {
        id = (_cs_read(d, CS_STM_TCSR) >> 16) & 0x7F;
    } else {
        /* can't read source id from this device */
    }
    return id;
}

int cs_trace_enable(cs_device_t dev)
{
    int rc;
    struct cs_device *d = DEV(dev);
    assert(cs_device_has_class(dev, CS_DEVCLASS_SOURCE));
    _cs_path_enable(d, /*enabled= */ 1);
    _cs_unlock(d);
    if (cs_device_has_class(dev, CS_DEVCLASS_CPU)) {
        /* Enable PTM trace */
        rc = _cs_etm_disable_programming(d);
        if (rc != 0) {
            return rc;
        }
        if (_cs_etm_version(d) < CS_ETMVERSION_PTM) {
            _cs_set(d, CS_ETMCR, CS_ETMCR_ETMEN);	/* ETM v3 only */
        } else {
            /* on PTM that bit is reserved */
        }
        /* The ETM powerdown bit should already have been cleared when programmed */
    } else if ((d->type == DEV_ITM) || (d->type == DEV_STM)) {
        _cs_swstim_trace_enable(d);
    } else {
        /* TBD */
    }
    return 0;
}

int cs_trace_is_enabled(cs_device_t dev)
{
    int is_enabled = 0;
    struct cs_device *d = DEV(dev);
    assert(cs_device_has_class(dev, CS_DEVCLASS_SOURCE));
    if (cs_device_has_class(dev, CS_DEVCLASS_CPU)) {
        if (CS_ETMVERSION_MAJOR(_cs_etm_version(d)) >= CS_ETMVERSION_ETMv4) {
            is_enabled =
                _cs_isset(d, CS_ETMV4_PRGCTLR, CS_ETMV4_PRGCTLR_en);
        } else {
            is_enabled = !_cs_isset(d, CS_ETMCR, CS_ETMCR_ProgBit);
        }
    }
    return is_enabled;
}

int cs_trace_disable(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);

    assert(cs_device_has_class(dev, CS_DEVCLASS_SOURCE));

    _cs_unlock(d);
    /* Take any source-specific actions to disable trace */
    if (cs_device_has_class(dev, CS_DEVCLASS_CPU)) {
        if (CS_ETMVERSION_MAJOR(_cs_etm_version(d)) >= CS_ETMVERSION_ETMv4) {
            /* ETMv4 - sufficent to enable programming */
            _cs_etm_v4_enable_programming(d);
        } else {
            /* ETM/PTM */
            if (_cs_etm_version(d) < CS_ETMVERSION_PTM) {
                _cs_clear(d, CS_ETMCR, CS_ETMCR_ETMEN);
            } else {
                /* on PTM that bit is reserved */
            }

            /* Now we should wait for the FIFO to drain (before we turn off the
               sink into which it's draining) - there's a comment on ProgBit
               "This bit remains 0 while there is any data in the FIFO.  This ensures
               that the FIFO is empty before you can reprogram the PTM."
               So to flush the FIFO we just set ProgBit and wait for it. */
            _cs_set(d, CS_ETMCR, CS_ETMCR_ProgBit);
            _cs_wait(d, CS_ETMSTATUS, CS_ETMSR_ProgBit);
        }
    } else if ((d->type == DEV_ITM) || (d->type == DEV_STM)) {
        _cs_swstim_trace_disable(d);
    } else {
        /* TBD: */
        return cs_report_device_error(d,
                                      "can't disable this trace source");
    }
    /* Disable funnel inputs that this source is connected to */
    return _cs_path_enable(d, /*enabled= */ 0);
}


int cs_trace_enable_timestamps(cs_device_t dev, int enabled)
{
    struct cs_device *d = DEV(dev);
    if (d->type == DEV_ITM) {
        _cs_unlock(d);
        _cs_set_bit(d, CS_ITM_CTRL, CS_ITM_CTRL_TSSEn, enabled);
        if (DTRACE(d)) {
            diagf("ITM control register: %08X\n",
                  _cs_read(d, CS_ITM_CTRL));
        }
        return 0;
    } else if (d->type == DEV_STM) {
        _cs_unlock(d);
        _cs_set_bit(d, CS_STM_TCSR, CS_STM_TCSR_TSEN, enabled);
        return 0;
    } else if (d->type == DEV_ETM) {
        /* We assume that the ETM is in programming mode */
        _cs_unlock(d);
        if (CS_ETMVERSION_MAJOR(_cs_etm_version(d)) >= CS_ETMVERSION_ETMv4) {
            return _cs_set_bit(d, CS_ETMV4_CONFIGR, CS_ETMV4_CONFIGR_TS,
                               enabled);
        } else {
            return _cs_set_bit(d, CS_ETMCR, CS_ETMCR_TSEn, enabled);
        }
    } else if (d->type == DEV_TS) {
        return _cs_tsgen_enable(d, enabled);
    } else {
        return -1;
    }
}

/** Enable or disable cycle accurate tracing on a trace source */
int cs_trace_enable_cycle_accurate(cs_device_t dev, int enable)
{
    struct cs_device *d = DEV(dev);
    if (d->type == DEV_ETM) {
        /* We assume that the ETM is in programming mode */
        _cs_unlock(d);
        if (CS_ETMVERSION_MAJOR(_cs_etm_version(d)) >= CS_ETMVERSION_ETMv4) {
            /* "TRCCCCTLR... must be programmed if TRCCONFIGR_CCI==1." */
            if (enable) {
                unsigned int const CCITMIN =
                    _cs_read(d, CS_ETMv4_IDR3) & 0xfff;
                _cs_write(d, CS_ETMV4_CCCTLR, CCITMIN);
            }
            /* enable cycle count on instruction trace */
            return _cs_set_bit(d, CS_ETMV4_CONFIGR, CS_ETMV4_CONFIGR_CCI,
                               enable);
        } else {
            return _cs_set_bit(d, CS_ETMCR, CS_ETMCR_CycleAccurate,
                               enable);
        }
    } else {
        return -1;
    }
}


int cs_replicator_set_filter(cs_device_t dev, unsigned int outport,
                             unsigned int filter)
{
    struct cs_device *d = DEV(dev);
    assert(cs_device_is_replicator(d));
    assert(outport <= 1);
    if (cs_device_is_non_mmio(d)) {
        return cs_report_device_error(d,
                                      "attempt to program non-programmable replicator");
    }
    filter &= 0xFF;
    _cs_unlock(d);
    return _cs_write(d, CS_REPLICATOR_IDFILTER(outport), filter);
}


/* end of cs_trace_source.c */
