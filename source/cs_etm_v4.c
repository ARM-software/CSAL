/*!
 * \file       cs_etm_v4.c
 * \brief      CS Access API - ETM/PTM programming
 *
 * \copyright  Copyright (C) ARM Limited, 2014. All rights reserved.
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


/* include the API fns & types*/
#include "cs_types.h"
#include "cs_etm.h"

/* internal lib etmv4 and common */
#include "cs_access_cmnfns.h"
#include "cs_etm_v4.h"

/*create a bitmask for bitwidth n (n 1 -> 31) */
#define BITMASK(n) (unsigned int)((0x1U << n) - 0x1U)

int _cs_etm_v4_static_config_init(struct cs_device *d)
{
    /* ETMv4 statics */
    /* set the ext pointer to the etmv4 static structure */
    d->v.etm.sc.p_cfg_ext = &(d->v.etm.sc_ex.etmv4_sc);
    d->v.etm.sc_ex.etmv4_sc.idr1.reg = d->v.etm.etmidr;
    d->v.etm.sc_ex.etmv4_sc.idr0.reg = _cs_read(d, CS_ETMv4_IDR0);
    d->v.etm.sc_ex.etmv4_sc.idr2.reg = _cs_read(d, CS_ETMv4_IDR2);
    d->v.etm.sc_ex.etmv4_sc.idr3.reg = _cs_read(d, CS_ETMv4_IDR3);
    d->v.etm.sc_ex.etmv4_sc.idr4.reg = _cs_read(d, CS_ETMv4_IDR4);
    d->v.etm.sc_ex.etmv4_sc.idr5.reg = _cs_read(d, CS_ETMv4_IDR5);
    d->v.etm.sc_ex.etmv4_sc.idr8 = _cs_read(d, CS_ETMv4_IDR8);
    d->v.etm.sc_ex.etmv4_sc.idr9 = _cs_read(d, CS_ETMv4_IDR9);
    d->v.etm.sc_ex.etmv4_sc.idr10 = _cs_read(d, CS_ETMv4_IDR10);
    d->v.etm.sc_ex.etmv4_sc.idr11 = _cs_read(d, CS_ETMv4_IDR11);
    d->v.etm.sc_ex.etmv4_sc.idr12 = _cs_read(d, CS_ETMv4_IDR12);
    d->v.etm.sc_ex.etmv4_sc.idr13 = _cs_read(d, CS_ETMv4_IDR13);
    return 0;
}

/* set the access selection masks to read all available registers */
void _cs_etm_v4_config_sel_all(cs_etmv4_config_t * c)
{
    c->flags = CS_ETMC_ALL;
    c->counter_acc_mask = BITMASK(ETMv4_NUM_COUNTERS_MAX);
    c->rsctlr_acc_mask = 0xFFFFFFFC;
    c->ss_comps_acc_mask = BITMASK(ETMv4_NUM_SS_COMP_MAX);
    c->addr_comps_acc_mask = BITMASK(ETMv4_NUM_ADDR_COMP_MAX);
    c->data_comps_acc_mask = BITMASK(ETMv4_NUM_DATA_COMP_MAX);
    c->cxid_comps_acc_mask = BITMASK(ETMv4_NUM_CXID_COMP_MAX);
    c->vmid_comps_acc_mask = BITMASK(ETMv4_NUM_VMID_COMP_MAX);
}

int _cs_etm_v4_config_init(struct cs_device *d, cs_etmv4_config_t * c)
{
    int rc = 0;
    memset((void *) c, 0, sizeof(cs_etmv4_config_t));
    c->scv4 = (cs_etm_v4_static_config_t *) (&(d->v.etm.sc_ex.etmv4_sc));
    c->idr = &(d->v.etm.etmidr);

    _cs_etm_v4_config_sel_all(c);

    return rc;
}

int _cs_etm_v4_config_get(struct cs_device *d, cs_etmv4_config_t * c)
{
    int rc = 0;
    int i, numregs, a_size;
    unsigned int masksel;

    assert(d->type == DEV_ETM);
    assert(CS_ETMVERSION_MAJOR(_cs_etm_version(d)) >= CS_ETMVERSION_ETMv4);

    /* general configuration */
    if (c->flags & CS_ETMC_CONFIG) {
        c->configr.reg = _cs_read(d, CS_ETMV4_CONFIGR);

        /* read if implemented */
        if (c->scv4->idr3.bits.stallctl) {
            c->stallcrlr = _cs_read(d, CS_ETMV4_STALLCTLR);
        }
        c->syncpr = _cs_read(d, CS_ETMV4_SYNCPR);
        if (c->scv4->idr0.bits.trccci) {
            c->ccctlr = _cs_read(d, CS_ETMV4_CCCTLR);
        }
        if ((c->scv4->idr0.bits.trcbb == 1)
            && (c->scv4->idr4.bits.numacpairs > 0)) {
            c->bbctlr = _cs_read(d, CS_ETMV4_BBCTLR);
        }
        if (c->scv4->idr0.bits.qfilt) {
            c->qctlr = _cs_read(d, CS_ETMV4_QCTLR);
        }
        c->traceidr = _cs_read(d, CS_ETMV4_TRACEIDR);
    }

    if (c->flags & CS_ETMC_EVENTSELECT) {
        c->eventctlr0r = _cs_read(d, CS_ETMV4_EVENTCTL0R);
        c->eventctlr1r = _cs_read(d, CS_ETMV4_EVENTCTL1R);
        if (c->scv4->idr0.bits.tssize > 0) {
            c->tsctlr = _cs_read(d, CS_ETMV4_TSCTLR);
        }
    }

    if (c->flags & CS_ETMC_TRACE_ENABLE) {
        c->victlr = _cs_read(d, CS_ETMV4_VICTLR);
        c->viiectlr = _cs_read(d, CS_ETMV4_VIIECTLR);
        c->vissctlr = _cs_read(d, CS_ETMV4_VISSCTLR);
        c->vipcssctlr = _cs_read(d, CS_ETMV4_VIPSSCTLR);

        if (c->scv4->idr0.bits.trcdata != 0) {
            c->vdctlr = _cs_read(d, CS_ETMV4_VDCTLR);
            c->vdsacctlr = _cs_read(d, CS_ETMV4_VDSACCTLR);
            c->vdarcctlr = _cs_read(d, CS_ETMV4_VDARCCTLR);
        }
    }

    if ((c->flags & CS_ETMC_SEQUENCER)
        && (c->scv4->idr5.bits.numseqstate > 0)) {
        /* use the actual number, unless greater than the storage we have. */
        numregs = c->scv4->idr5.bits.numseqstate - 1;
        if (numregs > ETMv4_NUM_SEQ_EVT_MAX)
            numregs = ETMv4_NUM_SEQ_EVT_MAX;
        for (i = 0; i < numregs; i++) {
            c->seqevr[i] = _cs_read(d, CS_ETMV4_SEQEVR(i));
        }
        c->seqrstevr = _cs_read(d, CS_ETMV4_SEQRSTEVR);
        c->seqstr = _cs_read(d, CS_ETMV4_SEQSTR);
    }

    if ((c->flags & CS_ETMC_COUNTER) && (c->scv4->idr5.bits.numcntr > 0)) {
        /* use the actual number, unless greater than the storage we have. */
        numregs = c->scv4->idr5.bits.numcntr;
        if (numregs > ETMv4_NUM_COUNTERS_MAX)
            numregs = ETMv4_NUM_COUNTERS_MAX;

        masksel = 0x1;

        for (i = 0; i < numregs; i++) {
            if (c->counter_acc_mask & masksel) {
                c->counter[i].cntrldvr = _cs_read(d, CS_ETMV4_CNTRLDVR(i));
                c->counter[i].cntctlr = _cs_read(d, CS_ETMV4_CNTCTLR(i));
                c->counter[i].cntvr = _cs_read(d, CS_ETMV4_CNTVR(i));
            }
            masksel <<= 1;
        }
    }

    if (c->flags & CS_ETMC_RES_SEL) {
        if (c->scv4->idr4.bits.numrspair > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = (c->scv4->idr4.bits.numrspair + 1) * 2;
            if (numregs > ETMv4_NUM_RES_SEL_CTL_MAX)
                numregs = ETMv4_NUM_RES_SEL_CTL_MAX;

            masksel = 0x4;	/* skip regs 0 and 1 as these are fixed and not accessible. */
            for (i = 2; i < numregs; i++) {
                if (masksel & c->rsctlr_acc_mask)
                    c->rsctlr[i] = _cs_read(d, CS_ETMV4_RSCTLR(i));
                masksel <<= 1;
            }
        }
        if (c->scv4->idr5.bits.numextinsel > 0) {
            c->extinselr = _cs_read(d, CS_ETMV4_EXTINSELR);
        }
    }

    if (c->flags & CS_ETMC_SSHOT_CTRL) {
        if (c->scv4->idr4.bits.numsscc > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr4.bits.numsscc;
            if (numregs > ETMv4_NUM_SS_COMP_MAX)
                numregs = ETMv4_NUM_SS_COMP_MAX;

            masksel = 0x1;
            for (i = 0; i < numregs; i++) {
                if (c->ss_comps_acc_mask & masksel) {
                    c->ss_comps[i].ssccr = _cs_read(d, CS_ETMV4_SSCCR(i));
                    c->ss_comps[i].sscsr = _cs_read(d, CS_ETMV4_SSCSR(i));
                    c->ss_comps[i].sspcicr =
                        _cs_read(d, CS_ETMV4_SSPCICR(i));
                }
                masksel <<= 1;
            }
        }
    }

    if (c->flags & CS_ETMC_ADDR_COMP) {
        if (c->scv4->idr4.bits.numacpairs > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr4.bits.numacpairs * 2;
            if (numregs > ETMv4_NUM_ADDR_COMP_MAX)
                numregs = ETMv4_NUM_ADDR_COMP_MAX;
            a_size =
                (c->scv4->idr2.bits.dasize ==
                 0x8) ? 64 : ((c->scv4->idr2.bits.iasize ==
                               0x8) ? 64 : 32);
            masksel = 0x1;
            for (i = 0; i < numregs; i++) {
                if (c->addr_comps_acc_mask & masksel) {
                    c->addr_comps[i].acvr_l =
                        _cs_read(d, CS_ETMV4_ACVR(i));
                    if (a_size == 64)
                        c->addr_comps[i].acvr_h =
                            _cs_read(d, CS_ETMV4_ACVR(i) + 4);
                    else
                        c->addr_comps[i].acvr_h = 0;
                    c->addr_comps[i].acatr_l =
                        _cs_read(d, CS_ETMV4_ACATR(i));
                }
                masksel <<= 1;
            }
        }
    }

    if (c->flags & CS_ETMC_DATA_COMP) {
        if (c->scv4->idr4.bits.numdvc > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr4.bits.numdvc;
            if (numregs > ETMv4_NUM_DATA_COMP_MAX)
                numregs = ETMv4_NUM_DATA_COMP_MAX;
            a_size = c->scv4->idr2.bits.dvsize == 0x8 ? 64 : 32;
            masksel = 0x1;
            for (i = 0; i < numregs; i++) {
                if (c->data_comps_acc_mask & masksel) {
                    c->data_comps[i].dvcvr_l =
                        _cs_read(d, CS_ETMV4_DVCVR(i));
                    c->data_comps[i].dvcmr_l =
                        _cs_read(d, CS_ETMV4_DVCMR(i));
                    if (a_size == 64) {
                        c->data_comps[i].dvcvr_h =
                            _cs_read(d, CS_ETMV4_DVCVR(i) + 4);
                        c->data_comps[i].dvcmr_h =
                            _cs_read(d, CS_ETMV4_DVCMR(i) + 4);
                    } else {
                        c->data_comps[i].dvcvr_h = 0;
                        c->data_comps[i].dvcmr_h = 0;
                    }
                }
                masksel <<= 1;
            }
        }
    }

    if (c->flags & CS_ETMC_CXID_COMP) {
        if (c->scv4->idr4.bits.numcidc > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr4.bits.numcidc;
            if (numregs > ETMv4_NUM_CXID_COMP_MAX)
                numregs = ETMv4_NUM_CXID_COMP_MAX;
            a_size = c->scv4->idr2.bits.cidsize == 0x8 ? 64 : 32;
            masksel = 0x1;
            for (i = 0; i < numregs; i++) {
                if (c->cxid_comps_acc_mask & masksel) {
                    c->cxid_comps[i].cidcvr_l =
                        _cs_read(d, CS_ETMV4_CIDCVR(i));
                    if (a_size == 64) {
                        c->cxid_comps[i].cidcvr_h =
                            _cs_read(d, CS_ETMV4_CIDCVR(i) + 4);
                    } else {
                        c->cxid_comps[i].cidcvr_h = 0;
                    }
                }
                masksel <<= 1;
            }
            c->cidcctlr0 = _cs_read(d, CS_ETMV4_CIDCCTLR0);
            c->cidcctlr1 = _cs_read(d, CS_ETMV4_CIDCCTLR1);
        }
    }

    if (c->flags & CS_ETMC_VMID_COMP) {
        if (c->scv4->idr4.bits.numvmidc > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr4.bits.numvmidc;
            if (numregs > ETMv4_NUM_VMID_COMP_MAX)
                numregs = ETMv4_NUM_VMID_COMP_MAX;
            a_size = c->scv4->idr2.bits.vmidsize == 0x8 ? 64 : 32;
            masksel = 0x1;
            for (i = 0; i < numregs; i++) {
                if (c->vmid_comps_acc_mask & masksel) {
                    c->vmid_comps[i].vmidcvr_l =
                        _cs_read(d, CS_ETMV4_VMIDCVR(i));
                    if (a_size == 64) {
                        c->vmid_comps[i].vmidcvr_h =
                            _cs_read(d, CS_ETMV4_VMIDCVR(i) + 4);
                    } else {
                        c->vmid_comps[i].vmidcvr_h = 0;
                    }
                }
                masksel <<= 1;
            }
            /* mask regs only exist if size > 8 bit. */
            if (c->scv4->idr2.bits.vmidsize > 0x1) {
                c->vmidcctlr0 = _cs_read(d, CS_ETMV4_VMIDCCTLR0);
                c->vmidcctlr1 = _cs_read(d, CS_ETMV4_VMIDCCTLR1);
            }
        }
    }

    return rc;
}

int _cs_etm_v4_config_put(struct cs_device *d, cs_etmv4_config_t * c)
{
    int rc = 0;
    int i, numregs, a_size;
    unsigned int masksel /*,a_mask */ ;

    assert(d->type == DEV_ETM);
    assert(CS_ETMVERSION_MAJOR(_cs_etm_version(d)) >= CS_ETMVERSION_ETMv4);

    _cs_etm_enable_programming(d);

    /* general configuration */
    if (c->flags & CS_ETMC_CONFIG) {
        _cs_write(d, CS_ETMV4_CONFIGR, c->configr.reg);

        /* write if implemented */
        if (c->scv4->idr3.bits.stallctl) {
            _cs_write(d, CS_ETMV4_STALLCTLR, c->stallcrlr);
        }
        _cs_write(d, CS_ETMV4_SYNCPR, c->syncpr);
        if (c->scv4->idr0.bits.trccci) {
            _cs_write(d, CS_ETMV4_CCCTLR, c->ccctlr);
        }
        if ((c->scv4->idr0.bits.trcbb == 1)
            && (c->scv4->idr4.bits.numacpairs > 0)) {
            _cs_write(d, CS_ETMV4_BBCTLR, c->bbctlr);
        }
        if (c->scv4->idr0.bits.qfilt) {
            _cs_write(d, CS_ETMV4_QCTLR, c->qctlr);
        }
        _cs_write(d, CS_ETMV4_TRACEIDR,
                  c->traceidr & BITMASK(c->scv4->idr5.bits.traceidsize));
    }

    if (c->flags & CS_ETMC_EVENTSELECT) {
        _cs_write(d, CS_ETMV4_EVENTCTL0R, c->eventctlr0r);
        _cs_write(d, CS_ETMV4_EVENTCTL1R, c->eventctlr1r);
        if (c->scv4->idr0.bits.tssize > 0) {
            _cs_write(d, CS_ETMV4_TSCTLR, c->tsctlr);
        }
    }

    if (c->flags & CS_ETMC_TRACE_ENABLE) {
        _cs_write(d, CS_ETMV4_VICTLR, c->victlr);
        _cs_write(d, CS_ETMV4_VIIECTLR, c->viiectlr);
        _cs_write(d, CS_ETMV4_VISSCTLR, c->vissctlr);
        _cs_write(d, CS_ETMV4_VIPSSCTLR, c->vipcssctlr);

        if (c->scv4->idr0.bits.trcdata != 0) {
            _cs_write(d, CS_ETMV4_VDCTLR, c->vdctlr);
            _cs_write(d, CS_ETMV4_VDSACCTLR, c->vdsacctlr);
            _cs_write(d, CS_ETMV4_VDARCCTLR, c->vdarcctlr);
        }
    }

    if ((c->flags & CS_ETMC_SEQUENCER)
        && (c->scv4->idr5.bits.numseqstate > 0)) {
        /* use the actual number, unless greater than the storage we have. */
        numregs = c->scv4->idr5.bits.numseqstate - 1;
        if (numregs > ETMv4_NUM_SEQ_EVT_MAX)
            numregs = ETMv4_NUM_SEQ_EVT_MAX;

        for (i = 0; i < numregs; i++) {
            _cs_write(d, CS_ETMV4_SEQEVR(i), c->seqevr[i]);
        }
        _cs_write(d, CS_ETMV4_SEQRSTEVR, c->seqrstevr);
        _cs_write(d, CS_ETMV4_SEQSTR, c->seqstr);
    }

    if ((c->flags & CS_ETMC_COUNTER) && (c->scv4->idr5.bits.numcntr > 0)) {
        /* use the actual number, unless greater than the storage we have. */
        numregs = c->scv4->idr5.bits.numcntr;
        if (numregs > ETMv4_NUM_COUNTERS_MAX)
            numregs = ETMv4_NUM_COUNTERS_MAX;

        masksel = 0x1;

        for (i = 0; i < numregs; i++) {
            if (c->counter_acc_mask & masksel) {
                _cs_write(d, CS_ETMV4_CNTRLDVR(i), c->counter[i].cntrldvr);
                _cs_write(d, CS_ETMV4_CNTCTLR(i), c->counter[i].cntctlr);
                _cs_write(d, CS_ETMV4_CNTVR(i), c->counter[i].cntvr);
            }
            masksel <<= 1;
        }
    }

    if (c->flags & CS_ETMC_RES_SEL) {
        if (c->scv4->idr4.bits.numrspair > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = (c->scv4->idr4.bits.numrspair + 1) * 2;
            if (numregs > ETMv4_NUM_RES_SEL_CTL_MAX)
                numregs = ETMv4_NUM_RES_SEL_CTL_MAX;

            masksel = 0x4;	/* skip regs 0 and 1 as these are fixed and not accessible. */
            for (i = 2; i < numregs; i++) {
                if (masksel & c->rsctlr_acc_mask)
                    _cs_write(d, CS_ETMV4_RSCTLR(i), c->rsctlr[i]);
                masksel <<= 1;
            }
        }
        if (c->scv4->idr5.bits.numextinsel > 0) {
            _cs_write(d, CS_ETMV4_EXTINSELR, c->extinselr);
        }
    }



    if (c->flags & CS_ETMC_SSHOT_CTRL) {
        if (c->scv4->idr4.bits.numsscc > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr4.bits.numsscc;
            if (numregs > ETMv4_NUM_SS_COMP_MAX)
                numregs = ETMv4_NUM_SS_COMP_MAX;

            masksel = 0x1;
            for (i = 0; i < numregs; i++) {
                if (c->ss_comps_acc_mask & masksel) {
                    _cs_write(d, CS_ETMV4_SSCCR(i), c->ss_comps[i].ssccr);
                    _cs_write(d, CS_ETMV4_SSCSR(i), c->ss_comps[i].sscsr);
                    _cs_write(d, CS_ETMV4_SSPCICR(i),
                              c->ss_comps[i].sspcicr);
                }
                masksel <<= 1;
            }
        }
    }

    if (c->flags & CS_ETMC_ADDR_COMP) {
        if (c->scv4->idr4.bits.numacpairs > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr4.bits.numacpairs * 2;
            if (numregs > ETMv4_NUM_ADDR_COMP_MAX)
                numregs = ETMv4_NUM_ADDR_COMP_MAX;
            /* if no data addr comp and 64 bit IA, ensure top bytes 0x0000 or 0xFFFF (see ETMv4 TRM 7.3.2) */
            /*a_mask = ((c->scv4->idr2.bits.dasize == 0x0)  && (c->scv4->idr2.bits.iasize == 0x8)) ? 0x0000FFFF : 0xFFFFFFFF; */
            masksel = 0x1;
            for (i = 0; i < numregs; i++) {
                if (c->addr_comps_acc_mask & masksel) {
                    _cs_write(d, CS_ETMV4_ACVR(i),
                              c->addr_comps[i].acvr_l);
                    _cs_write(d, CS_ETMV4_ACVR(i) + 4,
                              c->addr_comps[i].acvr_h /*& a_mask */ );
                    _cs_write(d, CS_ETMV4_ACATR(i),
                              c->addr_comps[i].acatr_l);
                }
                masksel <<= 1;
            }
        }
    }

    if (c->flags & CS_ETMC_DATA_COMP) {
        if (c->scv4->idr4.bits.numdvc > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr4.bits.numdvc;
            if (numregs > ETMv4_NUM_DATA_COMP_MAX)
                numregs = ETMv4_NUM_DATA_COMP_MAX;
            a_size = c->scv4->idr2.bits.dvsize == 0x8 ? 64 : 32;
            masksel = 0x1;
            for (i = 0; i < numregs; i++) {
                if (c->data_comps_acc_mask & masksel) {
                    /* write and force masked bits to 0 in value (TRM 7.3.25) */
                    _cs_write(d, CS_ETMV4_DVCVR(i),
                              c->data_comps[i].dvcvr_l & ~c->data_comps[i].
                              dvcmr_l);
                    _cs_write(d, CS_ETMV4_DVCMR(i),
                              c->data_comps[i].dvcmr_l);
                    if (a_size == 64) {
                        _cs_write(d, CS_ETMV4_DVCVR(i) + 4,
                                  c->data_comps[i].dvcvr_h & ~c->
                                  data_comps[i].dvcmr_h);
                        _cs_write(d, CS_ETMV4_DVCMR(i) + 4,
                                  c->data_comps[i].dvcmr_h);
                    }
                }
                masksel <<= 1;
            }

        }
    }

    if (c->flags & CS_ETMC_CXID_COMP) {
        if (c->scv4->idr4.bits.numcidc > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr4.bits.numcidc;
            if (numregs > ETMv4_NUM_CXID_COMP_MAX)
                numregs = ETMv4_NUM_CXID_COMP_MAX;
            a_size = c->scv4->idr2.bits.cidsize == 0x8 ? 64 : 32;
            masksel = 0x1;
            for (i = 0; i < numregs; i++) {
                if (c->cxid_comps_acc_mask & masksel) {
                    _cs_write(d, CS_ETMV4_CIDCVR(i),
                              c->cxid_comps[i].cidcvr_l);
                    if (a_size == 64) {
                        _cs_write(d, CS_ETMV4_CIDCVR(i) + 4,
                                  c->cxid_comps[i].cidcvr_h);
                    }
                }
                masksel <<= 1;
            }
            _cs_write(d, CS_ETMV4_CIDCCTLR0, c->cidcctlr0);
            _cs_write(d, CS_ETMV4_CIDCCTLR1, c->cidcctlr1);
        }
    }

    if (c->flags & CS_ETMC_VMID_COMP) {
        if (c->scv4->idr4.bits.numvmidc > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr4.bits.numvmidc;
            if (numregs > ETMv4_NUM_VMID_COMP_MAX)
                numregs = ETMv4_NUM_VMID_COMP_MAX;
            a_size = c->scv4->idr2.bits.vmidsize == 0x8 ? 64 : 32;
            masksel = 0x1;
            for (i = 0; i < numregs; i++) {
                if (c->vmid_comps_acc_mask & masksel) {
                    _cs_write(d, CS_ETMV4_VMIDCVR(i),
                              c->vmid_comps[i].vmidcvr_l);
                    if (a_size == 64) {
                        _cs_write(d, CS_ETMV4_VMIDCVR(i) + 4,
                                  c->vmid_comps[i].vmidcvr_h);
                    }
                }
                masksel <<= 1;
            }
            if (c->scv4->idr2.bits.vmidsize > 0x1) {
                _cs_write(d, CS_ETMV4_VMIDCCTLR0, c->vmidcctlr0);
                _cs_write(d, CS_ETMV4_VMIDCCTLR1, c->vmidcctlr1);
            }
        }
    }
    return rc;
}

int _cs_etm_v4_clean(struct cs_device *d)
{
    int rc = -1;
    cs_etmv4_config_t c;

    /* a zeroed config structure is close to clean */
    rc = _cs_etm_v4_config_init(d, &c);
    if (rc == 0) {
        c.flags = CS_ETMC_CONFIG;
        rc = _cs_etm_v4_config_get(d, &c);	/* get key registers */
    }

    if (rc == 0) {
        /* zero out the current general config, preserving trace ID */
        c.configr.reg = 0;
        c.stallcrlr = 0;
        c.syncpr = 0;
        c.ccctlr = 0;
        c.bbctlr = 0;
        c.qctlr = 0;

        /* select the entire config for writing to target */
        _cs_etm_v4_config_sel_all(&c);
        rc = _cs_etm_v4_config_put(d, &c);
    }

    return rc;
}

int _cs_etm_v4_enable_programming(struct cs_device *d)
{
    int rc = 0;
    unsigned int regval;

    _cs_unlock(d);		/* lsr unlock */

    regval = _cs_read(d, CS_ETMv4_PDSR);
    if ((regval & CS_ETMv4_PDSR_PowerUp) == 0) {
        rc = _cs_write(d, CS_ETMv4_PDCR, 0x8);	/* power it up */
        if (rc == 0)
            rc = _cs_wait(d, CS_ETMv4_PDSR, CS_ETMv4_PDSR_PowerUp);
    }

    if (rc == 0) {
        regval = _cs_read(d, CS_ETMv4_OSLSR);
        if (regval & 0x2)	/* OS locked */
            rc = _cs_write(d, CS_ETMv4_OSLAR, 0);
    }

    if (rc == 0) {
        _cs_claim(d, CS_CLAIM_INTERNAL);
        rc = _cs_write(d, CS_ETMV4_PRGCTLR, 0);	/* disable trace */
    }
    if (rc == 0)
        rc = _cs_wait(d, CS_ETMV4_STATR, CS_ETMV4_STATR_idle);	/* wait for idle bit */
    return rc;
}

int _cs_etm_v4_disable_programming(struct cs_device *d)
{
    int rc = 0;
    _cs_unlock(d);
    rc = _cs_write(d, CS_ETMV4_PRGCTLR, CS_ETMV4_PRGCTLR_en);	/* enable trace */
    return rc;
}

cs_etm_v4_static_config_t *get_etmv4_sc_ptr(cs_etm_static_config_t *
                                            sc_ptr)
{
    return (cs_etm_v4_static_config_t *) (sc_ptr->p_cfg_ext);
}

#ifndef UNIX_KERNEL
int _etmv4_edesc(unsigned int eventval, char *pstr)
{
    int regidx = 0;
    int chprinted = 0;

    /* default */
    if (eventval & 0x80) {
        regidx = eventval & 0xF;
        if (regidx != 0) {
            chprinted =
                sprintf(pstr, "[Pair]: RSCTLR%i RSCTLR%i", regidx * 2,
                        regidx * 2 + 1);
        } else
            chprinted = sprintf(pstr, "Reserved Value");

    } else {
        regidx = eventval & 0x1F;
        if (regidx > 1)
            chprinted = sprintf(pstr, "[Single]: RSCTLR%i", regidx);
        else
            chprinted =
                sprintf(pstr, "[Single]: %s",
                        regidx == 1 ? "ALWAYS" : "NEVER");
    }

    return chprinted;
}

int _bitnums_as_str(int bits, unsigned int value, char *pstr)
{
    int i, have_1, ch_printed;
    unsigned int mask;

    have_1 = 0;
    mask = 1;
    if (bits > 31)
        bits = 31;
    ch_printed = 0;

    for (i = 0; i < bits; i++) {
        if (value & mask) {
            if (have_1)
                ch_printed += sprintf(pstr + ch_printed, ", %d", i);
            else
                ch_printed += sprintf(pstr + ch_printed, "%d", i);
            have_1 = 1;
        }
        mask <<= 1;
    }
    if (!have_1)
        ch_printed += sprintf(pstr + ch_printed, "none");
    return ch_printed;
}

int _el_desc(unsigned int els, char *pstr)
{
    unsigned int mask;
    int i, ch_printed;

    ch_printed = 0;

    if (els != 0) {
        mask = 1;
        ch_printed += sprintf(pstr + ch_printed, "[");
        for (i = 0; i < 4; i++) {
            if (els & mask) {
                ch_printed += sprintf(pstr + ch_printed, "EL%d ", i);
            }
            mask <<= 1;
        }
        ch_printed += sprintf(pstr + ch_printed, "]");
    } else
        ch_printed += sprintf(pstr + ch_printed, "[none]");

    return ch_printed;
}

int _sel_desc(int regnum, unsigned int selector, char *pstr)
{
    unsigned int group, select, inv, pairinv;
    int valid = 0, ch_printed = 0;
    char buf1[128];

    group = (selector >> 16) & 0xF;
    select = selector & 0xFFFF;
    inv = (selector >> 20) & 0x1;
    pairinv = (((selector >> 21) & 0x1) && (regnum % 2 == 0)) ? 1 : 0;
    ch_printed += sprintf(pstr, "[%01X:%04X : ", group, select);

    if ((select & 0xFF) == 0) {
        ch_printed += sprintf(pstr + ch_printed, "no resource selected");
        valid = 1;
    } else {
        switch (group) {
        case 0:
            if (select <= 0xF) {	/* 4 valid bits */
                _bitnums_as_str(4, select, buf1);
                ch_printed += sprintf(pstr + ch_printed, "EXTIN %s", buf1);
                valid = 1;
            }
            break;

        case 1:
            if (select <= 0xFF) {	/* 8 valid bits */
                _bitnums_as_str(8, select, buf1);
                ch_printed +=
                    sprintf(pstr + ch_printed, "PE Comp input %s", buf1);
                valid = 1;
            }
            break;

        case 2:
            if (select <= 0xFF) {	/* 8 valid bits */
                valid = 1;
                _bitnums_as_str(4, select, buf1);
                ch_printed +=
                    sprintf(pstr + ch_printed, "CountZ { %s };", buf1);
                _bitnums_as_str(4, select >> 4, buf1);
                ch_printed +=
                    sprintf(pstr + ch_printed, " Seq States { %s }", buf1);

            }
            break;

        case 3:
            if (select <= 0xFF) {	/* 8 valid bits */
                valid = 1;
                _bitnums_as_str(8, select, buf1);
                ch_printed +=
                    sprintf(pstr + ch_printed, "Single Shot Comp: %s ",
                            buf1);
            }
            break;

        case 4:		/* 16 valid bits */
            valid = 1;
            _bitnums_as_str(16, select, buf1);
            ch_printed +=
                sprintf(pstr + ch_printed, "Single Addr Comp: %s", buf1);
            break;

        case 5:
            if (select <= 0xFF) {	/* 8 valid bits */
                valid = 1;
                _bitnums_as_str(8, select, buf1);
                ch_printed +=
                    sprintf(pstr + ch_printed, "Addr Range Comp: %s",
                            buf1);
            }
            break;

        case 6:
            if (select <= 0xFF) {	/* 8 valid bits */
                valid = 1;
                _bitnums_as_str(8, select, buf1);
                ch_printed +=
                    sprintf(pstr + ch_printed, "Cxt ID Comp: %s", buf1);
            }
            break;

        case 7:
            if (select <= 0xFF) {	/* 8 valid bits */
                valid = 1;
                _bitnums_as_str(8, select, buf1);
                ch_printed +=
                    sprintf(pstr + ch_printed, "VMID Comp: %s", buf1);
            }
            break;

        default:
            break;

        }
    }

    if (!valid)
        ch_printed += sprintf(pstr + ch_printed, "Reserved Value");

    ch_printed += sprintf(pstr + ch_printed, " ]");
    if (valid) {
        ch_printed +=
            sprintf(pstr + ch_printed, " %s%s", inv ? "INV " : "",
                    pairinv ? " PAIRINV" : "");
    }
    return ch_printed;
}

/* print according to selection flags */
int _cs_etm_v4_config_print(struct cs_device *d, cs_etmv4_config_t * c)
{
    int i, numregs, a_size;
    unsigned int masksel;
    static char sz_buf1[256], sz_buf2[128];
    static char *inst_p0_sz[] = {
        "Trace LD & ST instructions as P0 off",
        "Trace LD instructions as P0",
        "Trace ST instructions as P0",
        "Trace LD & ST instructions as P0"
    };
    static char *cond_sz[] = {
        "disabled",
        "LD instr traced",
        "ST instr traced",
        "LD & ST instr traced",
        "reserved value", "reserved value", "reserved value",
        "All instr traced"
    };
    static char *qe_sz[] = {
        "disabled",
        "QE with instruction counts enabled",
        "reserved value",
        "All QE enabled"
    };

    assert(d->type == DEV_ETM);
    assert(CS_ETMVERSION_MAJOR(_cs_etm_version(d)) >= CS_ETMVERSION_ETMv4);
    if (c->flags == 0) {
        printf("ETM config print : no data selected for print\n");
        return -1;
    }

    /* print static if 'all' */
    if (c->flags == CS_ETMC_ALL) {
        printf("ETMv4 static configuration:\n");
        printf("\tIDR0 = %08X\n", c->scv4->idr0.reg);
        printf("\tIDR1 = %08X\n", c->scv4->idr1.reg);
        printf("\tIDR2 = %08X\n", c->scv4->idr2.reg);
        printf("\tIDR3 = %08X\n", c->scv4->idr3.reg);
        printf("\tIDR4 = %08X\n", c->scv4->idr4.reg);
        printf("\tIDR5 = %08X\n", c->scv4->idr5.reg);
    }

    printf("ETMv4 dynamic configuration:\n");

    /* general configuration */
    if (c->flags & CS_ETMC_CONFIG) {
        printf("\n===General configuration===\n");
        printf("\tTRACEIDR = %08X\n", c->traceidr);
        printf("\tCONFIGR = %08X\n", c->configr.reg);
        printf("\t\t.instp0 = %X (%s)\n", c->configr.bits.instp0,
               inst_p0_sz[c->configr.bits.instp0]);
        printf("\t\t.bb     = %X (Branch Broadcast %s)\n",
               c->configr.bits.bb,
               c->configr.bits.bb == 1 ? "enabled" : "disabled");
        printf("\t\t.cci    = %X (Cycle Count instruction trace %s)\n",
               c->configr.bits.cci,
               c->configr.bits.cci == 1 ? "enabled" : "disabled");
        printf("\t\t.cid    = %X (Context ID trace %s)\n",
               c->configr.bits.cid,
               c->configr.bits.cid == 1 ? "enabled" : "disabled");
        printf("\t\t.vmid   = %X (VMID trace %s)\n", c->configr.bits.vmid,
               c->configr.bits.vmid == 1 ? "enabled" : "disabled");
        printf("\t\t.cond   = %X (Conditional instuction trace: %s)\n",
               c->configr.bits.cond, cond_sz[c->configr.bits.cond]);
        printf("\t\t.ts     = %X (Global timestamp trace %s)\n",
               c->configr.bits.ts,
               c->configr.bits.ts == 1 ? "enabled" : "disabled");
        printf("\t\t.rs     = %X (Return Stack %s)\n", c->configr.bits.rs,
               c->configr.bits.rs == 1 ? "enabled" : "disabled");
        printf("\t\t.qe     = %X (Q element trace: %s\n",
               c->configr.bits.qe, qe_sz[c->configr.bits.qe]);
        printf("\t\t.da     = %X (Data address trace %s)\n",
               c->configr.bits.da,
               c->configr.bits.da == 1 ? "enabled" : "disabled");
        printf("\t\t.dv     = %X (Data value trace %s)\n",
               c->configr.bits.dv,
               c->configr.bits.dv == 1 ? "enabled" : "disabled");

        if (c->scv4->idr3.bits.stallctl)
            printf("\tSTALLCTLR = %08X\n", c->stallcrlr);
        else
            printf("\tSTALLCTLR not implemented.\n");

        printf("\tSYNCPR = %02X\n", c->syncpr);

        if (c->scv4->idr0.bits.trccci)
            printf("\tCCCTLR = %03X (Cycle Count control)\n", c->ccctlr);
        else
            printf("\tCCCTLR not implemented.\n");

        if ((c->scv4->idr0.bits.trcbb == 1)
            && (c->scv4->idr4.bits.numacpairs > 0))
            printf("\tBBCTLR = %03X (Branch Broadcast control)\n",
                   c->bbctlr);
        else
            printf("\tBBCTLR not implemented.\n");

        if (c->scv4->idr0.bits.qfilt)
            printf("\tQCTLR = %03X (Q element control)\n", c->qctlr);
        else
            printf("\tQCTLR not implemented.\n");
    }

    if (c->flags & CS_ETMC_EVENTSELECT) {
        printf("\n===Event Select===\n");
        printf("\tEVENTCTL0R = %08X\n", c->eventctlr0r);
        for (i = 0; i <= c->scv4->idr0.bits.numevent; i++) {
            _etmv4_edesc((c->eventctlr0r >> (8 * i)) & 0xFF, sz_buf1);
            printf("\t\tEvent%i=%s\n", i, sz_buf1);
        }

        printf("\tEVENTCTL1R = %08X\n", c->eventctlr1r);
        printf
            ("\t\t.insten = %01X: Instr Trace event element on events - ",
             c->eventctlr1r & 0xF);
        if ((c->eventctlr1r & BITMASK(c->scv4->idr0.bits.numevent)) == 0)
            printf("disabled\n");
        else {
            masksel = 0x1;
            for (i = 0; i <= c->scv4->idr0.bits.numevent; i++) {
                if (c->eventctlr1r & masksel)
                    printf("%d ", i);
                masksel <<= 1;
            }
            printf("\n");
        }
        printf("\t\t.dataen = %d: Data trace element %s\n",
               (c->eventctlr1r >> 4) & 0x1,
               c->eventctlr1r & 0x10 ? "on event 0" : "disabled");
        printf("\t\t.atb = %d: ATB trace trigger %s\n",
               (c->eventctlr1r >> 11) & 0x1,
               (c->eventctlr1r >> 11) & 0x1 ? "enabled" : "disabled");

        if (c->scv4->idr0.bits.tssize > 0) {
            _etmv4_edesc(c->tsctlr & 0xFF, sz_buf1);
            printf("\tTSCTLR = %02X (Event = %s)\n", c->tsctlr, sz_buf1);
        } else
            printf("\tTSCTLR not implemented\n");
    }

    if (c->flags & CS_ETMC_TRACE_ENABLE) {
        printf("\n===Trace Enables===\n");
        _etmv4_edesc(c->victlr & 0xFF, sz_buf1);
        printf("\tVICTLR = %08X (ViewInst Event = %s)\n", c->victlr,
               sz_buf1);
        _el_desc((c->victlr >> 16) & 0xB, sz_buf1);
        _el_desc((c->victlr >> 20) & 0x7, sz_buf2);
        printf
            ("\t.exlevel_s = %01X, ELs off:%s\n\t.exlevel_ns = %01X, ELs off:%s\n",
             (c->victlr >> 16) & 0xF, sz_buf1, (c->victlr >> 20) & 0xF,
             sz_buf2);
        printf("\t.ssstatus = %d (StartStop = %s)\n",
               (c->victlr >> 9) & 0x1,
               (c->victlr & 0x200) ? "started" : "stopped");
        printf("\tVIIECTLR = %08X\n", c->viiectlr);
        printf("\tVISSCTLR = %08X\n", c->vissctlr);
        printf("\tVIPCSSCTLR = %08X\n", c->vipcssctlr);

        if (c->scv4->idr0.bits.trcdata != 0) {
            _etmv4_edesc(c->vdctlr & 0xFF, sz_buf1);
            printf("\tVDCTLR = %08X (ViewData Event = %s)\n", c->vdctlr,
                   sz_buf1);
            printf("\tVDSACCTLR = %08X\n", c->vdsacctlr);
            printf("\tVDARCCTLR = %08X\n", c->vdarcctlr);
        } else
            printf("\tData trace not implemented\n");
    }

    if (c->flags & CS_ETMC_SEQUENCER) {
        if (c->scv4->idr5.bits.numseqstate > 0) {
            printf("\n===Sequencer===\n");
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr5.bits.numseqstate - 1;
            if (numregs > ETMv4_NUM_SEQ_EVT_MAX)
                numregs = ETMv4_NUM_SEQ_EVT_MAX;
            for (i = 0; i < numregs; i++) {
                _etmv4_edesc(c->seqevr[i] & 0xFF, sz_buf1);
                _etmv4_edesc((c->seqevr[i] >> 8) & 0xFF, sz_buf2);
                printf
                    ("\tSEQEVR%d = %08X, (Event-F %d->%d = %s; Event-B %d<-%d = %s)\n",
                     i, c->seqevr[i], i, i + 1, sz_buf1, i, i + 1,
                     sz_buf2);
            }
            _etmv4_edesc(c->seqrstevr & 0xFF, sz_buf1);
            printf("\tSEQRSTEVR = %02X, (Seqencer Reset Event = %s)\n",
                   c->seqrstevr, sz_buf1);
            printf("\tSEQSTR = %01X\n", c->seqstr);
        } else
            printf("\n===Sequencer not implemented===\n");
    }


    if (c->flags & CS_ETMC_COUNTER) {
        if (c->scv4->idr5.bits.numcntr > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr5.bits.numcntr;
            if (numregs > ETMv4_NUM_COUNTERS_MAX)
                numregs = ETMv4_NUM_COUNTERS_MAX;

            printf("\n===Counters (%d)===\n", numregs);

            masksel = 0x1;

            for (i = 0; i < numregs; i++) {
                if (c->counter_acc_mask & masksel) {
                    _etmv4_edesc(c->counter[i].cntctlr & 0xFF, sz_buf1);
                    _etmv4_edesc((c->counter[i].cntctlr >> 8) & 0xFF,
                                 sz_buf2);
                    printf
                        ("\tCNTCTLR%d = %08X, (%s%sCount Event = %s; Reload Event = %s)\n",
                         i, c->counter[i].cntctlr,
                         c->counter[i].
                         cntctlr & CS_ETMV4_CNTCTLR_chain ? " chain; " :
                         "",
                         c->counter[i].
                         cntctlr & CS_ETMV4_CNTCTLR_rldself ? " rldself; "
                         : "", sz_buf1, sz_buf2);
                    printf("\tCNTRLDVR%d = %04X (Reload Value)\n", i,
                           c->counter[i].cntrldvr);
                    printf("\tCNTVR%d = %04X (Counter Value)\n", i,
                           c->counter[i].cntvr);
                }
                masksel <<= 1;
            }
        } else
            printf("\n===Counters not implemented===\n");
    }

    if (c->flags & CS_ETMC_RES_SEL) {
        printf("\n===Resource Selection Registers (%d) ===\n",
               (c->scv4->idr4.bits.numrspair + 1) * 2);
        printf("\tRSCTLR0 => Fixed resource = FALSE / NEVER\n");
        printf("\tRSCTLR1 => Fixed resource = TRUE  / ALWAYS\n");

        if (c->scv4->idr4.bits.numrspair > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = (c->scv4->idr4.bits.numrspair + 1) * 2;
            if (numregs > ETMv4_NUM_RES_SEL_CTL_MAX)
                numregs = ETMv4_NUM_RES_SEL_CTL_MAX;

            masksel = 0x4;	/* skip regs 0 and 1 as these are fixed and not accessible. */
            for (i = 2; i < numregs; i++) {
                if (masksel & c->rsctlr_acc_mask) {
                    _sel_desc(i, c->rsctlr[i], sz_buf1);
                    printf("\tRSCTLR%d = %08X (%s)\n", i, c->rsctlr[i],
                           sz_buf1);
                }
                masksel <<= 1;
            }
        }

        if (c->scv4->idr5.bits.numextinsel > 0) {
            printf("\n=== External inputs===\n");
            printf("\tEXTINSELR = %08X\n", c->extinselr);
        } else
            printf("\n=== External inputs not implemented===\n");
    }

    if (c->flags & CS_ETMC_SSHOT_CTRL) {
        if (c->scv4->idr4.bits.numsscc > 0) {

            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr4.bits.numsscc;
            if (numregs > ETMv4_NUM_SS_COMP_MAX)
                numregs = ETMv4_NUM_SS_COMP_MAX;
            printf("\n===Single Shot Comparators (%d)===\n", numregs);

            masksel = 0x1;
            for (i = 0; i < numregs; i++) {
                if (c->ss_comps_acc_mask & masksel) {
                    _bitnums_as_str(8, (c->ss_comps[i].ssccr >> 16) & 0xFF,
                                    sz_buf2);
                    _bitnums_as_str(16, c->ss_comps[i].ssccr & 0xFFFF,
                                    sz_buf1);

                    printf
                        ("\tSSCCR%d = %08X, (ARPair=%02X [%s], ACSingle=%04X [%s] RST=%d)\n",
                         i, c->ss_comps[i].ssccr,
                         (c->ss_comps[i].ssccr >> 16) & 0xFF, sz_buf2,
                         c->ss_comps[i].ssccr & 0xFFFF, sz_buf1,
                         (c->ss_comps[i].ssccr >> 24) & 0x1);
                    printf
                        ("\tSSCSR%d = %08X, (Status=%d, Support: PC:%s; DV:%s, DA:%s, INST:%s)\n",
                         i, c->ss_comps[i].sscsr,
                         (c->ss_comps[i].sscsr >> 31) & 0x1,
                         ((c->ss_comps[i].sscsr >> 3) & 0x1) ? "Y" : "N",
                         ((c->ss_comps[i].sscsr >> 2) & 0x1) ? "Y" : "N",
                         ((c->ss_comps[i].sscsr >> 1) & 0x1) ? "Y" : "N",
                         (c->ss_comps[i].sscsr & 0x1) ? "Y" : "N");
                    printf("\tSSPCOCR%d = %08X\n", i,
                           c->ss_comps[i].sspcicr);
                }
                masksel <<= 1;
            }
        } else
            printf("\n===Single Shot Comps not implemented===\n");
    }

    if (c->flags & CS_ETMC_ADDR_COMP) {
        static char const *const tname[4] =
            { "I Addr", "D LD Addr", "D ST Addr", "D LD or ST Addr" };
        static char const *const ctxttname[4] =
            { "None", "CXTID", "VMID", "CXTID & VMID" };
        static char const *const dm_name[4] =
            { "None", "Identical", "Reserved", "Different" };
        static char const *const ds_name[4] =
            { "Byte", "Halfword", "Word", "DoubleWord" };


        if (c->scv4->idr4.bits.numacpairs > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr4.bits.numacpairs * 2;
            printf("\n===Address Comparators (%d)===\n", numregs);
            if (numregs > ETMv4_NUM_ADDR_COMP_MAX)
                numregs = ETMv4_NUM_ADDR_COMP_MAX;
            a_size =
                (c->scv4->idr2.bits.dasize ==
                 0x8) ? 64 : ((c->scv4->idr2.bits.iasize ==
                               0x8) ? 64 : 32);
            masksel = 0x1;
            for (i = 0; i < numregs; i++) {
                if (c->addr_comps_acc_mask & masksel) {
                    printf("\tACVR%d = ", i);
                    if (a_size == 64)
                        printf("%08X", c->addr_comps[i].acvr_h);
                    printf("%08X\n", c->addr_comps[i].acvr_l);
                    printf
                        ("\tACATR%d = %08X, (Type:%s, Context: %s Ctxt-comp %d,",
                         i, c->addr_comps[i].acatr_l,
                         tname[(c->addr_comps[i].acatr_l) & 0x3],
                         ctxttname[(c->addr_comps[i].acatr_l >> 2) & 0x3],
                         (c->addr_comps[i].acatr_l >> 4) & 0x7);
                    _el_desc((c->addr_comps[i].acatr_l >> 8) & 0xF,
                             sz_buf1);
                    _el_desc((c->addr_comps[i].acatr_l >> 12) & 0xF,
                             sz_buf2);
                    printf("Excl ELs_S%s, Excl ELs_NS%s,", sz_buf1,
                           sz_buf2);
                    if ((c->scv4->idr4.bits.numdvc > 0)
                        && (i / 2 <= (c->scv4->idr4.bits.numdvc - 1))) {
                        if (i % 2 == 0)
                            printf("Data: Match-%s; Size-%s; %s )\n",
                                   dm_name[(c->addr_comps[i].
                                            acatr_l >> 16) & 0x3],
                                   ds_name[(c->addr_comps[i].
                                            acatr_l >> 18) & 0x3],
                                   (c->addr_comps[i].
                                    acatr_l & 0x100000) ? "Range AC" :
                                   "Single AC");
                        else
                            printf("Data: See ACATR%d )\n", i - 1);
                    } else
                        printf("Data: No Data Value Comp)\n");

                }
                masksel <<= 1;
            }

        } else
            printf("\n===Address Comparators Not Implemented===\n");
    }

    if (c->flags & CS_ETMC_DATA_COMP) {
        if (c->scv4->idr4.bits.numdvc > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr4.bits.numdvc;
            if (numregs > ETMv4_NUM_DATA_COMP_MAX)
                numregs = ETMv4_NUM_DATA_COMP_MAX;
            printf("\n===Data Value Comparators (%d)===\n", numregs);

            a_size = c->scv4->idr2.bits.dvsize == 0x8 ? 64 : 32;
            masksel = 0x1;
            for (i = 0; i < numregs; i++) {
                if (c->data_comps_acc_mask & masksel) {
                    printf("\tDVCVR%d = ", i);
                    if (a_size == 64)
                        printf("%08X", c->data_comps[i].dvcvr_h);
                    printf("%08X\n", c->data_comps[i].dvcvr_l);

                    printf("\tDVCMR%d = ", i);
                    if (a_size == 64)
                        printf("%08X", c->data_comps[i].dvcmr_h);
                    printf("%08X\n", c->data_comps[i].dvcmr_l);
                }
                masksel <<= 1;
            }

        } else
            printf("\n===Data Value Comparators not implemented===\n");
    }

    if (c->flags & CS_ETMC_CXID_COMP) {
        if (c->scv4->idr4.bits.numcidc > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr4.bits.numcidc;
            if (numregs > ETMv4_NUM_CXID_COMP_MAX)
                numregs = ETMv4_NUM_CXID_COMP_MAX;
            printf("\n===Context ID Comparators (%d)===\n", numregs);
            masksel = 0x1;
            for (i = 0; i < numregs; i++) {
                if (c->cxid_comps_acc_mask & masksel) {
                    printf("\tCIDCVR%d = %08X\n", i,
                           c->cxid_comps[i].cidcvr_l);
                }
                masksel <<= 1;
            }
            printf("\tCIDCCTLR0 = %08X, (Byte Mask Comps 0-3)\n",
                   c->cidcctlr0);
            printf("\tCIDCCTLR1 = %08X, (Byte Mask Comps 4-7)\n",
                   c->cidcctlr1);
        } else
            printf("\n===Context ID Comparators Not Implemented===\n");
    }

    if (c->flags & CS_ETMC_VMID_COMP) {
        if (c->scv4->idr4.bits.numvmidc > 0) {
            /* use the actual number, unless greater than the storage we have. */
            numregs = c->scv4->idr4.bits.numvmidc;
            if (numregs > ETMv4_NUM_VMID_COMP_MAX)
                numregs = ETMv4_NUM_VMID_COMP_MAX;
            printf("\n===VMID Comparators (%d)===\n", numregs);
            masksel = 0x1;
            for (i = 0; i < numregs; i++) {
                if (c->vmid_comps_acc_mask & masksel) {
                    printf("\tVMIDCVR%d = %02X\n", i,
                           c->vmid_comps[i].vmidcvr_l);
                }
                masksel <<= 1;
            }
            if (c->scv4->idr2.bits.vmidsize > 0x1) {
                printf("\tVMIDCCTLR0 = %08X\n", c->vmidcctlr0);
                printf("\tVMIDCCTLR1 = %08X\n", c->vmidcctlr1);
            }
        } else
            printf("\n===VMID Comparators Not Implemented===\n");
    }
    return 0;
}

#endif

/*end of file   cs_etm_v4.c */
