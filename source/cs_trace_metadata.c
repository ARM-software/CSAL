/*
  CS-Access - Examples: supplementary functions to extract component meta-data for post run analysis

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

#include "csaccess.h"
#include "csregisters.h"
#include "cs_trace_metadata.h"

#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

/* ---------- Local functions ------------- */

struct out_buf {
    char *p;
    unsigned int size_left;
    unsigned int len;
};

static void add_to_buf(struct out_buf *b, char const *fmt, ...)
{
    int n;
    va_list args;
    va_start(args, fmt);
    if (b->size_left > 0) {
        /* TBD: vsnprintf is non-standard.  May need retargeting for bare-metal. */
        n = vsnprintf(b->p, b->size_left, fmt, args);
        b->size_left -= n;
        b->p += n;
        b->len += n;
    } else {
    }
    va_end(args);
}

/*
  The ETM metadata is

  (a) data that is _architecturally required_ for correct reconstruction of
  packet boundaries

  (b) some extra data that is required for basic validation of trace,
  e.g. timestamp format so we can check timestamps don't go backwards
*/
struct etm_metadata {
    unsigned int addr_encoding_alt:1;
    unsigned int cycle_accurate:1;
    unsigned int timestamp_enabled:1;
    unsigned int timestamp_gray:1;
    unsigned int return_stack_enabled:1;
    unsigned int waypoint_for_dmb_dsb:1;
    unsigned char etm_version;	/* e.g. 0x35 for ETM v3.5, 0x41 for PFT v1.1, 0x50 for ETM v4 */
    unsigned char timestamp_bits;	/* 48 or 64 */
    unsigned char cid_bits;	/* 0, 8, 16, 32 */
    unsigned char vmid_bits;	/* 0, 8, 16 */
    /* For robustness, capture the actual identifier/capabilities registers */
    unsigned int etmidr;	/* trcidr1 in v4 */
    unsigned int etmcr;		/* trcconfigr in v4 */
    unsigned int etmccer;	/* unused v4 */
    unsigned int etmtraceidr;	/* trctraceidr in v4 */
    unsigned int etmv4authstatus;	/* etmv4 */
    unsigned int trcidr0;	/* etmv4 */
    unsigned int trcidr2;	/* etmv4 */
    unsigned int trcidr8;	/* etmv4 */
    unsigned int trcidr9;	/* etmv4 */
    unsigned int trcidr10;	/* etmv4 */
    unsigned int trcidr11;	/* etmv4 */
    unsigned int trcidr12;	/* etmv4 */
    unsigned int trcidr13;	/* etmv4 */
};

static int cs_get_etm_metadata(cs_device_t dev, struct etm_metadata *m)
{
    unsigned int etmcr, etmccer;
    cs_etmv4_config_t t4config;	/* ETMv4 config */
    cs_etm_v4_configr_t cr;	/* ETMv4 cr */
    etm_v4_idr0_ut idr0;	/* ETMv4 idr0 */
    etm_v4_idr2_ut idr2;	/* ETMv4 idr2 */

    assert(cs_device_has_class(dev, CS_DEVCLASS_SOURCE));
    assert(cs_device_get_type(dev) == DEV_ETM);

    m->etmidr = cs_device_read(dev, CS_ETMIDR);
    m->etm_version = ((m->etmidr >> 4) & 0xFF) + 0x10;

    if (m->etm_version < 0x50) {
        etmcr = cs_device_read(dev, CS_ETMCR);
        etmccer = cs_device_read(dev, CS_ETMCCER);
        m->etmcr = etmcr;
        m->etmccer = etmccer;

        m->etmtraceidr = cs_device_read(dev, CS_ETMTRACEIDR);

        m->cycle_accurate = ((etmcr & CS_ETMCR_CycleAccurate) != 0);
        m->return_stack_enabled = ((etmcr & 0x20000000) != 0);
        m->timestamp_enabled = ((etmcr & CS_ETMCR_TSEn) != 0);
        if (m->timestamp_enabled) {
            m->timestamp_bits = (etmccer & 0x20000000) ? 64 : 48;
            m->timestamp_gray = (etmccer & 0x10000000) ? 0 : 1;
        } else {
            m->timestamp_bits = 0;
            m->timestamp_gray = 0;	/* Actually unknown */
        }
        m->waypoint_for_dmb_dsb = (etmccer & 0x2000000) != 0;
        /* Convert 0, 1, 2, 3 to 0, 8, 16, 32 */
        m->cid_bits = ((1U << ((etmcr & 0xC000) >> 14)) >> 1) << 3;
        m->vmid_bits = 8;	/* TBD */
    } else {
        m->etmcr = cs_device_read(dev, CS_ETMV4_CONFIGR);
        m->etmtraceidr = cs_device_read(dev, CS_ETMV4_TRACEIDR);
        m->etmv4authstatus = cs_device_read(dev, CS_ETMv4_AUTHSTATUS);

        /* ETMv4 config */
        cs_etm_config_init_ex(dev, &t4config);	/* init will link to the static config already read up */
        m->trcidr0 = t4config.scv4->idr0.reg;
        m->trcidr2 = t4config.scv4->idr2.reg;
        m->trcidr8 = t4config.scv4->idr8;
        m->trcidr9 = t4config.scv4->idr9;
        m->trcidr10 = t4config.scv4->idr10;
        m->trcidr11 = t4config.scv4->idr11;
        m->trcidr12 = t4config.scv4->idr12;
        m->trcidr13 = t4config.scv4->idr13;

        /* ETMv4 CR */
        cr.reg = m->etmcr;
        m->cycle_accurate = cr.bits.cci;
        m->timestamp_enabled = cr.bits.ts;
        m->return_stack_enabled = cr.bits.rs;

        /* ETMv4 idr0; */
        idr0.reg = m->trcidr0;
        m->timestamp_gray = 0;
        if (m->timestamp_enabled && (idr0.bits.tssize != 0)) {
            m->timestamp_bits = idr0.bits.tssize == 0x8 ? 64 : 48;
        } else {
            m->timestamp_bits = 0;
        }

        /* ETMv4 idr2; */
        idr2.reg = m->trcidr2;
        m->cid_bits = idr2.bits.cidsize == 0x4 ? 32 : 0;
        m->vmid_bits = idr2.bits.vmidsize == 0x1 ? 8 : 0;
    }
    return 0;
}

/* ========== API functions ================ */

/*
  Generate trace metadata for DS-5. 
*/
int cs_get_trace_metadata(int mtype, cs_device_t dev, int trace_id,
                          char *buf, unsigned int size, char *name_buf,
                          unsigned int name_buf_size)
{
    struct out_buf b;
    cs_devtype_t d_type;

    b.p = buf;
    b.size_left = size;
    b.len = 0;

    d_type = cs_device_get_type(dev);

    if (cs_device_has_class(dev, CS_DEVCLASS_SOURCE)) {
        cs_atid_t atid = cs_get_trace_source_id(dev);
        /* To cope with ETMv4's two trace sources we ought to loop here... */
        if (cs_device_has_class(dev, CS_DEVCLASS_CPU) != 0) {
            struct etm_metadata meta;
            cs_get_etm_metadata(dev, &meta);
            trace_id++;
            add_to_buf(&b, "[device]\n");
            /* The device name has to match the one in the board's DTSL config.
               E.g. for TC2 we have PTM_0, PTM_1, ETM_0, ETM_1, ETM_2. */
#if 0
            if (meta.etm_version < 0x40) {
                /* e.g. 0x35 (from id 0x25) is ETM3.5 */
                add_to_buf(&b, "name=ETM_%d\n\n", d->affine_cpu);
            } else if (meta.etm_version < 0x50) {
                /* e.g. 0x41 (from id 0x31) is PFT1.1 */
                add_to_buf(&b, "name=PTM_%d\n\n", d->affine_cpu);
            } else {
                /* e.g. 0x50 is ETM4.0 */
                add_to_buf(&b, "name=ETM_%d\n\n", d->affine_cpu);
            }
#else
            {
                /* Scan all trace sources of this type (ETM or PTM) and count ones
                   with an affine CPU lower than this one. */
                cs_device_t pd;
                unsigned int countp = 0;
                int is_ptm = (meta.etm_version >= 0x40
                              && meta.etm_version < 0x50);
                cs_for_each_device(pd) {
                    if (cs_device_has_class
                        (pd, CS_DEVCLASS_SOURCE | CS_DEVCLASS_CPU)
                        && cs_device_get_affinity(pd) <
                        cs_device_get_affinity(dev)) {
                        struct etm_metadata pm;
                        cs_get_etm_metadata(pd, &pm);
                        if ((pm.etm_version >= 0x40
                             && pm.etm_version < 0x50) == is_ptm) {
                            ++countp;
                        }
                    }
                }
                add_to_buf(&b, "name=%s_%u\n", (is_ptm ? "PTM" : "ETM"),
                           countp);
                if (name_buf) {
                    snprintf(name_buf, name_buf_size, "%s_%u",
                             (is_ptm ? "PTM" : "ETM"), countp);
                }
            }
#endif
            add_to_buf(&b, "class=trace_source\n");
            if (meta.etm_version < 0x40) {
                /* e.g. 0x35 (from id 0x25) is ETM3.5 */
                add_to_buf(&b, "type=ETM%d.%d\n\n",
                           (meta.etm_version >> 4) & 0xF,
                           meta.etm_version & 0xF);
            } else if (meta.etm_version < 0x50) {
                /* e.g. 0x41 (from id 0x31) is PFT1.1 */
                add_to_buf(&b, "type=PTM%d.%d\n\n",
                           ((meta.etm_version >> 4) & 0xF) - 3,
                           meta.etm_version & 0xF);
            } else {
                /* e.g. 0x50 is ETM4.0 */
                add_to_buf(&b, "type=ETM%d\n\n",
                           ((meta.etm_version >> 4) & 0xF) - 1);
            }
            if (meta.etm_version < 0x50) {
                add_to_buf(&b, "[regs]\n");
                add_to_buf(&b, "ETMCR(0x%03X)=0x%08X\n", CS_ETMCR >> 2,
                           meta.etmcr);
                add_to_buf(&b, "ETMIDR(0x%03X)=0x%08X\n", CS_ETMIDR >> 2,
                           meta.etmidr);
                add_to_buf(&b, "ETMCCER(0x%03X)=0x%08X\n", CS_ETMCCER >> 2,
                           meta.etmccer);
                add_to_buf(&b, "ETMTRACEIDR(0x%03X)=0x%08X\n",
                           CS_ETMTRACEIDR >> 2, meta.etmtraceidr);
            } else {
                add_to_buf(&b, "[regs]\n");
                add_to_buf(&b, "TRCCONFIGR(0x%03X)=0x%08X\n",
                           CS_ETMV4_CONFIGR >> 2, meta.etmcr);
                add_to_buf(&b, "TRCTRACEIDR(0x%03X)=0x%08X\n",
                           CS_ETMV4_TRACEIDR >> 2, meta.etmtraceidr);
                add_to_buf(&b, "TRCAUTHSTATUS(0x%03X)=0x%08X\n",
                           CS_ETMv4_AUTHSTATUS >> 2, meta.etmv4authstatus);

                add_to_buf(&b, "TRCIDR0(0x%03X)=0x%08X\n",
                           CS_ETMv4_IDR0 >> 2, meta.trcidr0);
                add_to_buf(&b, "TRCIDR1(0x%03X)=0x%08X\n",
                           CS_ETMv4_IDR1 >> 2, meta.etmidr);
                add_to_buf(&b, "TRCIDR2(0x%03X)=0x%08X\n",
                           CS_ETMv4_IDR2 >> 2, meta.trcidr2);
                add_to_buf(&b, "TRCIDR8(0x%03X)=0x%08X\n",
                           CS_ETMv4_IDR8 >> 2, meta.trcidr8);
                add_to_buf(&b, "TRCIDR9(0x%03X)=0x%08X\n",
                           CS_ETMv4_IDR9 >> 2, meta.trcidr9);
                add_to_buf(&b, "TRCIDR10(0x%03X)=0x%08X\n",
                           CS_ETMv4_IDR10 >> 2, meta.trcidr10);
                add_to_buf(&b, "TRCIDR11(0x%03X)=0x%08X\n",
                           CS_ETMv4_IDR11 >> 2, meta.trcidr11);
                add_to_buf(&b, "TRCIDR12(0x%03X)=0x%08X\n",
                           CS_ETMv4_IDR12 >> 2, meta.trcidr12);
                add_to_buf(&b, "TRCIDR13(0x%03X)=0x%08X\n",
                           CS_ETMv4_IDR13 >> 2, meta.trcidr13);

            }
        } else if (d_type == DEV_ITM) {
            add_to_buf(&b, "[device]\n");
            add_to_buf(&b, "name=ITM_%u\n", trace_id);
            add_to_buf(&b, "class=trace_source\n");
            add_to_buf(&b, "type=ITM\n\n");
            add_to_buf(&b, "[regs]\n");
            add_to_buf(&b, "ITM_CTRL(0x%03X)=0x%08X\n", CS_ITM_CTRL >> 2,
                       cs_device_read(dev, CS_ITM_CTRL));
            if (name_buf) {
                snprintf(name_buf, name_buf_size, "ITM_%u", trace_id);
            }
        } else if (d_type == DEV_STM) {
            add_to_buf(&b, "[device]\n");
            add_to_buf(&b, "name=STM_%u\n", trace_id);
            add_to_buf(&b, "class=trace_source\n");
            add_to_buf(&b, "type=STM\n\n");
            add_to_buf(&b, "[regs]\n");
            add_to_buf(&b, "STMTCSR(0x%03X)=0x%08X\n", CS_STM_TCSR >> 2,
                       cs_device_read(dev, CS_STM_TCSR));
            if (name_buf) {
                snprintf(name_buf, name_buf_size, "STM_%u", trace_id);
            }
        } else {
            add_to_buf(&b, "name=UNKNOWN%u\n", atid);
            add_to_buf(&b, "class=trace_source\n");
            add_to_buf(&b, "format=UNKNOWN\n");
        }
    }
    if (b.size_left > 0) {
        b.p[0] = '\0';
    }
    return b.len + 1;
}

/* end of cs_trace_metadata.c */
