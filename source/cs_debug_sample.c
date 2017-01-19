/*
  Memory-mapped access to CPU sampling debug features.

  Copyright (C) 2014 ARM Ltd.

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
#include "cs_debug_sample.h"

/* ---------- Local functions ------------- */
/* this called from API fn if V8 core */
static int cs_debug_v8_pc_sample(struct cs_device *d, cs_virtaddr_t * pc,
                                 unsigned int *cid, unsigned int *vmid)
{
    unsigned int regval, regval_h;
    cs_virtaddr_t pc_sample = 0;


    /* check PC sampling support is present */
    if ((d->v.debug.devid & CS_V8EDDEVID_SMPL_MSK) ==
        CS_V8EDDEVID_SMPL_NONE)
        return -1;

    /* check target processor is powered, running and accessible */
    regval = _cs_read(d, CS_V8EDPRSR);
    if ((regval & CS_V8EDPRSR_COREOK_MSK) != CS_V8EDPRSR_COREOK_VAL)
        return -1;

    /* grab the PC - this "snapshots" the VMID and Context ID/ */
    regval = _cs_read(d, CS_V8EDPCSR_l);

    /* if we really want the PC then set the output value */
    if (pc != NULL) {
        if (G.virt_addr_64bit == 1) {	/* built with 64 bit address values */
            regval_h = _cs_read(d, CS_V8EDPCSR_h);

            /* only compile this if we have 64 bit VA - will generate compile warning otherwise. */
#ifdef CS_VA64BIT
            pc_sample = (((cs_virtaddr_t) regval_h) & 0xFFFFFFFF) << 32;
#endif
        }
        pc_sample |= (regval & 0xFFFFFFFF);
        *pc = pc_sample;
    }

    /* context ID always present  - get it if requested */
    if (cid != NULL)
        *cid = _cs_read(d, CS_V8EDCIDSR);

    /* check if VM ID wanted */
    if (vmid != NULL) {
        if ((d->v.debug.devid & CS_V8EDDEVID_SMPL_MSK) ==
            CS_V8EDDEVID_SMPL_P_C_V) {
            *vmid = _cs_read(d, CS_V8EDVIDSR);
        }
    }
    return 0;
}

/* ========== API functions ================ */
int cs_debug_get_pc_sample(cs_device_t dev, cs_virtaddr_t * pc,
                           unsigned int *cid, unsigned int *vmid)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_CPU_DEBUG);

    /* check for v8 architecture */
    if (IS_V8(d))
        return cs_debug_v8_pc_sample(d, pc, cid, vmid);

    if (d->v.debug.pcsamplereg != 0) {
        /* Take a PC sample whatever happens, as this causes the other
           sample registers to be read synchronously */
        cs_virtaddr_t samp = _cs_read(d, d->v.debug.pcsamplereg);
        if (pc != NULL) {
            *pc = samp;
        }
        if ((d->v.debug.devid & 0xF) >= 2) {
            if (cid != NULL) {
                *cid = _cs_read(d, CS_DBGCIDSR);
            }
            if ((d->v.debug.devid & 0xF) >= 3) {
                if (vmid != NULL) {
                    *vmid = _cs_read(d, CS_DBGVIDSR);
                }
            }
        }
        return 0;
    } else {
        return -1;
    }
}


/* end of csdebug.c */
