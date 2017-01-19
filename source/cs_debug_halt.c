/*
  Memory-mapped access to CPU debug features.

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

#ifdef USING_V7_DBG_HALT

int cs_debug_halt(cs_device_t dev, unsigned int flags)
{
    int rc;
    unsigned int req;
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_CPU_DEBUG);
    assert(!IS_V8(d));

    /* Request halt */
    _cs_unlock(d);
    req = CS_DBGDRCR_HRQ;
    if (flags & CS_DEBUG_CANCEL_BUS_REQUESTS) {
        req |= CS_DBGDRCR_CBRRQ;
    }
    _cs_write_wo(d, CS_DBGDRCR, req);
    /* Wait until halted - n.b. on v7.1 could test DBGPRSR_HALTED */
    rc = _cs_wait(d, CS_DBGDSCR, CS_DBGDSCR_HALTED);
    if (rc) {
        return rc;
    }
    /* The CPU is left unlocked on the assumption we'll be injecting
       instructions via DBGITR etc. */
    _cs_set(d, CS_DBGDSCR, CS_DBGDSCR_ITRen);
    return 0;
}


int cs_debug_is_halted(cs_device_t dev, cs_debug_moe_t * reason)
{
    int flag;
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_CPU_DEBUG);
    assert(!IS_V8(d));

    flag = _cs_isset(d, CS_DBGDSCR, CS_DBGDSCR_HALTED);
    if (flag && reason != NULL) {
        /* Read the MOE field */
        *reason = (cs_debug_moe_t) ((_cs_read(d, CS_DBGDSCR) >> 2) & 0xF);
    }
    return flag;
}


int cs_debug_cpu_is_active(cs_device_t dev)
{
    int i;
    int is_active = 0;
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_CPU_DEBUG);
    assert(!IS_V8(d));

    _cs_unlock(d);
    /* What we're aiming to do here is to clear the sticky pipeline advance
       and then look for it being set.  This shows that the other core is
       advancing instructions through the pipeline.  It relies on us giving
       the other core enough time that if "running", some instructions would
       in fact be advanced - we don't want to falsely report it's stuck just
       because it's stalled on a memory access or floating-point divide. */
    _cs_write_wo(d, CS_DBGDRCR, CS_DBGDRCR_CSPA);
    /* Poll the bit a few times - this raises the success rate for an active
       CPU from about 80% to nearly 100%. */
    for (i = 0; i < 5; ++i) {
        is_active = _cs_isset(d, CS_DBGDSCR, CS_DBGDSCR_PipeAdv);
        if (is_active)
            break;
    }
    return is_active;
}


/*
  Halted-mode debug routines, to read/write registers.
*/

#define R0 0
#define R1 1

#define CP15_DFAR   0xEE060F10
#define CP15_DFSR   0xEE050F10

static int _cs_debug_exec(struct cs_device *d, unsigned int inst)
{
    /* Write the instruction to the ITR.  Use of the ITR is assumed to
       have already been enabled, e.g. by cs_debug_halt. */
    assert(_cs_isset(d, CS_DBGDSCR, CS_DBGDSCR_ITRen));
    assert(!IS_V8(d));

    _cs_write_wo(d, CS_DBGITR, inst);
    /* Wait for the architectural effect to complete. */
    return _cs_wait(d, CS_DBGDSCR, CS_DBGDSCR_InstrCompl_l);
}


int cs_debug_exec(cs_device_t dev, unsigned int inst)
{
    return _cs_debug_exec(DEV(dev), inst);
}


/*
  Execute an instruction that's assumed to write to the (internal) DBGDTRTX -
  i.e. either a MCR p14,... or a LDC p14,....
  An LDC might fail and cause a data abort.
  This may update the DFAR/DFSR, which might cause a problem if the target
  is in the middle of a page fault handler.
  The caller is assumed to have taken steps to preserve and restore these registers.
*/
#define CS_DEBUG_READ_DATA_ABORT  (-10)
#define CS_DEBUG_READ_NO_RESPONSE (-11)
static int cs_debug_exec_and_read(struct cs_device *d, unsigned int inst,
                                  unsigned int *pvalue)
{
    int rc;
    unsigned int dscr;
    unsigned int value;
    /* Write the instruction to the ITR and wait for it to complete.
       This is more reliable than simply writing it to ITR and waiting for
       TXfull to be signalled, since the instruction might fail. */
    rc = _cs_debug_exec(d, inst);
    if (rc) {
        return rc;
    }
    /* Now, either the value should be available in the transfer register,
       or the instruction should have failed.  We should not have to poll TXfull. */
    dscr = _cs_read(d, CS_DBGDSCR);
    if (dscr & CS_DBGDSCR_TXfull) {
        value = _cs_read(d, CS_DBGDTRTX);
        if (pvalue) {
            *pvalue = value;
        }
        rc = 0;
    } else if (dscr & (CS_DBGDSCR_SDABORT_l | CS_DBGDSCR_ADABORT_l)) {
        rc = CS_DEBUG_READ_DATA_ABORT;
    } else {
        fprintf(stderr,
                "** no response to debug data transfer, DBGDSCR=%08X\n",
                dscr);
        rc = CS_DEBUG_READ_NO_RESPONSE;
    }
    return rc;
}


/*
  Write a value to the (external) DBGDTRRX and wait for it to be visible internally.
  Then execute an instruction and wait for it to complete.
*/
static int cs_debug_write_and_exec(struct cs_device *d, unsigned int value,
                                   unsigned int inst)
{
    _cs_write_wo(d, CS_DBGDTRRX, value);
    _cs_wait(d, CS_DBGDSCR, CS_DBGDSCR_RXfull);
    return _cs_debug_exec(d, inst);
}


static int cs_debug_read_register(struct cs_device *d, unsigned int reg,
                                  unsigned int *pvalue)
{
    unsigned int inst;

    assert(d->type == DEV_CPU_DEBUG);
    assert(!IS_V8(d));

    /* MCR p14,0,rx,c0,c5,0 */

    inst = 0xEE000E15 | (reg << 12);
    return cs_debug_exec_and_read(d, inst, pvalue);
}


/*
  Read a CP15 register, using a work register.
*/
static int cs_debug_read_cp15(struct cs_device *d, unsigned int inst,
                              unsigned int *pvalue, unsigned int workreg)
{
    /* Execute MRC to read a value into the work register... */
    cs_debug_exec(d, inst | 0x00100000 | (workreg << 12));
    /* ... and return the value of that work register. */
    return cs_debug_read_register(d, workreg, pvalue);
}


static int cs_debug_write_register(struct cs_device *d, unsigned int reg,
                                   unsigned int value)
{
    /* Execute an MRC from the debug transfer register, into the selected core register. */
    return cs_debug_write_and_exec(d, value, (0xEE100E15 | (reg << 12)));
}


static int cs_debug_write_cp15(struct cs_device *d, unsigned int inst,
                               unsigned int value, unsigned int workreg)
{
    /* Write the value into the work register... */
    cs_debug_write_register(d, workreg, value);
    /* ... and execute the MCR from that work register. */
    return cs_debug_exec(d, inst | (workreg << 12));
}


int cs_debug_read_registers(cs_device_t dev, unsigned int mask,
                            unsigned int *regs)
{
    int rc;
    unsigned int i;
    unsigned int dscr;
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_CPU_DEBUG);
    assert(!IS_V8(d));

    dscr = _cs_read(d, CS_DBGDSCR);
    if ((dscr & 0x00300000) != 0) {
        /* External DCC access mode is not non-blocking */
        return -1;
    }
    for (i = 0; i < 15; ++i) {
        if ((mask & (1U << i)) != 0) {
            rc = cs_debug_read_register(d, i, &regs[i]);
            if (rc)
                break;
        }
    }
    return rc;
}


int cs_debug_read_sysreg(cs_device_t dev, unsigned int reg,
                         unsigned int *pvalue)
{
    int rc;
    struct cs_device *d = DEV(dev);
    unsigned int save_r0;

    assert(!IS_V8(d));

    rc = cs_debug_read_register(d, R0, &save_r0);
    if (!rc) {
        cs_debug_exec(d, 0xE10F0000 | (reg << 22) | (R0 << 12));	/* MRS r0,... */
        cs_debug_read_register(d, R0, pvalue);
        rc = cs_debug_write_register(d, R0, save_r0);
    }
    return rc;
}

int cs_debug_read_memory(cs_device_t dev, cs_virtaddr_t addr, void *data,
                         unsigned int size)
{
    int rc, rc1;
    struct cs_device *d = DEV(dev);


    /* R0 is used as the base address register */
    unsigned int save_r0;
    unsigned int save_dfar, save_dfsr;
    unsigned char *p = (unsigned char *) data;

    assert(!IS_V8(d));

    rc = cs_debug_read_register(d, R0, &save_r0);
    if (!rc) {
        /* Clear the sticky data abort bits */
        _cs_write_wo(d, CS_DBGDRCR, CS_DBGDRCR_CSE);
        /* Preserve the fault registers in case we overwrite them */
        cs_debug_read_cp15(d, CP15_DFAR, &save_dfar, R0);
        cs_debug_read_cp15(d, CP15_DFSR, &save_dfsr, R0);
        /* Now set the base address for the LDCs */
        cs_debug_write_register(d, R0, (addr & ~3));
        while (size > 0) {
            unsigned int value;
            /* LDC p14,c5,[r0],#4 */
            rc = cs_debug_exec_and_read(d, 0xECB05E01 | (R0 << 16),
                                        &value);
            if (rc) {
                if (rc == CS_DEBUG_READ_DATA_ABORT) {
                    unsigned int dfar, dfsr;
                    /* Clear the sticky abort bits, otherwise we'll keep failing to read */
                    _cs_write_wo(d, CS_DBGDRCR, CS_DBGDRCR_CSE);
                    cs_debug_read_cp15(d, CP15_DFAR, &dfar, R0);
                    cs_debug_read_cp15(d, CP15_DFSR, &dfsr, R0);
                    fprintf(stderr,
                            "** debug read data abort, DFAR=%08X, DFSR=%08X (saved %08X,%08X)\n",
                            dfar, dfsr, save_dfar, save_dfsr);
                }
                cs_debug_write_cp15(d, CP15_DFAR, save_dfar, R0);
                cs_debug_write_cp15(d, CP15_DFSR, save_dfsr, R0);
                break;
            }
            if ((addr & 3) != 0 || size < 4) {
                unsigned int i;
                value >>= ((addr & 3) << 3);
                for (i = (addr & 3); i < 4 && size > 0; ++i) {
                    *p++ = value & 0xFF;
                    --size;
                }
            } else {
                *(unsigned int *) p = value;
                p += 4;
                size -= 4;
            }
        }
        rc1 = cs_debug_write_register(d, R0, save_r0);
        if (!rc && rc1) {
            rc = rc1;
        }
    }
    return rc;
}


int cs_debug_restart(cs_device_t dev)
{
    int rc;
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_CPU_DEBUG);
    assert(!IS_V8(d));

    /* If the CPU was previously halted by us, we'd expect it already to be unlocked.
       But it might have been halted by a debug event and still be locked. */
    _cs_unlock(d);
    /* "When the processor is in Debug state, it can exit Debug state by
       performing a single write to DBGDRCR with DBGDRCR.{CSE,RRQ} == 0b11." */
    _cs_write_wo(d, CS_DBGDRCR, CS_DBGDRCR_CSE | CS_DBGDRCR_RRQ);
    rc = _cs_wait(d, CS_DBGDSCR, CS_DBGDSCR_RESTARTED);
    /* At this point either
       - the processor has exited Debug state (HALTED=0)
       - the processor has exited and re-entered Debug state (HALTED=1) */
    /* For safety, re-lock the CPU. */
    if (rc == 0) {
        _cs_lock(d);
    }
    return rc;
}

#endif				/*  USING_V7_DBG_HALT */

/* end of cs_debug_halt.c */
