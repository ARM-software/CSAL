/*
  Coresight Access Library - API SW Stimulus port programming functions

  Copyright (C) ARM Limited, 2013. All rights reserved.

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
#include "cs_sw_stim.h"
#include "cs_topology.h"

/* ---------- Local functions ------------- */
unsigned int cs_stm_get_ext_ports_size(struct cs_device *d)
{
    assert(d->type == DEV_STM);
    /* System Trace Macrocell Programmers' Model Architecture
       Specification Version 1.0, p. 3.1: "Each extended stimulus
       port occupies 256 consecutive bytes in the memory map." */
    return d->v.stm.n_ports * 256;
}

int _cs_swstim_trace_enable(struct cs_device *d)
{
    if (d->type == DEV_ITM) {
        _cs_set(d, CS_ITM_CTRL, CS_ITM_CTRL_ITMEn);
        return 0;
    } else if (d->type == DEV_STM) {
        _cs_set(d, CS_STM_TCSR, CS_STM_TCSR_EN);
        return 0;
    } else
        return cs_report_device_error(d, "not swstim device");
}

int _cs_swstim_trace_disable(struct cs_device *d)
{
    if (d->type == DEV_ITM) {
        _cs_clear(d, CS_ITM_CTRL, CS_ITM_CTRL_ITMEn);
        _cs_waitnot(d, CS_ITM_CTRL, CS_ITM_CTRL_ITMBusy);
    } else if (d->type == DEV_STM) {
        /* "To ensure that all writes to the STM stimulus ports are traced before
           disabling the STM, ARM recommends that software writes to the stimulus
           port then reads from any stimulus port before clearing STMTCSR.EN.
           This is only required if the same piece of software is writing to the
           stimulus ports and disabling the STM." */
        if (d->v.stm.ext_ports) {
            unsigned char *master0 = d->v.stm.ext_ports[0];
            if (master0) {
                +*(unsigned int volatile *) master0;
            }
        }
        _cs_clear(d, CS_STM_TCSR, CS_STM_TCSR_EN);
        _cs_waitnot(d, CS_STM_TCSR, CS_STM_TCSR_BUSY);
    } else {
        return cs_report_device_error(d, "not swstim device");
    }
    return 0;
}

int _cs_swstim_set_trace_id(struct cs_device *d, cs_atid_t id)
{
    if (d->type == DEV_ITM) {
        _cs_set_mask(d, CS_ITM_CTRL, 0x007F0000,
                     ((unsigned int) id << 16));
    } else if (d->type == DEV_STM) {
        _cs_set_mask(d, CS_STM_TCSR, 0x007F0000,
                     ((unsigned int) id << 16));
    } else {
        return cs_report_device_error(d, "not swstim device");
    }
    return 0;
}

int _cs_stm_config_static_init(struct cs_device *d)
{
    d->v.stm.s_config.spfeat1.reg = _cs_read(d, CS_STM_FEAT1R);
    d->v.stm.s_config.spfeat2.reg = _cs_read(d, CS_STM_FEAT2R);
    d->v.stm.s_config.spfeat3.reg = _cs_read(d, CS_STM_FEAT3R);
#if 0
    fprintf(stderr, "FEAT1R=0x%08x FEAT2R=0x%08x FEAT3R=0x%08x\n",
            _cs_read(d, CS_STM_FEAT1R),
            _cs_read(d, CS_STM_FEAT2R), _cs_read(d, CS_STM_FEAT3R));
#endif
    return 0;
}

/* ========== API functions ================ */
int cs_trace_swstim_get_port_count(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    if (d->type == DEV_ITM) {
        return d->v.itm.n_ports;
    } else if (d->type == DEV_STM) {
        return d->v.stm.n_ports;
    } else {
        return cs_report_device_error(d, "can't count s/w stimulus ports");
    }
}


/*
  Generate a 32-bit stimulus on a given port.
  For STM this is a "marked timestamped" packet.  Instrumented software
  would in general be expected to acquire a memory mapping to a segment
  of the stimulus area, supporting all sizes and flavors of STP packet.
*/
int cs_trace_stimulus(cs_device_t dev, unsigned int port,
                      unsigned int value)
{
    struct cs_device *d = DEV(dev);

    assert(cs_device_has_class
           (dev, CS_DEVCLASS_SOURCE | CS_DEVCLASS_SWSTIM));
    assert(port < cs_trace_swstim_get_port_count(dev));

    if (d->type == DEV_ITM) {
        /* "The lock access mechanism is not present for any access to stimulus
           registers" */
        return _cs_write_wo(d, CS_ITM_STIMPORT(port), value);
    } else if (d->type == DEV_STM) {
        if (d->v.stm.ext_ports) {
            unsigned char *master =
                d->v.stm.ext_ports[d->v.stm.current_master];
            if (master == NULL)
                return cs_report_device_error(d,
                                              "STM master memory address not configured.");
            *(unsigned int volatile *) (master +
                                        CS_STM_EXT_PORT_I_DMTS(port)) =
                value;
            return 0;
        } else if (d->v.stm.basic_ports) {
            return _cs_write_wo(d, CS_STM_STIMR(port), value);
        } else {
            return cs_report_device_error(d,
                                          "No STM stimulus ports available!");
        }
    } else {
        return cs_report_device_error(d, "trace stimulus unimplemented");
    }
}

int cs_trace_swstim_enable_trigger(cs_device_t dev, unsigned int mask,
                                   unsigned int value)
{
    int ret = 0;
    struct cs_device *d = DEV(dev);
    assert(cs_device_has_class
           (dev, CS_DEVCLASS_SOURCE | CS_DEVCLASS_SWSTIM));

    _cs_unlock(d);
    if (d->type == DEV_ITM) {
        ret = _cs_set_mask(d, CS_ITM_TRTRIG, mask, value);
    } else if (d->type == DEV_STM) {
        /* STM has similar functionality using SPTER */
        ret = _cs_set_mask(d, CS_STM_SPTER, mask, value);
    } else {
        ret =
            cs_report_device_error(d,
                                   "can't enable triggers for this device");
    }
    return ret;
}

int cs_trace_swstim_enable_all_ports(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    _cs_unlock(d);
    if (d->type == DEV_ITM) {
        /* Enable all stimulus ports */
        _cs_write(d, CS_ITM_TRCEN, 0xFFFFFFFF);
    } else if (d->type == DEV_STM) {
        /* clear master select - all masters enabled */
        if (d->v.stm.n_masters > 1)
            _cs_clear(d, CS_STM_SPMSCR, CS_STM_SPMSCR_MASTCTL);
        /* clear port select - not used so SPER applies to all groups */
        if (d->v.stm.n_ports > 32)
            _cs_clear(d, CS_STM_SPSCR, CS_STM_SPSCR_PORTCTL);
        /* enable all ports in the group. */
        _cs_write(d, CS_STM_SPER, 0xFFFFFFFF);
    } else
        return cs_report_device_error(d,
                                      "not swstim - can't enable ports for this device");
    return 0;
}

int cs_trace_swstim_set_sync_repeat(cs_device_t dev, unsigned int value)
{
    struct cs_device *d = DEV(dev);
    _cs_unlock(d);
    if (d->type == DEV_ITM) {
        _cs_write(d, CS_ITM_SYNCCTRL, value);
    } else if (d->type == DEV_STM) {
        _cs_write(d, CS_STM_SYNCR, (value & 0xFFF));
    } else
        return cs_report_device_error(d,
                                      "not swstim - can't set sync repeat for this device");
    return 0;
}

/************************ STM only functions ********************/

int cs_stm_config_master(cs_device_t dev, unsigned int master,
                         cs_physaddr_t port_0_addr)
{
    struct cs_device *d = DEV(dev);
    unsigned char *local_addr;
    unsigned int size;

    assert(d->type == DEV_STM);
    assert(d->v.stm.ext_ports != NULL);
    assert(master < d->v.stm.n_masters);
    assert(!d->v.stm.ext_ports[master]);

    size = cs_stm_get_ext_ports_size(d);
    local_addr =
        (unsigned char *) io_map(port_0_addr, size, /*writable= */ 1);
    if (local_addr) {
        /* Check (as far as we can) that this really does look like an STM stimulus area.
           "All STM memory-mapped registers presented on the AXI are write-only.
           Reads always return an AXI OKAY read response and the read data is
           zero regardless of the STM state." */
        unsigned int tw0, tw1;
        tw0 = *(unsigned int volatile *) local_addr;
        tw1 = *(unsigned int volatile *) (local_addr + size - 4);
        if (tw0 != 0 || tw1 != 0) {
            io_unmap(local_addr, size);
            return cs_report_device_error(d,
                                          "not swstim - stimulus area is not reading back as zero");
        }
        d->v.stm.ext_ports[master] = local_addr;
        return 0;
    } else {
        return -1;
    }
}

int cs_stm_select_master(cs_device_t dev, unsigned int master)
{
    struct cs_device *d = DEV(dev);

    assert(d->type == DEV_STM);
    assert(d->v.stm.ext_ports != NULL);
    assert(master < d->v.stm.n_masters);

    if (d->v.stm.ext_ports[master] == 0)
        return cs_report_device_error(d,
                                      "STM - cannot set unconfigured master address.");
    d->v.stm.current_master = master;
    return 0;
}

static unsigned int const s_op_offsets[] = {
    0x00,			/* G_DMTS   */
    0x08,			/* G_DM     */
    0x10,			/* G_DTS    */
    0x18,			/* G_D      */
    0x80,			/* I_DMTS   */
    0x88,			/* I_DM     */
    0x90,			/* I_DTS    */
    0x98,			/* I_D      */
    0x60,			/* G_FLAGTS */
    0x68,			/* G_FLAG   */
    0x70,			/* G_TRIGTS */
    0x78,			/* G_TRIG   */
    0xE0,			/* I_FLAGTS */
    0xE8,			/* I_FLAG   */
    0xF0,			/* I_TRIGTS */
    0xF8			/* I_TRIG   */
};

int cs_stm_ext_write(cs_device_t dev, const unsigned int port,
                     const unsigned char *value, const int length,
                     const int trans_type)
{
    struct cs_device *d = DEV(dev);
    int write_unit_size = d->v.stm.s_config.spfeat2.bits.dsize == 1 ? 8 : 4;	/* byte size starts out @ fundamnetal data size for the unit */
    unsigned char *master = d->v.stm.ext_ports[d->v.stm.current_master];
    int bytes_written = 0;

    if (master == 0)
        return cs_report_device_error(d,
                                      "STM - cannot write to unconfigured master address.");


    assert(d->type == DEV_STM);
    assert(STM_OP_VALID(trans_type));
    assert((value != 0) || !STM_OP_DATA(trans_type));
    assert(port < cs_trace_swstim_get_port_count(dev));
    assert(master != NULL);
    assert((value == 0) || (length > 0));

    if (STM_OP_DATA(trans_type)) {
        while ((length - bytes_written) >= write_unit_size) {
            if (write_unit_size == 4)
                *(uint32_t volatile *) (master + port * 256 +
                                        s_op_offsets[trans_type]) =
                    *(uint32_t *) (value + bytes_written);
            else
                *(uint64_t volatile *) (master + port * 256 +
                                        s_op_offsets[trans_type]) =
                    *(uint64_t *) (value + bytes_written);
            bytes_written += write_unit_size;
        }

        while (bytes_written < length) {
            if (length - bytes_written >= 4) {
                *(uint32_t volatile *) (master + port * 256 +
                                        s_op_offsets[trans_type]) =
                    *(uint32_t *) (value + bytes_written);
                bytes_written += 4;
            } else if (length - bytes_written >= 2) {
                *(uint16_t volatile *) (master + port * 256 +
                                        s_op_offsets[trans_type]) =
                    *(uint16_t *) (value + bytes_written);
                bytes_written += 2;
            } else {
                *(uint8_t volatile *) (master + port * 256 +
                                       s_op_offsets[trans_type]) =
                    *(uint8_t *) (value + bytes_written);
                bytes_written++;
            }
        }
    } else {
        /* none data - just write a 0 value */
        *(uint32_t volatile *) (master + port * 256 +
                                s_op_offsets[trans_type]) = 0;
    }
    return 0;
}

/*
  #define CS_STMC_NONE    0x0000
  #define CS_STMC_CTRL    0x0001  TCSR
  #define CS_STMC_SYNC    0x0002  SYNCR 
  #define CS_STMC_PENA    0x0004  Port enable regs (SPER, SPTER, SPSCR, SPMCR, PRIVMASKR 
  #define CS_STMC_OVER    0x0008  Override regs (OVERIDERR, MOVERRIDER) 
  #define CS_STMC_TRIG    0x0010  Trigger control (SPTRIGCSR) 
  #define CS_STMC_ALL     0xFFFF
*/

int cs_stm_config_get(cs_device_t dev, stm_config_t * dyn_config)
{
    struct cs_device *d = DEV(dev);

    assert(d->type == DEV_STM);

    _cs_unlock(d);

    if (dyn_config->config_op_flags & CS_STMC_CTRL)
        dyn_config->tcsr.reg = _cs_read(d, CS_STM_TCSR);

    if (dyn_config->config_op_flags & CS_STMC_SYNC)
        dyn_config->syncr = _cs_read(d, CS_STM_SYNCR);

    if (dyn_config->config_op_flags & CS_STMC_PENA) {
        dyn_config->sper = _cs_read(d, CS_STM_SPER);
        dyn_config->spter = _cs_read(d, CS_STM_SPTER);
        dyn_config->spscr = _cs_read(d, CS_STM_SPSCR);
        dyn_config->spmscr = _cs_read(d, CS_STM_SPMSCR);
        dyn_config->privmaskr = _cs_read(d, CS_STM_PRIVMASKR);
    }

    if (dyn_config->config_op_flags & CS_STMC_OVER) {
        dyn_config->spoverrider = _cs_read(d, CS_STM_SPOVERRIDER);
        dyn_config->spmoverrider = _cs_read(d, CS_STM_SPMOVERRIDER);
    }

    if (dyn_config->config_op_flags & CS_STMC_TRIG) {
        dyn_config->sptrigcsr = _cs_read(d, CS_STM_SPTRIGCSR);
    }

    return 0;
}

int cs_stm_config_put(cs_device_t dev, stm_config_t * dyn_config)
{
    struct cs_device *d = DEV(dev);

    assert(d->type == DEV_STM);

    _cs_unlock(d);

    if (dyn_config->config_op_flags & CS_STMC_CTRL)
        _cs_write(d, CS_STM_TCSR, dyn_config->tcsr.reg);

    if (dyn_config->config_op_flags & CS_STMC_SYNC)
        _cs_write(d, CS_STM_SYNCR, dyn_config->syncr);

    if (dyn_config->config_op_flags & CS_STMC_PENA) {
        _cs_write(d, CS_STM_SPER, dyn_config->sper);
        _cs_write(d, CS_STM_SPTER, dyn_config->spter);
        _cs_write(d, CS_STM_SPSCR, dyn_config->spscr);
        _cs_write(d, CS_STM_SPMSCR, dyn_config->spmscr);
        _cs_write(d, CS_STM_PRIVMASKR, dyn_config->privmaskr);
    }

    if (dyn_config->config_op_flags & CS_STMC_OVER) {
        _cs_write(d, CS_STM_SPOVERRIDER, dyn_config->spoverrider);
        _cs_write(d, CS_STM_SPMOVERRIDER, dyn_config->spmoverrider);
    }

    if (dyn_config->config_op_flags & CS_STMC_TRIG) {
        _cs_write(d, CS_STM_SPTRIGCSR, dyn_config->sptrigcsr);
    }
    return 0;
}

/* end of cs_sw_stim.c */
