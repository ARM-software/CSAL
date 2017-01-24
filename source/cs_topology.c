/*
  Coresight Access Library - API component register access functions

  Copyright (C) ARM Limited, 2013-2016. All rights reserved.

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
#include "cs_topology.h"
#include "cs_reg_access.h"
#include "cs_etm.h"
#include "cs_sw_stim.h"
#include "cs_trace_sink.h"

/* ---------- Local functions ------------- */
static int cs_scan_romtable(cs_physaddr_t rom_addr, void const *tabv);

static unsigned int raw_read(unsigned char const *local,
                             unsigned int offset)
{
    return *(unsigned int const volatile *) (local + offset);
}

static int cs_addr_is_excluded(cs_physaddr_t addr)
{
    struct addr_exclude *a;
    for (a = G.exclusions; a != NULL; a = a->next) {
        if (a->from <= addr && addr < a->to) {
            return 1;
        }
    }
    return 0;
}

static void cs_stm_device_unregister(struct cs_device *d)
{
    assert(d->type == DEV_STM);

    if (d->v.stm.ext_ports != NULL) {
        unsigned int i;
        for (i = 0; i < d->v.stm.n_masters; i++) {
            if (d->v.stm.ext_ports[i] != NULL) {
                io_unmap(d->v.stm.ext_ports, cs_stm_get_ext_ports_size(d));
            }
        }
        free(d->v.stm.ext_ports);
    }
}

/*
  Register a device (or ROM table) at a given address.

  For a device, a device object is created and the local memory mapping
  is retained.  This is currently unconditional, even for devices (such
  as CPUs and PMUs) which we don't expect to manage.

  The public API for registering ROM tables is cs_register_romtable,
  but we handle them here too in case there are chained ROM tables.
  (we don't know if it's a subtable until we go looking at the id
  registers - by which time we've probably mapped it read/write.

  While registering, we print (to diagnostic output) a one-line summary
  of the device configuration.  This comprises static information, e.g.
  - device type and features
  - ETB buffer size
  - TMC configuration
  but not dynamic information, e.g.
  - device settings and status
  - ETB buffer occupancy
  - TMC operating mode
*/
static cs_device_t cs_device_or_romtable_register(cs_physaddr_t addr)
{
    unsigned int cs_class;
    unsigned char *local;
    struct cs_device *d = NULL;

    assert(is_4k_page_address(addr));
    if (DTRACEG) {
        diagf("!Registering device or ROM table at %" CS_PHYSFMT "\n",
              addr);
    }
    if (cs_addr_is_excluded(addr)) {
        diagf("!skipping excluded device at %" CS_PHYSFMT "\n", addr);
        return ERRDESC;
    }
    local = (unsigned char *) io_map(addr, 4096, /*writable= */ 1);
    if (!local) {
        cs_report_error("can't map device at %" CS_PHYSFMT "", addr);
        return ERRDESC;
    }
    if (raw_read(local, CS_CIDR3) != 0xB1) {
        //cs_report_error("not a CoreSight component at %" CS_PHYSFMT "", addr);
        return ERRDESC;
    }
    cs_class = CS_CLASS_OF(raw_read(local, CS_CIDR1));
    if (cs_class == CS_CLASS_ROMTABLE) {
        /* Recursively scan a secondary ROM table */
        cs_scan_romtable(addr, local);
        io_unmap(local, 4096);
        return ERRDESC;		/* not a device */
    }

    if (cs_class == CS_CLASS_CORESIGHT) {
        unsigned int major, minor;
        unsigned int devaff0, devaff1, devid;

        d = cs_device_new(addr, local);
        assert(d != NULL);

        diagf("%" CS_PHYSFMT ":", addr);

        d->devtype_from_id = cs_device_read(d, CS_DEVTYPE);
        d->devaff0 = cs_device_read(d, CS_DEVAFF0);
        if (d->devaff0 != 0) {
            G.devaff0_used = 1;
        }
        devaff1 = cs_device_read(d, CS_DEVAFF1);
        devid = cs_device_read(d, CS_DEVID);
        /* Get the 3-digit PrimeCell device number */
        d->part_number =
            ((_cs_read(d, CS_PIDR1) & 0xF) << 8) | (_cs_read(d, CS_PIDR0) &
                                                    0xFF);

        /* For example, device type 0x13 is major=3, minor=1 */
        major = (d->devtype_from_id >> 0) & 15;
        minor = (d->devtype_from_id >> 4) & 15;

        /* Just in case the component's already unlocked when we register it,
           ensure our cached flag of its lock status is correctly set. */
        d->is_unlocked = _cs_isunlocked(d);
        d->is_permanently_unlocked = 0;

        /* Show basic information for the device. The first two numbers
           indicate the CoreSight device class. */
        diagf(" %u.%u %03X", major, minor, d->part_number);
        if (0)
            diagf(" %08X %08X %08X", devaff0, devaff1,
                  cs_device_read(d, CS_DEVARCH));
        diagf(" %08X", devid);
        diagf(" %02X/%02X", _cs_read(d, CS_CLAIMCLR) & 0xFF,
              _cs_read(d, CS_CLAIMSET) & 0xFF);

        /* See http://wiki.arm.com/Eng/PerphIDRegs */
        if (major == 1) {
            /* Trace sinks */
            d->devclass |= CS_DEVCLASS_SINK;
            d->n_in_ports = 1;
            if (minor == 1) {
                /* Trace port, e.g. TPIU or SWO */
                d->devclass |= CS_DEVCLASS_PORT;
                if (d->part_number == 0x912) {
                    d->type = DEV_TPIU;
                } else {
                    d->type = DEV_SWO;
                }
            } else if (minor == 2) {
                d->type = DEV_ETB;
                d->devclass |= CS_DEVCLASS_BUFFER;
                /* Find buffer size */
                if (d->part_number == 0x961) {	/* TMC */
                    d->v.etb.is_tmc_device = 1;
                    /* The TMC configuration type is a static property of the way the RTL was configured:
                       0 for ETB, 1 for ETR, 2 for ETF. */
                    d->v.etb.tmc.config_type = ((devid >> 6) & 0x3);
                    d->v.etb.buffer_size_bytes =
                        _cs_read(d, CS_ETB_RAM_DEPTH) << 2;
                    d->v.etb.pointer_scale_shift = 0;
                    d->v.etb.tmc.memory_width = ((devid >> 8) & 0x7);
                } else {
                    d->v.etb.is_tmc_device = 0;
                    d->v.etb.buffer_size_bytes =
                        _cs_read(d,
                                 CS_ETB_RAM_DEPTH) <<
                        ETB_WIDTH_SCALE_SHIFT;
                    d->v.etb.pointer_scale_shift = ETB_WIDTH_SCALE_SHIFT;
                }
            }
        } else if (major == 2) {
            /* Trace links */
            d->devclass |= CS_DEVCLASS_LINK;
            /* Default for a link is to have one in and one out */
            d->n_in_ports = 1;
            d->n_out_ports = 1;
            if (minor == 1) {
                d->type = DEV_FUNNEL;
                /* For a funnel, find the number of in-ports */
                d->n_in_ports = (devid & 0xf);
                if (d->n_in_ports == 0) {
                    d->n_in_ports = 8;
                }
            } else if (minor == 3) {
                d->type = DEV_ETF;
                d->devclass |= CS_DEVCLASS_SINK | CS_DEVCLASS_BUFFER;
                /* [1:0] MODE dynamically selects the operating mode [TMC 1.1.2].
                   The following are the operation modes:
                   3 = Reserved
                   2 = Hardware FIFO mode (ETF configuration only)
                   1 = Software FIFO mode
                   0 = Circular Buffer mode
                */
                /*_cs_write(d, CS_TMC_MODE, 0); pick teh mode later */
                d->v.etb.is_tmc_device = 1;
                /* Find buffer size - for TMC this is always in 32-bit words */
                d->v.etb.buffer_size_bytes =
                    _cs_read(d, CS_ETB_RAM_DEPTH) << 2;
                d->v.etb.pointer_scale_shift = 0;
                d->v.etb.tmc.config_type = ((devid >> 6) & 0x3);	/* For a link, expect ETF */
                d->v.etb.tmc.memory_width = ((devid >> 8) & 0x7);
            } else if (minor == 2) {
                d->type = DEV_REPLICATOR;
                d->n_out_ports = devid & 0xF;
            } else {
                /* TBD: future components? */
            }
        } else if (major == 3) {
            /* Trace sources */
            d->devclass |= CS_DEVCLASS_SOURCE;
            d->n_out_ports = 1;	/* ETMv4 might have two */
            if (minor == 1) {
                /* CPU trace source - be careful, the CPU might be powered off */
                d->type = DEV_ETM;
                d->devclass |= CS_DEVCLASS_CPU;
                d->v.etm.etmidr = 0;

                /* NB - ETM v4 does not have the CCR - and this bit is always one in a CoreSight ETM anyway
                   if (_cs_read(d, CS_ETMCCR) & 0x80000000) {
                   d->v.etm.etmidr = _cs_read(d, CS_ETMIDR);
                   } else {
                   d->v.etm.etmidr = 0;
                   } */
                /* always read the ETMIDR - establish the ETM architecture version */
                d->v.etm.etmidr = _cs_read(d, CS_ETMIDR);	/* same place on each etm */

                /* Store static configuration of ETM/PTM in device struct */

                /* init the static structure */
                _cs_etm_static_config_init(d);

            } else if (minor == 4) {
                /* ITM */
                d->type = DEV_ITM;
                d->devclass |= CS_DEVCLASS_SWSTIM;
                /* The docs just say DEVID specifies the number of ports (32) but
                   future-proof it by masking off the top bits. */
                d->v.itm.n_ports = devid & 0xFFFF;
            } else if (minor == 6) {
                /* STM */
                d->type = DEV_STM;
                d->devclass |= CS_DEVCLASS_SWSTIM;
                d->ops.unregister = cs_stm_device_unregister;
                d->v.stm.n_ports = devid & 0x1FFFF;
                _cs_stm_config_static_init(d);
                d->v.stm.n_masters =
                    d->v.stm.s_config.spfeat3.bits.nummast + 1;
                /* [17:16] SPTYPE Stimulus Port type support:
                   b00 = Only Basic Stimulus Ports implemented.
                   b01 = Only Extended Stimulus Ports implemented.
                   b10 = Both Basic and Extended Stimulus Ports implemented.
                */
                switch (d->v.stm.s_config.spfeat2.bits.sptype) {
                case 0x0:
                    if (d->v.stm.n_ports > 32) {
                        cs_report_error
                            ("STM can handle max. 32 basic ports");
                        return ERRDESC;
                    }
                    d->v.stm.basic_ports = 1;
                    break;
                case 0x2:
                    d->v.stm.basic_ports = 1;
                    /* Fall-through */
                case 0x1:
                    /* Allocate the array of pointers to the port ranges */
                    d->v.stm.ext_ports =
                        (unsigned char **) malloc(sizeof(unsigned char *) *
                                                  d->v.stm.n_masters);
                    memset(d->v.stm.ext_ports, 0,
                           sizeof(unsigned char *) * d->v.stm.n_masters);
                    d->v.stm.current_master = 0;
                    break;
                }
            }
        } else if (major == 4) {
            /* Debug control */
            if (minor == 1) {
                d->devclass |= CS_DEVCLASS_CTI;
                d->type = DEV_CTI;
                d->v.cti.n_channels = (devid >> 16) & 0xF;
                d->v.cti.n_triggers = (devid >> 8) & 0x1F;
                if (d->v.cti.n_triggers > CTI_MAX_IN_PORTS) {
                    d->v.cti.n_triggers = CTI_MAX_IN_PORTS;
                }
            }
            /* We'd like to set CS_DEVCLASS_CPU here if it's a CPU's CTI */
        } else if (major == 5) {
            /* Debug logic */
            if (minor == 1) {
                d->devclass |= CS_DEVCLASS_DEBUG | CS_DEVCLASS_CPU;
                d->type = DEV_CPU_DEBUG;
                if ((d->part_number & 0xF00) == (0xD00)) {
                    /* v8 Arch core */
                    d->v.debug.debug_arch = 0x8;
                    d->v.debug.didr = _cs_read(d, CS_V8EDDFR_l);	/* bottom half of EDDFR contains similar stuff to v7 DIDR. */
                    d->v.debug.devid = _cs_read(d, CS_V8EDDEVID);
                    d->v.debug.pcsamplereg = CS_DBGPCSR_40;
                } else {
                    /* v7 arch core */
                    d->v.debug.debug_arch = 0x7;
                    d->v.debug.didr = _cs_read(d, CS_DBGDIDR);
                    if (((d->v.debug.didr >> 16) & 0xF) >= 0x5 ||
                        (d->v.debug.didr & CS_DBGDIDR_DEVID_imp) != 0) {
                        d->v.debug.devid = _cs_read(d, CS_DBGDEVID);
                    } else {
                        d->v.debug.devid = 0;
                    }
                    /* Follow the procedure in C10.1.1 to establish which register
                       is the PC sampling register */
                    d->v.debug.pcsamplereg = 0;
                    if (d->v.debug.didr & CS_DBGDIDR_PCSR_imp) {
                        d->v.debug.pcsamplereg = CS_DBGPCSR_33;
                    }
                    if ((d->v.debug.devid & 0x0F) > 1) {
                        d->v.debug.pcsamplereg = CS_DBGPCSR_40;
                    }
                }
            } else if (minor == 7) {
                /* logic analysers - Stygian or ELA-500 */
                d->devclass |= CS_DEVCLASS_TRIGSRC | CS_DEVCLASS_ELA;
                d->type = DEV_ELA;
            }
        } else if (major == 6) {
            /* Performance monitor */
            d->devclass |= CS_DEVCLASS_PMU;
            if (minor == 1) {
                d->devclass |= CS_DEVCLASS_CPU;
                d->type = DEV_CPU_PMU;
                d->v.pmu.cfgr = _cs_read(d, CS_PMCFGR);
                /* Number of counters will be in PMCFGR, but PMCR may be more correct */
                d->v.pmu.n_counters = d->v.pmu.cfgr & 0xFF;
                {
                    unsigned int pmcr = _cs_read(d, CS_PMCR);
                    unsigned int n = (pmcr >> 11) & 0x1F;
                    if (n != 0 && n != d->v.pmu.n_counters) {
                        d->v.pmu.n_counters = n;
                    }
                }
                /* Set up the scale for indexing into the PMU counters in memory */
                d->v.pmu.map_scale =
                    ((d->v.pmu.cfgr & 0x00003f00) == 0x00003f00) ? 3 : 2;
            } else {
                /* Device PMU */
                d->v.pmu.n_counters = -1;	/* unknown */
            }
        }

        /* If we haven't identified this as a CPU-affine device,
           make sure it's indicated as non-affine.  Currently we have
           no way to indicate cluster-affine devices. */
        if (!(d->devclass & CS_DEVCLASS_CPU)) {
            d->affine_cpu = CS_NO_CPU;
        }
    } else if (cs_class == CS_CLASS_PRIMECELL) {
        /* Wouldn't normally be seen in a CoreSight ROM table. */
        unsigned int part_number =
            ((raw_read(local, CS_PIDR1) & 0xF) << 8) |
            (raw_read(local, CS_PIDR0) & 0xFF);
        if (part_number == 0x101) {
            d = cs_device_new(addr, local);
            assert(d != NULL);
            d->is_unlocked = 1;
            d->is_permanently_unlocked = 1;
            d->part_number = part_number;
            d->devclass = CS_DEVCLASS_TIMESTAMP;
            d->type = DEV_TS;
            G.timestamp_device = d;
            /* assume CS timestamp gen which must have control interface. */
            d->v.ts.config.if_type = TSGEN_INTERFACE_CTRL;

            diagf("%" CS_PHYSFMT ":", addr);

        } else {
            diagf("!Unexpected PrimeCell part %03X at %" CS_PHYSFMT "\n",
                  part_number, addr);
            return ERRDESC;
        }
    } else {
        diagf("!Unexpected device class %u at %" CS_PHYSFMT "\n",
              cs_class, addr);
        return ERRDESC;
    }

    if (d != NULL) {
        diagf(" type=%2d", d->type);
        diagf(" %c", (d->is_unlocked ? 'O' : '-'));
        if (d->devclass & CS_DEVCLASS_CPU) {
            /* CoreSight component belonging to a CPU.  DEVAFF0 might or might not be
               set to indicate the MPIDR of the CPU.  Note that CPU CTIs don't seem
               to have DEVAFF0 set - which means they're indistinguishable from
               non-CPU CTIs. */
            diagf(" CPU %u.%u", (d->devaff0 >> 8) & 0xff,
                  (d->devaff0) & 0xff);
        }
        if (d->devclass & CS_DEVCLASS_SOURCE)
            diagf(" SOURCE");
        if (d->devclass & CS_DEVCLASS_SWSTIM) {
            diagf(" SWSTIM(%u)",
                  cs_trace_swstim_get_port_count(DEVDESC(d)));
            if (d->type == DEV_STM) {
                diagf(" [STM %s, %u-bit, %u masters]",
                      (d->v.stm.
                       basic_ports ? ((d->v.stm.ext_ports == 0) ?
                                      "basic ports only" :
                                      "basic and ext ports") :
                       "ext ports only"),
                      (d->v.stm.s_config.spfeat2.bits.dsize ? 64 : 32),
                      d->v.stm.n_masters);
            }
        }
        if (d->devclass & CS_DEVCLASS_TRIGSRC)
            diagf(" TRIG_SRC");
        if (d->devclass & CS_DEVCLASS_ELA) {
            diagf(" LOGIC ANALYSER");
        }
        if (d->devclass & CS_DEVCLASS_LINK)
            diagf(" LINK");
        if (d->devclass & CS_DEVCLASS_SINK)
            diagf(" SINK");
        if (d->devclass & CS_DEVCLASS_BUFFER) {
            if ((d->type == DEV_ETB) && d->v.etb.is_tmc_device
                && (d->v.etb.tmc.config_type == CS_TMC_CONFIG_TYPE_ETR)) {
                diagf(" BUFFER(ETR r/w size: %uK)",
                      cs_get_buffer_size_bytes(DEVDESC(d)) / 1024);
            } else
                diagf(" BUFFER(%uK)",
                      cs_get_buffer_size_bytes(DEVDESC(d)) / 1024);
        }
        if (d->devclass & CS_DEVCLASS_PORT)
            diagf(" PORT");
        if (d->devclass & CS_DEVCLASS_CTI)
            diagf(" CTI");
        if ((d->devclass & CS_DEVCLASS_LINK)
            || (d->devclass & CS_DEVCLASS_SINK)) {
            switch (d->type) {
            case DEV_ETF:
                assert(d->v.etb.is_tmc_device);
                diagf(" [TMC: ETF configuration]");
                break;
            case DEV_ETB:
                if (d->v.etb.is_tmc_device) {
                    /* can't be ETF as this is filtered out earlier */
                    diagf(" [TMC: %s configuration]",
                          (d->v.etb.tmc.config_type ==
                           CS_TMC_CONFIG_TYPE_ETR) ? "ETR" : "ETB");
                } else {
                    diagf(" [ETB]");
                }
                break;
            case DEV_TPIU:
                diagf(" [TPIU]");
                break;
            case DEV_SWO:
                diagf(" [SWO]");
                break;
            case DEV_FUNNEL:
                diagf(" [FUNNEL: %u in ports]", d->n_in_ports);
                break;
            case DEV_REPLICATOR:
                diagf(" [REPLICATOR: %u out ports]", d->n_out_ports);
                break;
            }
        }
        if (d->devclass & CS_DEVCLASS_DEBUG) {
            diagf(" DEBUG");
            if (d->v.debug.debug_arch == 0x8) {	/* v8 debug */
                if ((d->v.debug.didr & 0xF) == 0x6)
                    diagf(" v8");
                else
                    diagf(" unknown");
                diagf(" (%u bkpt)", ((d->v.debug.didr >> 12) & 0xF) + 1);
                diagf(" (%u wpt)", ((d->v.debug.didr >> 20) & 0xF) + 1);
                diagf(" (%u ctx_cmp)",
                      ((d->v.debug.didr >> 28) & 0xF) + 1);
                if ((d->v.debug.devid & 0xF) > 0) {
                    switch (d->v.debug.devid & 0xF) {
                    case 2:
                        diagf(" sample: PCSR, CIDSR");
                        break;
                    case 3:
                        diagf(" sample: PCSR, CIDSR, VIDSR");
                        break;
                    }
                }
            } else {		/* v7 debug */

                switch ((d->v.debug.didr >> 16) & 0xF) {
                case 1:
                    diagf(" v6");
                    break;
                case 2:
                    diagf(" v6.1");
                    break;
                case 3:
                    diagf(" v7 (full CP14)");
                    break;
                case 4:
                    diagf(" v7 (base CP14)");
                    break;
                case 5:
                    diagf(" v7.1");
                    break;
                }
                diagf(" (%u wpt)", ((d->v.debug.didr >> 28) & 0xF) + 1);
                diagf(" (%u bkpt)", ((d->v.debug.didr >> 24) & 0xF) + 1);
                if ((d->v.debug.devid & 0xF) >= 1) {
                    diagf(" sample:PC");
                    if ((d->v.debug.devid & 0xF) >= 2) {
                        diagf(",CXID");
                        if ((d->v.debug.devid & 0xF) >= 3) {
                            diagf(",VMID");
                        }
                    }
                }
            }
            {
                unsigned int dscr = _cs_read(d, CS_DBGDSCR);
                if (dscr & CS_DBGDSCR_NS) {
                    diagf("; non-Secure, ");
                } else {
                    diagf("; Secure,");
                }
                if (dscr & CS_DBGDSCR_HALTED) {
                    unsigned int moe = (dscr >> 2) & 0xF;
                    diagf(" halted(%u)", moe);
                } else {
                    diagf(" running");
                }
            }
        }
        if (d->devclass & CS_DEVCLASS_PMU) {
            diagf(" PMU (%u counters)", d->v.pmu.n_counters);
        }
        if (d->devclass & (CS_DEVCLASS_DEBUG | CS_DEVCLASS_PMU)) {
            /* CS_DBGAUTHSTATUS == CS_PMAUTHSTATUS */
            unsigned int auth = _cs_read(d, CS_DBGAUTHSTATUS);
            /* There are 4 types of authentication:
               SNI[7:6], SI[5:4], NSNI[3:2], NSI[1:0] */
            /* Each has 3 states: 00 (n.imp.), 10 (imp.dis), 11 (imp.en) */
            diagf(" auth=%02X", auth);
        }
        if (d->devclass & CS_DEVCLASS_TIMESTAMP)
            diagf(" TIMESTAMP");
        switch (d->type) {
        case DEV_ETM:
	    {
            /* Major version number: 2: ETMv3, 3: PTM, 4: ETMv4 */
            unsigned int major = ((d->v.etm.etmidr) >> 8) & 0xF;
            unsigned int minor = ((d->v.etm.etmidr) >> 4) & 0xF;
            diagf(" %cTMv%u.%u",
                  ((major == 3) ? 'P' : 'E'),
                  ((major < 3) ? (major + 1) : (major ==
                                                3) ? 1 : major),
                  minor);
	    }
	    break;
        }
        diagf("\n");
        /* Keep it mapped */
    }

    return DEVDESC(d);
}


static struct cs_device *cs_device_find(cs_physaddr_t addr)
{
    struct cs_device *d;
    for (d = G.device_top; d != NULL; d = d->next) {
        if (d->phys_addr == addr) {
            break;
        }
    }
    return d;
}

static void cs_set_default_power_domain(cs_power_domain_t pd)
{
    G.power_domain_default = pd;
}


/*
  CSARCH2 16.2.5
*/
static int cs_scan_romtable(cs_physaddr_t rom_addr, void const *tabv)
{
    unsigned int i;
    unsigned int const *tab = (unsigned int const *) tabv;

    if (DTRACEG) {
        diagf("!Scanning ROM table at %" CS_PHYSFMT " (mapped to %p)\n",
              rom_addr, tabv);
    }
    assert(G.registration_open);
    if (CS_CLASS_OF(tab[CS_CIDR1 / 4]) != CS_CLASS_ROMTABLE) {
        return cs_report_error("page at %" CS_PHYSFMT
                               " is not a CoreSight ROM table", rom_addr);
    }
    /* "The first entry is at address 0x000. Each subsequent entry is at
       the next 4-byte boundary, until a value of 0x00000000 is read which
       is the final entry." */
    for (i = 0; i <= (0xEFC / 4); ++i) {
        unsigned int entry = tab[i];
        if (entry == 0x00000000) {
            break;
        }
        if ((entry & 1) == 0) {
            /* Entry not present */
        } else {
            cs_physaddr_t dev_addr;
            unsigned int offset = (entry & 0xFFFFF000);
            int power_domain = (entry & 4) ? ((entry >> 4) & 31) : -1;
            cs_set_default_power_domain(power_domain);
            dev_addr = rom_addr + offset;
            cs_device_or_romtable_register(dev_addr);
        }
    }
    return 0;
}

static void _cs_link_affinity(struct cs_device *dbg,
                              struct cs_device *other)
{
    assert(dbg->type == DEV_CPU_DEBUG);
    switch (other->type) {
    case DEV_CPU_DEBUG:
        /* ignore */
        break;
    case DEV_CPU_PMU:
        dbg->v.debug.pmu = other;
        break;
    case DEV_ETM:
        dbg->v.debug.etm = other;
        break;
    case DEV_CTI:
        dbg->v.debug.cti = other;
        break;
    }
}

/* Used in asserts only */
#ifdef DEBUG
static int cs_device_has_atb_out(struct cs_device *d)
{
    return (d->devclass & (CS_DEVCLASS_SOURCE | CS_DEVCLASS_LINK)) != 0;
}

static int cs_device_has_atb_in(struct cs_device *d)
{
    return (d->devclass & (CS_DEVCLASS_LINK | CS_DEVCLASS_SINK)) != 0;
}

static int cs_device_outport_is_valid(struct cs_device *d, unsigned int p)
{
    return cs_device_has_atb_out(d) && p < d->n_out_ports;
}

static int cs_device_inport_is_valid(struct cs_device *d, unsigned int p)
{
    return cs_device_has_atb_in(d) && p < d->n_in_ports;
}
#endif
/* ========== API functions ================ */

/* ========= registration group =========== */

int cs_register_romtable(cs_physaddr_t rom_addr)
{
    int rc;
    unsigned int *tab;

    if (!is_4k_page_address(rom_addr)) {
        return cs_report_error("ROM table must be 4K-aligned");
    }
    if (DTRACEG) {
        diagf("!registering ROM table at %" CS_PHYSFMT "\n", rom_addr);
    }
    assert(G.init_called);
    tab = (unsigned int *) io_map(rom_addr, 4096, /*writable= */ 0);
    if (!tab) {
        return cs_report_error("can't map ROM table at %" CS_PHYSFMT "",
                               rom_addr);
    }
    rc = cs_scan_romtable(rom_addr, tab);
    io_unmap(tab, 4096);
    return rc;
}

/*
  Register a device at a given address.
*/
cs_device_t cs_device_register(cs_physaddr_t addr)
{
    struct cs_device *d;

    assert(G.registration_open);
    d = cs_device_find(addr);
    if (d != NULL) {
        /* Device was already registered */
        return DEVDESC(d);
    } else {
        return cs_device_or_romtable_register(addr);
    }
}



int cs_exclude_range(cs_physaddr_t from, cs_physaddr_t to)
{
    struct addr_exclude *a =
        (struct addr_exclude *) malloc(sizeof(struct addr_exclude));
    if (a == NULL) {
        return -1;
    }
    assert(from <= to);
    if (from < to) {
        a->from = from;
        a->to = to;
        a->next = G.exclusions;
        G.exclusions = a;
    }
    return 0;
}


int cs_device_set_affinity(cs_device_t dev, cs_cpu_t cpu)
{
    struct cs_device *d = DEV(dev);

    assert(G.registration_open);
    if (cpu == CS_NO_CPU) {
        return 0;
    }
    d->affine_cpu = cpu;
    if (d->type == DEV_CPU_DEBUG) {
        /* See if any CTI, PMU or ETM are affine to this CPU, and link them up */
        struct cs_device *e;
        for (e = G.device_top; e != NULL; e = e->next) {
            if (e != d && e->affine_cpu == cpu) {
                _cs_link_affinity(d, e);
            }
        }
    } else {
        cs_device_t ed =
            cs_cpu_get_device(cpu, CS_DEVCLASS_CPU | CS_DEVCLASS_DEBUG);
        if (ed != ERRDESC) {
            _cs_link_affinity(DEV(ed), d);
        }
    }
    return 0;
}

int cs_device_set_power_domain(cs_device_t dev,
                               cs_power_domain_t power_domain)
{
    struct cs_device *d = DEV(dev);
    d->power_domain = power_domain;
    return 0;
}

int cs_atb_register(cs_device_t from, unsigned int from_port,
                    cs_device_t to, unsigned int to_port)
{
    struct cs_device *fd = DEV(from);
    struct cs_device *td = DEV(to);
    assert(cs_device_outport_is_valid(fd, from_port));
    assert(cs_device_inport_is_valid(td, to_port));
    assert(fd->outs[from_port] == NULL);
    fd->outs[from_port] = DEV(to);
    fd->to_in_port[from_port] = to_port;
    assert(td->ins[to_port] == NULL);
    td->ins[to_port] = DEV(from);
    td->from_out_port[to_port] = from_port;
    return 0;
}

/*
  Check for valid trace id.
  0x00: indicates null trace source.
  0x70-0x7C: reserved
  0x7D: trigger
  0x7E: reserved
  0x7F: reserved to avoid confusion with sync packet
*/
int cs_atid_is_valid(cs_atid_t id)
{
    return id > 0x00 && id < 0x70;
}


cs_device_t cs_atb_add_replicator(unsigned int n_outports)
{
    struct cs_device *d = cs_device_new(CS_NO_PHYS_ADDR, NULL);
    assert(n_outports > 1 && n_outports <= CS_MAX_OUT_PORTS);
    d->devclass |= CS_DEVCLASS_LINK;
    d->n_in_ports = 1;
    d->n_out_ports = n_outports;
    return DEVDESC(d);
}

int cs_registration_complete(void)
{
    G.registration_open = 0;
    return 0;
}

int cs_registration_completed(void)
{
    return !G.registration_open;
}




/*  ========= topology iteration group =========== */

cs_device_t cs_device_first(void)
{
    return DEVDESC(G.device_top);
}

cs_device_t cs_device_next(cs_device_t dev)
{
    struct cs_device *d;
    assert(dev != ERRDESC);
    d = DEV(dev);
    assert(d != NULL);
    if (d->next == NULL) {
        return ERRDESC;
    } else {
        return DEVDESC(d->next);
    }
}

int cs_device_has_class(cs_device_t dev, unsigned int cls)
{
    struct cs_device *d = DEV(dev);
    return (d->devclass & cls) == cls;
}

cs_devtype_t cs_device_get_type(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    return d->type;
}

/*
  Trace Bus topology metadata accessors
*/
int cs_num_out_ports(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    return d->n_out_ports;
}

int cs_num_in_ports(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    return d->n_in_ports;
}


cs_device_t cs_get_device_at_outport(cs_device_t dev, unsigned int port)
{
    struct cs_device *d = DEV(dev);
    struct cs_device *dev_outport = d->outs[port];
    assert(cs_device_outport_is_valid(d, port));
    return DEVDESC(dev_outport);
}

unsigned char cs_get_dest_inport(cs_device_t dev, unsigned int port)
{
    struct cs_device *d = DEV(dev);
    assert(cs_device_outport_is_valid(d, port));
    return d->to_in_port[port];
}


cs_device_t cs_get_device_at_inport(cs_device_t dev, unsigned int port)
{
    struct cs_device *d = DEV(dev);
    struct cs_device *dev_inport = d->ins[port];
    assert(cs_device_inport_is_valid(d, port));
    return DEVDESC(dev_inport);
}

unsigned char cs_get_src_outport(cs_device_t dev, unsigned int port)
{
    struct cs_device *d = DEV(dev);
    assert(cs_device_inport_is_valid(d, port));
    return d->from_out_port[port];
}


cs_cpu_t cs_device_get_affinity(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    return d->affine_cpu;
}


cs_device_t cs_cpu_get_device(cs_cpu_t cpu, unsigned int cls)
{
    struct cs_device *d;
    for (d = G.device_top; d != NULL; d = d->next) {
        if (d->affine_cpu == cpu && (d->devclass & cls) == cls) {
            break;
        }
    }
    if (d != NULL) {
        return DEVDESC(d);
    } else {
        return ERRDESC;
    }
}

cs_device_t cs_device_get(cs_physaddr_t addr)
{
    struct cs_device *d = cs_device_find(addr);
    if (d != NULL) {
        return DEVDESC(d);
    } else {
        return ERRDESC;
    }
}

unsigned int cs_device_get_MPIDR(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    return d->devaff0;
}

unsigned int cs_n_devices(void)
{
    return G.n_devices;
}


/* end of cs_topology.c */
