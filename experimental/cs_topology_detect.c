/*
CoreSight topology detection

Copyright (C) ARM Ltd. 2016.  All rights reserved.

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

/*
This module auto-detects CoreSight trace bus connectivity by probing the
integration test registers on each device.  This is recommended only to be
used in a controlled environment, when configuring the library for a new device.
Once the topology is known, suitable configuration calls should be programmed
in for production use.

TBD:
  - invisible funnels (multiple masters for one slave)
  - ETMv4 data trace
  - CTI
*/

#include "cs_topology_detect.h"

#include "csaccess.h"

#include "csregisters.h"
#include "cs_reg_access.h"

#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/*
Test if device is part of the ATB fabric.
*/
static int cs_device_has_atb(cs_device_t d)
{
  return cs_num_out_ports(d) > 0 || cs_num_in_ports(d) > 0;
}


/*
Check if device is needed for topology detection - for now, we just
need ATB devices (so no CTI, CPU debug or PMU).
*/
static int detecting_atb(cs_device_t d)
{
  if (!cs_device_has_atb(d)) {
    return 0;
  }
  if (cs_device_address(d) == 1) {
    /* Non-memory-mapped ATB device: e.g. invisible replicator or funnel */
    return 0;
  }
  return 1;
}
   

static int cs_device_quiesce(cs_device_t d)
{
  int rc;
  cs_devtype_t const type = cs_device_get_type(d);
  if (cs_device_has_class(d, CS_DEVCLASS_SOURCE)) {
    rc = cs_trace_disable(d);
    assert(!cs_trace_is_enabled(d));
  } else if (type == DEV_FUNNEL) {
    /* disable all input ports */
    rc = cs_device_clear(d, CS_FUNNEL_CTRL, 0xFF);
  } else if (type == DEV_ETB || type == DEV_ETF || type == DEV_TPIU) {
    rc = cs_sink_disable(d);
  } else {
    rc = 0;
  }
  return rc;
}


int fake_in_ports(cs_device_t d) {
  if (cs_device_get_type(d) == DEV_FUNNEL) {
    return cs_num_in_ports(d) + 1;
  } else { 
    return cs_num_in_ports(d);
  }
}

#define cs_num_in_ports(d) fake_in_ports(d)


/*
Put any device into or out of integration mode.
(For CPU PMUs, this has no effect.)
*/
static int cs_set_integration_mode(cs_device_t d, int flag)
{
  if (flag) {
    /* Enter integration mode, first disabling device activity */
    int rc = cs_device_quiesce(d);
    if (rc) {
      return rc;
    }
    /* For a TMC, it's not enough to quiesce (stop) the device.
       It must be disabled. */
    if (cs_device_get_type(d) == DEV_ETF) {
      cs_device_clear(d, CS_ETB_CTRL, CS_ETB_CTRL_TraceCaptEn);
    }
    /* Now enter integration mode. Typically a device must already be disabled.
       E.g. TMC: "Writing to this register other than when in Disabled state
       results in Unpredictable behavior." */
    rc = cs_device_set(d, 0xF00, 0x01);
    if (!(cs_device_read(d, 0xF00) & 0x01)) {
      return -1;
    }
    return rc;
  } else {
    /* Leave integration mode */
    return cs_device_clear(d, 0xF00, 0x1);
  }
}



/*
Enable a single port on a funnel.  Return <0 if the port can't be enabled,
e.g. because it's outside the range of supported ports.
*/
static int cs_funnel_enable_only(cs_device_t d, unsigned int port)
{
  int rc;
  unsigned int x = cs_device_read(d, CS_FUNNEL_CTRL);
  rc = cs_device_write_only(d, CS_FUNNEL_CTRL, (x & 0xFFFFFF00) | (1U << port));
  if (rc < 0) {
    return rc;
  }
  x = cs_device_read(d, CS_FUNNEL_CTRL);
  if ((x & 0xFF) != (1U << port)) {
    /* No ports selected - port was out of range */
    return -1;
  }
  return 0;
}


/*
Set to 1 or 0 the value of the downstream ATVALIDM signal, on a given
ATB master port (port 0 other than for replicators and ETMv4 data trace).
*/
static int cs_set_integration_ATVALIDM(cs_device_t m, unsigned int mp, int flag)
{
  int const is_replicator = (cs_device_get_type(m) == DEV_REPLICATOR);
  unsigned int ATVALIDM_reg;
  unsigned int ATVALIDM_mask = is_replicator ? (0x01 << (mp*2)) : 0x01;
  assert(mp < cs_num_out_ports(m));
  switch (cs_device_get_type(m)) {
  case DEV_REPLICATOR:
    ATVALIDM_reg = 0xEFC;
    break;
  case DEV_ETF:
    ATVALIDM_reg = 0xEDC;
    break;
  case DEV_ETM:
    if (cs_etm_get_version(m) < CS_ETMVERSION_ETMv4) {
      ATVALIDM_reg = 0xEF8;
    } else if (cs_num_out_ports(m) == 2) {
      /* For ETMv4 with data trace (Cortex-R7, 0x936), 0xEFC is instruction ATB */
      ATVALIDM_reg = ((mp == 0) ? 0xEFC : 0xEF8);
    } else {
      /* ETMv4 on R/M-profile may have two ports - instruction and data */
      /* Even for A-profile the port may vary between CPUs - need to check TRCPIDR0 */
      switch (cs_device_part_number(m)) {
      case 0x95D:   /* Cortex-A53 */
      case 0x959:   /* Cortex-A73 */
      default:
        ATVALIDM_reg = 0xEFC;
        break;
      case 0x95E:   /* Cortex-A57 */
      case 0x95A:   /* Cortex-A72 */
        ATVALIDM_reg = 0xEF8;
        break;
      }
    }
    break;
  default:
    ATVALIDM_reg = 0xEF8;
    break;
  }
  /* This actually writes zeroes into all the other bits...
     but during topology detection that hopefully won't matter. */
  if (0) {
    fprintf(stderr, "  setting %#x mask 0x%02x to %u\n", ATVALIDM_reg, ATVALIDM_mask, flag);
  }
  return cs_device_write_only(m, ATVALIDM_reg, (flag ? ATVALIDM_mask : 0));
}


/*
Test the value of the upstream ATVALIDS signal.
Return non-zero if the signal is observed.
Hence, on error we must return zero.
*/
static int cs_get_integration_ATVALIDS(cs_device_t s, unsigned int sp)
{
  int valid = 0;
  unsigned int const ATVALIDS_reg = 0xEF8;
  unsigned int const ATVALIDS_mask = (cs_device_get_type(s) == DEV_REPLICATOR) ? 0x08 : 0x01;
  assert(sp < cs_num_in_ports(s));
  if (cs_device_get_type(s) == DEV_FUNNEL) {
    /* Funnels don't have separate integration bits for each of their
       ATB slave ports - instead the control register is used to select the
       active slave port. */
    int rc = cs_funnel_enable_only(s, sp);
    if (rc) {
      return 0;    /* return false on failure to select this port */
    }
  }
  valid = (cs_device_read(s, ATVALIDS_reg) & ATVALIDS_mask) != 0;
  return valid;
}


static int cs_set_integration_ATREADYS(cs_device_t s, unsigned int sp)
{
  int const is_replicator = (cs_device_get_type(s) == DEV_REPLICATOR);
  unsigned int const ATREADYS_reg = is_replicator ? 0xEFC : 0xEF0;
  unsigned int const ATREADYS_mask = is_replicator ? 0x10 : 0x01;
  assert(sp < cs_num_in_ports(s));
  if (cs_device_get_type(s) == DEV_FUNNEL) {
    cs_funnel_enable_only(s, sp);
  }
  return cs_device_write_only(s, ATREADYS_reg, ATREADYS_mask);
}


/*
Topology detection via integration registers.

The devices are assumed to have been already enumerated e.g. by ROM table scan.

  1. Disable and set integration mode on all devices
  2. Check that integration registers aren't wiggling by themselves
  3. Wiggle integration registers and look for the wiggle in other devices
  4. Unset integration mode on all devices

The process is explained more fully in [CSA2.0] D6.4, "Detection algorithm".

It is not guaranteed that the CoreSight subsystem is in a usable state
once the topology detection is done.  For regular use this is not meant to
be an alternative to setup via a device description.

The 'do_construct' parameter controls whether the detector calls the API
to stitch the devices together.  If you want to traverse and print out the
resulting topology, you probably want to do that.

CoreSight trace fabrics may have invisible (non-programmable) replicators
and funnels, the latter typically inside CPU clusters.

Currently CSAL does not handle invisible funnels.

Topology detection detects a master being connected to multiple slaves,
and explicitly constructs a non-programmable replicator.  An alternative
would be to have CSAL spot when a master output port is being connected
to a second slave, and automatically insert an invisible replicator.

Similarly, CSAL could spot when a slave output was being connected to
a second master, and automatically insert an invisible funnel.
*/
int cs_detect_topology(int do_construct)
{
  int ok = 0;
  cs_device_t m;
  fprintf(stderr, "CoreSight topology detection\n");
  if (cs_error_count() > 0) {
    fprintf(stderr, "Detection abandoned - pending errors\n");
    return -1;
  }
  /* Switch to integration mode */
  fprintf(stderr, "Switching to integration mode...\n");
  cs_for_each_device(m) if (detecting_atb(m)) {
    int rc = cs_set_integration_mode(m, 1);
    if (rc) {
      fprintf(stderr, "Failed to set integration mode for %" CS_PHYSFMT "\n", cs_device_address(m));
      /* carry on... */
    }
  }
  if (cs_error_count() > 0) {
    fprintf(stderr, "Couldn't switch all devices to integration mode\n");
  }
  /* Master preamble and slave preamble combined - set all bits to zero. */
  fprintf(stderr, "Master/slave preamble...\n");
  cs_for_each_device(m) if (detecting_atb(m)) {
    /* Set all integration bits to zero. */
    /* For funnels, to clear ATREADYS on all slaves, we should iterate
       through all the ports. */
    int const is_funnel = (cs_device_get_type(m) == DEV_FUNNEL);
    /* Ensure all slave/master ports are cleared - so we need 1 go through
       even for source-only devices. */
    unsigned int const n_slaves = is_funnel ? cs_num_in_ports(m) : 1;
    unsigned int sp;
    for (sp = 0; sp < n_slaves; ++sp) {
      if (is_funnel) {
        if (0 > cs_funnel_enable_only(m, sp)) {
          break;
        }
      } 
      cs_device_write_only(m, 0xEF0, 0);
      cs_device_write_only(m, 0xEF8, 0);
      cs_device_write_only(m, 0xEFC, 0);
      if (cs_device_get_type(m) == DEV_ETF) {
        cs_device_write_only(m, 0xEDC, 0);
      }
    }
    /* Possibly not necessary, but leaving the funnel with one specific
       port enabled could leave the funnel forwarding trace valid signals
       from an upstream master to some other downstream slave. */
    if (is_funnel) {  
      cs_device_clear(m, CS_FUNNEL_CTRL, 0xFF);
    }
  }
  if (cs_error_count() > 0) {
    fprintf(stderr, "Errors occurred in preamble - abandoning detection\n");
    goto done;
  }
  /* Use the integration registers to detect ATB topology.
     The sequence for ATB relies on asserting upstream and checking
     for the assert downstream:
       master: ATVALIDM := 0
       slave: ATREADYS := 0
       master: ATVALIDM := 1
       slave: look for ATVALIDS == 1
       slave: ATREADYS := 1
       master: ATVALIDM := 0
       slave: check ATVALIDS == 0
       slave: ATREADYS := 0
  */
  fprintf(stderr, "Detecting ATB topology...\n");
  cs_for_each_device(m) if (detecting_atb(m)) {
    unsigned int const n_master_ports = cs_num_out_ports(m);
    unsigned int mp;
    for (mp = 0; mp < n_master_ports; ++mp) {
      cs_device_t s;
      unsigned int n_found = 0;
      struct slave {
        struct slave *next;
        cs_device_t slave;
        unsigned int slave_port;
      };
      struct slave *slaves = NULL;
      /* Set ATVALIDM := 1 on master(s) */
      fprintf(stderr, "checking master %" CS_PHYSFMT " port %u\n", cs_device_address(m), mp);    
      cs_set_integration_ATVALIDM(m, mp, 1);
      /* Scan slaves, looking for ATVALIDS.  Potentially (if there are invisible
         replicators in the way) we could see ATVALIDS on several downstream slaves. */
      usleep(100);
      cs_for_each_device(s) {
        unsigned int sp;
        if (s == m) continue;
        if (!detecting_atb(s)) continue;       
        unsigned int const n_slave_ports = cs_num_in_ports(s);
        if (0) {
          fprintf(stderr, "  checking slave %" CS_PHYSFMT " (%u in-ports)\n", cs_device_address(s), n_slave_ports);
        }
        for (sp = 0; sp < n_slave_ports; ++sp) {
          /* slave: look for ATVALIDS == 1 */
          if (cs_get_integration_ATVALIDS(s, sp)) {
            struct slave *sl;
            fprintf(stderr, "  %" CS_PHYSFMT " (slave port %u) ATVALIDS is set\n",
                cs_device_address(s), sp);
            /* slave: set ATREADYS := 1 */
            cs_set_integration_ATREADYS(s, sp);
            /* master: set ATVALIDM := 0 */
            cs_set_integration_ATVALIDM(m, mp, 0);
            /* slave: check ATVALIDS == 0 */
            if (cs_get_integration_ATVALIDS(s, sp)) {
              fprintf(stderr, "  stuck at 1\n");
            }
            ++n_found;
            sl = (struct slave *)malloc(sizeof(struct slave));
            sl->next = slaves;
            sl->slave = s;
            sl->slave_port = sp;
            slaves = sl;
            cs_set_integration_ATVALIDM(m, mp, 1);   /* Ready for next time */
            break;    /* don't check other in-ports for this slave */
          }
        } /* for each of the slave's input ports */
        /* See note in the preamble code about why it's important to leave
           the funnel disabled. */
        if (cs_device_get_type(s) == DEV_FUNNEL) {
          cs_device_clear(s, CS_FUNNEL_CTRL, 0xFF);
        }
      } /* for each potential slave device in the system */
      /* Set ATVALIDM := 0 on master port */
      cs_set_integration_ATVALIDM(m, mp, 0);
      /* We now have a list of slave ports that are connected to this master port. */
      if (n_found > 0) {        
        struct slave *sl;
        struct slave *next;
        cs_device_t md = m;
        unsigned int slix = 0;
        if (n_found > 1) {
          if (do_construct) {
            cs_device_t rep = cs_atb_add_replicator(n_found);
            cs_atb_register(m, mp, rep, 0);
            md = rep;
          }
        }
        for (sl = slaves; sl; sl = next) {
          next = sl->next;
          unsigned int const mdp = (n_found > 1) ? slix : mp;            
          if (do_construct) {
            cs_atb_register(md, mdp, sl->slave, sl->slave_port); 
          }
          free(sl);
          ++slix;
        }
      } else {
        fprintf(stderr, "  master %" CS_PHYSFMT " port %u - no slave ports connected!\n", cs_device_address(m), mp);
      }
    } /* loop over all master ports for this master */
    if (cs_error_count() > 0) {
      fprintf(stderr, "Errors occurred in detection\n");
      goto done;
    }
  } /* loop over all masters */
  ok = 1;
done:
  /* Switch out of integration mode */
  fprintf(stderr, "Switching back to production mode...\n");
  cs_for_each_device(m) if (detecting_atb(m)) {
    cs_set_integration_mode(m, 0);
  }
  if (cs_error_count() > 0 || !ok) {
    return -1;
  }
  /* Now the topology can be used or printed */
  return 0;
}


/* end of cs_topology_detect.c */

