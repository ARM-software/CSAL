/*
CoreSight topology printing 

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
This module generates text to describe the CoreSight topology, in various formats:

  - C source, comprising a sequence of calls to the CSAL API

  - a fragment for Linux device tree source

  - a 'dot' graph suitable for visualizing the topology

These serve slightly different purposes.  The C API calls and DTS are primarily
to allow software to discover the existence and connectivity of devices, on the
assumption it can find out other device properties by reading ID registers.
The 'dot' graph (and other visualizations) on the other hand, present user-friendly
views of the CoreSight system and should probably include useful information from
the id registers.
*/

#include "cs_topology_print.h"

#include "csaccess.h"
#include "csregisters.h"
#include "cs_reg_access.h"

#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


static char const *cs_device_type_name(cs_device_t d)
{
   cs_devtype_t type = cs_device_get_type(d);
   switch (type) {
   case DEV_FUNNEL: return "funnel";
   case DEV_REPLICATOR: return "replicator";
   case DEV_ETM:    return "etm";
   case DEV_ITM:    return "itm";
   case DEV_STM:    return "stm";
   case DEV_TS:     return "timestamp";
   case DEV_ETB:    return "etb";
   case DEV_ETF:    return "etf";
   case DEV_TPIU:   return "tpiu";
   case DEV_CTI:    return "cti";
   case DEV_CPU_PMU:   return "cpu_pmu";
   case DEV_CPU_DEBUG: return "cpu_debug";
   case DEV_ELA:    return "ela";
   }
   return "csdev";
}


static int cs_device_is_non_mmio(cs_device_t d) { return cs_device_address(d) == 1; }


/*
Get a suitable base address for the collection of CoreSight devices -
we can then address them as offsets from the base.
*/
static cs_physaddr_t device_base(void)
{
    cs_device_t d;
    cs_physaddr_t base = (cs_physaddr_t)(-1);
    /* Find the lowest base address */
    cs_for_each_device(d) {
        if (cs_device_address(d) < base) {
            base = cs_device_address(d);
        }
    }
    base &= ~0xffffff;     /* round down to a suitable boundary */
    return base;
}


static void fprint_device_name(FILE *fd, cs_device_t d, cs_physaddr_t base)
{
    fprintf(fd, "%s_", cs_device_type_name(d));
    if (!cs_device_is_non_mmio(d)) {
        fprintf(fd, "%" CS_PHYSFMT, cs_device_address(d) - base);
    } else {
        fprintf(fd, "%p", d);
    }
}


/*
Print CoreSight topology as a sequence of calls to the CSAL C API
*/
static int cs_print_topology_stdc(FILE *fd)
{
    cs_physaddr_t const base = device_base();
    cs_device_t d;

    fprintf(fd, "    cs_physaddr_t base = 0x%" CS_PHYSFMT ";\n", base);
    fprintf(fd, "    /* Set base addresses for CoreSight devices */\n");
    cs_for_each_device(d) {
        fprintf(fd, "    cs_device_t const ");
        fprint_device_name(fd, d, base);
        fprintf(fd, " = ");
        if (!cs_device_is_non_mmio(d)) {
            cs_physaddr_t offset = cs_device_address(d) - base;
            fprintf(fd, "cs_device_register(base + 0x%" CS_PHYSFMT ");\n", offset);
        } else {
            assert(cs_num_out_ports(d) > 1);
            fprintf(fd, "cs_atb_add_replicator(%u);\n", cs_num_out_ports(d));
        }
        if (cs_device_get_affinity(d) >= 0) {
            fprintf(fd, "    cs_device_set_affinity(");
            fprint_device_name(fd, d, base);
            fprintf(fd, ", %u);\n", cs_device_get_affinity(d));
        }
    }
    fprintf(fd, "    /* Define trace bus (ATB) connections */\n");
    cs_for_each_device(d) {
        unsigned int op;
        for (op = 0; op < cs_num_out_ports(d); ++op) {
            cs_device_t s = cs_get_device_at_outport(d, op);
            if (!s) {
                fprintf(fd, "    /* ");
                fprint_device_name(fd, d, base);
                fprintf(fd, " output port %u is not connected */\n", op);
                continue;
            }
            fprintf(fd, "    cs_atb_register(");
            fprint_device_name(fd, d, base);
            fprintf(fd, ", %u, ", op);
            fprint_device_name(fd, s, base);
            fprintf(fd, ", %u);\n", cs_get_dest_inport(d, op));
        }
    }
    /* TBD: CPU affinity */
    /* TBD: cross-trigger */
    return 0;
}


/*
Print CoreSight topology as the input to a dot/graphviz graph
*/
static int cs_print_topology_dot(FILE *fd)
{
    cs_physaddr_t const base = device_base();
    cs_device_t d;

    fprintf(fd, "digraph {\n");
    fprintf(fd, "  size=\"7.5,10\";\n");
    fprintf(fd, "  node [shape=box];\n\n");
    cs_for_each_device(d) {
        fprintf(fd, "  ");
        fprint_device_name(fd, d, base);
        fprintf(fd, " [label=\"%s", cs_device_type_name(d));
        if (cs_device_get_type(d) == DEV_ETM) {
            int ver = cs_etm_get_version(d);
            fprintf(fd, " ");
            switch (CS_ETMVERSION_MAJOR(ver)) {
            case CS_ETMVERSION_ETMv3:
                fprintf(fd, "ETMv3");
                break;
            case CS_ETMVERSION_PTM:
                fprintf(fd, "PFTv1");
                break;
            case CS_ETMVERSION_ETMv4:
                fprintf(fd, "ETMv4");
                break;
            default:
                fprintf(fd, "ETM?");
            }
            fprintf(fd, ".%u", CS_ETMVERSION_MINOR(ver));
        }
        if (cs_device_has_class(d, CS_DEVCLASS_BUFFER)) {
            fprintf(fd, " %uK", cs_get_buffer_size_bytes(d) / 1024);
        }
        if (!cs_device_is_non_mmio(d)) {
            fprintf(fd, "\\n%#lx", (unsigned long)cs_device_address(d));
        }
        if (cs_device_get_affinity(d) >= 0) {
            fprintf(fd, "\\nCPU %u", cs_device_get_affinity(d));
        }
        fprintf(fd, "\"]\n");
    }
    /* Print CPU subgraphs */
    fprintf(fd, "\n");
    /* We group all devices associated with a CPU (debug, ETM, PMU, CTI).
       TBD: We don't currently create subgraphs for CPU clusters along with
       their cluster devices (cluster CTI, cluster funnel) but we'd expect
       they end up as neighbours in the graph because of connectivity. */
    /* To avoid horizontal spread we use invisible links to try and
       force devices to stack vertically within a cluster. */
    {
        /* There ought to be a better way to iterate through the CPUs and their affine devices */
        unsigned int i;
        for (i = 0; i < 32; ++i) {
            int printed = 0;
            cs_device_t d_etm = 0;
            cs_device_t d_pmu = 0;
            cs_device_t d_cti = 0;
            cs_device_t d_debug = 0;
            cs_for_each_device(d) {
                if (cs_device_get_affinity(d) == i) {
                    switch (cs_device_get_type(d)) {
                    case DEV_ETM:
                        d_etm = d;
                        break;
                    case DEV_CTI:
                        d_cti = d;
                        break;
                    case DEV_CPU_DEBUG:
                        d_debug = d;
                        break;
                    case DEV_CPU_PMU:
                        d_pmu = d;
                        break;
                    }
                    if (!printed) {
                        fprintf(fd, "  subgraph \"cluster_cpu%u\" {\n", i);
                        fprintf(fd, "    label=\"CPU %u\";\n", i);
                        printed = 1;
                    }
                    fprintf(fd, "    ");
                    fprint_device_name(fd, d, base);
                    fprintf(fd, ";\n");
                }
            }
            if (d_pmu && d_etm) {
                fprintf(fd, "    ");
                fprint_device_name(fd, d_pmu, base);
                fprintf(fd, " -> ");
                fprint_device_name(fd, d_etm, base);
                fprintf(fd, " [style=\"invis\"];\n");
            }
            if (d_debug && d_cti) {
                fprintf(fd, "    ");
                fprint_device_name(fd, d_debug, base);
                fprintf(fd, " -> ");
                fprint_device_name(fd, d_cti, base);
                fprintf(fd, " [style=\"invis\"];\n");
            }
            if (d_cti && d_pmu) {
                fprintf(fd, "    ");
                fprint_device_name(fd, d_cti, base);
                fprintf(fd, " -> ");
                fprint_device_name(fd, d_pmu, base);
                fprintf(fd, " [style=\"invis\"];\n");
            }
            if (printed) {
                fprintf(fd, "  }\n");
            }
        }
    }
    /* Print ATB topology */
    fprintf(fd, "\n");
    cs_for_each_device(d) {
        unsigned int op;
        for (op = 0; op < cs_num_out_ports(d); ++op) {
            cs_device_t s = cs_get_device_at_outport(d, op);
            if (!s) {               
                continue;
            }
            fprintf(fd, "  ");
            fprint_device_name(fd, d, base);
            fprintf(fd, " -> ");
            fprint_device_name(fd, s, base);
            fprintf(fd, " [label=\"%u->%u\"]", op, cs_get_dest_inport(d, op));
            fprintf(fd, "\n");
        }
    }
    fprintf(fd, "}\n");
    /* TBD: cross-trigger topology */
    return 0;
}


static int cs_device_in_linux_device_tree(cs_device_t d)
{
    switch (cs_device_get_type(d)) {
    case DEV_FUNNEL:
    case DEV_REPLICATOR:
    case DEV_ETM:
    case DEV_ETB:
    case DEV_ETF:
    case DEV_TPIU:
        return 1;
    default:
        return 0;
    }
}


static char const *plural(unsigned int n)
{
    assert(n >= 1);
    return (n > 1) ? "s" : "";
}


static char const *dts_device_type_name(cs_device_t d)
{
    /* TBD fix for "ptm" */
    return cs_device_type_name(d);
}


/*
Generate the sequence number for a device, in its category - or -1 if it's the only one.
We don't cache this - we assume that printing a device tree isn't something we
do often and that quadratic (or worse) scaling is acceptable.
*/
static int dts_device_seq(cs_device_t thisd)
{
    cs_device_t d;
    unsigned int seq = 0;
    int this_seq = -1;
    char this_name[40];
    strcpy(this_name, dts_device_type_name(thisd));
    cs_for_each_device(d) {
        if (d == thisd) {
            this_seq = seq;
            ++seq;
        } else if (!strcmp(dts_device_type_name(d), this_name)) {
            ++seq;
        }
    }
    if (seq == 1) {
        this_seq = -1;    /* there was only one of this kind */
    }
    return this_seq;
}


/*
Generate a unique identifier for a CoreSight device in the device tree.
This is the device class, plus a sequence number if there are multiple devices
of the same class.  So in a system with one funnel, it would be called "funnel",
while in a system with two funnels, they would be "funnel0" and "funnel1".
*/
static char const *dts_device_id(cs_device_t d)
{
    static char buf[40];
    int seq = dts_device_seq(d);
    strcpy(buf, cs_device_type_name(d));
    if (seq != -1) {
        sprintf(buf + strlen(buf), "%d", seq);
    }
    return buf;
}


/*
Generate the port identifier for an input or output port on a device.
This is the device identifier and a port indicator - as for devices,
it's appended with a sequence number only if there are multiple ports.
*/
static char const *dts_port_id(cs_device_t d, int isout, unsigned int n)
{
    static char buf[50];
    sprintf(buf, "%s_%s_port", dts_device_id(d), (isout ? "out" : "in"));
    if ((isout ? cs_num_out_ports(d) : cs_num_in_ports(d)) > 1) {
        sprintf(buf + strlen(buf), "%u", n);
    }
    return buf;
}


static cs_device_t cs_other_device(cs_device_t d, int isout, unsigned int n)
{
    cs_device_t od;
    od = isout ? cs_get_device_at_outport(d, n) : cs_get_device_at_inport(d, n);
    return od;
}


static void dts_print_port(FILE *fd, char const *tabs, cs_device_t d, int isout, unsigned int n)
{
    cs_device_t const other_device = cs_other_device(d, isout, n);
    unsigned int const other_port = isout ? cs_get_dest_inport(d, n) : cs_get_src_outport(d, n);

    fprintf(fd, "%s%s: endpoint {\n", tabs, dts_port_id(d, isout, n));
    if (!isout) {
        fprintf(fd, "%s\tslave-mode;\n", tabs);
    }    
    fprintf(fd, "%s\tremote-endpoint = <&%s>;\n", tabs, dts_port_id(other_device, !isout, other_port));          
    fprintf(fd, "%s};\n", tabs);
}


/*
Print CoreSight topology as a Linux device tree source fragment
*/
static int cs_print_topology_dts(FILE *fd)
{
    cs_device_t d;

    fprintf(fd, "/*\n * Device Tree source fragment\n */\n\n");
    fprintf(fd, "/* auto-generated by CSAL topogen utility */\n");

    /* For cross-references to CPUs in the DTS - some DTS might use uppercase "CPU" instead */
    char const *const dts_cpu_id_name = "cpu";

    cs_for_each_device(d) {
        char compat[20];
        char devname[20];     /* device type name - PTM is "ptm" not "etm */
        if (!cs_device_in_linux_device_tree(d)) {
            continue;
        }

        fprintf(fd, "\n");
        fprintf(fd, "\t");
        strcpy(devname, dts_device_type_name(d));
        fprintf(fd, "%s", devname);
        if (!cs_device_is_non_mmio(d)) {
            fprintf(fd, "@0,%08lx", (unsigned long)cs_device_address(d));
        }
        fprintf(fd, " {\n");
        
        /* "compatibility" */
        if (cs_device_is_non_mmio(d)) {
            fprintf(fd, "\t\t/* non-configurable %ss don't show up on the\n\t\t * AMBA bus.  As such no need to add \"arm,primecell\".\n\t\t */\n",
                devname);
        }
        sprintf(compat, "%s", dts_device_type_name(d));
        if (cs_device_get_type(d) == DEV_ETM) {
          if (cs_etm_get_version(d) == CS_ETMVERSION_ETMv4) {
            strcpy(compat, "etm4x");
          } else if (cs_etm_get_version(d) == CS_ETMVERSION_PTM) {
            strcpy(compat, "ptm");
          }
        }
        fprintf(fd, "\t\tcompatible = \"arm,coresight-%s\"", compat);
        if (!cs_device_is_non_mmio(d)) {
            fprintf(fd, ", \"arm,primecell\"");
        }
        fprintf(fd, ";\n");

        /* "reg" */
        if (!cs_device_is_non_mmio(d)) {
            /* "reg" specification must allow for 32-bit and 40/64-bit addressing */
            cs_physaddr_t addr = cs_device_address(d);
            if (sizeof(addr) > 4) {    /* TBD is this the right way to check? */
                /* large */
                fprintf(fd, "\t\treg = <%#x %#x 0 0x1000>;\n", (unsigned int)(addr >> 32), (unsigned int)addr);           
            } else {
                fprintf(fd, "\t\treg = <%#x 0x1000>;\n", (unsigned int)addr);
            }
        }

        /* traditional blank line */
        fprintf(fd, "\n");
        
        /* "cpu" */
        if (cs_device_get_affinity(d) >= 0) {
            fprintf(fd, "\t\tcpu = <&%s%u>;\n", dts_cpu_id_name, cs_device_get_affinity(d));
        }

        /* "clocks" would go here, but CSAL doesn't know about it */
        fprintf(fd, "\t\t/* \"clocks\" and \"clock-names\" can be specified here */\n\n");

        /* "ports" */
        {
            unsigned int const inp = cs_num_in_ports(d);
            unsigned int const outp = cs_num_out_ports(d);
            int const multiport = (inp + outp) > 1;
            fprintf(fd, "\t\tport%s {\n", plural(inp+outp));
            if (!multiport) {
                dts_print_port(fd, "\t\t\t", d, (outp > 0), 0);
            } else {
                unsigned int i;
                unsigned int pn = 0;
                fprintf(fd, "\t\t\t#address-cells = <1>;\n");
                fprintf(fd, "\t\t\t#size-cells = <0>;\n");
                for (i = 0; i < outp; ++i) {
                    cs_device_t od = cs_other_device(d, 1, i);
                    if (!od || !cs_device_in_linux_device_tree(od)) continue;
                    fprintf(fd, "\n");
                    if (i == 0) {
                        fprintf(fd, "\t\t\t/* %s output port%s */\n", devname, plural(outp));
                    }
                    fprintf(fd, "\t\t\tport@%u {\n", pn);
                    fprintf(fd, "\t\t\t\treg = <%u>;\n", i);
                    dts_print_port(fd, "\t\t\t\t", d, /*isout=*/1, i);
                    fprintf(fd, "\t\t\t};\n");
                    ++pn;
                }
                for (i = 0; i < inp; ++i) {
                    cs_device_t od = cs_other_device(d, 0, i);
                    if (!od || !cs_device_in_linux_device_tree(od)) continue;
                    fprintf(fd, "\n");
                    if (i == 0) {
                        fprintf(fd, "\t\t\t/* %s input port%s */\n", devname, plural(inp));
                    }
                    fprintf(fd, "\t\t\tport@%u {\n", pn);
                    fprintf(fd, "\t\t\t\treg = <%u>;\n", i);
                    dts_print_port(fd, "\t\t\t\t", d, /*isout=*/0, i);
                    fprintf(fd, "\t\t\t};\n");
                    ++pn;
                }
            }            
            fprintf(fd, "\t\t};\n");
        }
    
        fprintf(fd, "\t};\n");
    }
    /* TBD: cross-trigger, when supported by Linux device tree */
    return 0;
}


int cs_print_topology(FILE *fd, cs_topology_format_t fmt)
{
    switch (fmt) {
    case CS_TOP_STDC:
        return cs_print_topology_stdc(fd);
    case CS_TOP_DOT:
        return cs_print_topology_dot(fd);
    case CS_TOP_DTS:
        return cs_print_topology_dts(fd);
    default:
        return -1;
    }
    return 0;
}  
