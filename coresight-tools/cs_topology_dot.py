#!/usr/bin/python

"""
Render a CoreSight topology as a 'dot' graph source.

Copyright (C) ARM Ltd. 2019.  All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from __future__ import print_function

import sys

import cs_topology


def memory_size_str(sz):
    if sz >= 1024*1024:
        return "%uM" % (sz // (1024*1024))
    elif sz >= 1024:
        return "%uK" % (sz // 1024)
    else:
        return "%u" % sz


def generate_dot(p):
    """
    Render the ATB topology as a dot/graphviz graph.
    This is exclusive of the surrounding 'digraph', so other objects can be added.
    Output is written to standard output.
    """
    seq = 0
    for d in p:
        seq += 1
        d.dotid = "D%u" % seq
        d.dotshow = False     # set when device is connected to a link
        if d.name is None:
            d.name = "%s_%u" % (d.type_str(), seq)
    for ln in p.links:
        if ln.linktype == cs_topology.CS_LINK_CTI:
            continue
        attrs = []
        if ln.master.type == cs_topology.CS_DEVTYPE_REPLICATOR and not ln.master.is_hidden:
            attrs.append("taillabel=\"%u\"" % ln.master_port)
        if ln.slave.type == cs_topology.CS_DEVTYPE_FUNNEL and not ln.slave.is_hidden:
            attrs.append("headlabel=\"%u\"" % ln.slave_port)
        print("  %s -> %s [%s];" % (ln.master.dotid, ln.slave.dotid, ', '.join(attrs)))
        ln.master.dotshow = True
        ln.slave.dotshow = True
    for d in p:
        if not d.dotshow:
            print("ignoring unconnected device: %s" % (d), file=sys.stderr)
            continue
        # The type of the device is in most cases obvious from the name it was given in the SDF file.
        if d.type == cs_topology.CS_DEVTYPE_FUNNEL:
            shape = "invtrapezium"
        elif d.type == cs_topology.CS_DEVTYPE_REPLICATOR:
            shape = "trapezium"
        else:
            shape = "box"
        if not d.is_hidden:
            name = d.name    # This generally indicates the type - e.g. it's derived from the type or a core name
            # ETF and ETB
            try:
                name += "\\n%uK" % (d.ram_size_bytes / 1024)
            except (AttributeError, TypeError):
                pass
            if d.type == cs_topology.CS_DEVTYPE_BUFFER:
                name += "\\nbuffer"
            elif d.type == cs_topology.CS_DEVTYPE_ROUTER:
                name += "\\nrouter"
            # Funnels
            try:
                name += "\\n%u ports" % (d.port_count)
            except (AttributeError, TypeError):
                pass
            # ETMs
            try:
                name += "\\n%s" % (d.version_string)
            except (AttributeError, TypeError):
                pass
            # All devices should have a part number
            try:
                name += "\\n%03X" % (d.part_number)
            except (AttributeError, TypeError):
                pass
            try:
                name += "\\n%s" % (memory_size_str(d.ram_size))
            except (AttributeError, TypeError):
                pass
            try:
                name += "\\n%s" % (d.address_str())
            except (AttributeError, TypeError):
                pass
        else:
            name = ""
        print("  %s [label=\"%s\" shape=\"%s\"];" % (d.dotid, name, shape))
        if d.type == cs_topology.CS_DEVTYPE_ROUTER:
            print("  %sAXI [label=\"AXI\" shape=\"circle\"];" % (d.dotid))
            try:
                lab = "%u bits" % d.mem_width_bits
            except AttributeError:
                lab = ""
            try:
                catu = d.catu_device_name
                print("  %sCATU [label=\"CATU:%s\"];" % (d.dotid, catu))
                print("  %s -> %sCATU [label=\"%s\"];" % (d.dotid, d.dotid, lab))
                print("  %sCATU -> %sAXI [label=\"%s\"];" % (d.dotid, d.dotid, lab))
            except AttributeError:
                print("  %s -> %sAXI [label=\"%s\"];" % (d.dotid, d.dotid, lab))
        elif d.type == cs_topology.CS_DEVTYPE_PORT:
            lab = "port"
            try:
                lab += "\\n%s bits" % d.port_sizes
            except (AttributeError, TypeError):
                pass
            print("  %sPORT [label=\"%s\"];" % (d.dotid, lab))
            print("  %s -> %sPORT;" % (d.dotid, d.dotid))
    def rank_all(x):
        printed = False
        for d in x:
            if d.dotshow:
                if not printed:
                    print("  subgraph {")
                    print("    rank=same;")
                    printed = True
                print("    %s;" % d.dotid)
        if printed:
            print("  }")
    rank_all([d for d in p if d.type == cs_topology.CS_DEVTYPE_CORE])
    rank_all([d for d in p if d.type[0] == 3])
    rank_all([d for d in p if d.type[0] == 1])


def generate_digraph(p, size="7,10", label="None"):
    """
    Generate a complete digraph to standard output.
    The caller can concatenate these to form a multipage document.
    """
    print("digraph {")
    if label is not None:
        # Add the label. Hopefully no characters that need escaping.
        print("  label=\"%s\";" % label)
    print("  size=\"%s\";" % size)
    generate_dot(p)
    print("}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="generate DOT graph")
    parser.add_argument("-i", "--input", type=str, default="topology.json", help="input JSON")
    parser.add_argument("--size", type=str, default="7,10")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    p = cs_topology.load(opts.input)
    generate_digraph(p, size=opts.size)
