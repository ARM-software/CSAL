#!/usr/bin/python

"""
Render a CoreSight topology as a 'dot' graph source.
"""

from __future__ import print_function

import cs_topology


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
        d.dotshow = False
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
            continue
        if d.name is None:
            d.name = "d_%u" % seq
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
            except:
                pass
            if d.type == cs_topology.CS_DEVTYPE_BUFFER:
                name += "\\nbuffer"
            elif d.type == cs_topology.CS_DEVTYPE_ROUTER:
                name += "\\nrouter"
            # Funnels
            try:
                name += "\\n%u ports" % (d.port_count)
            except:
                pass
            # ETMs
            try:
                name += "\\n%s" % (d.version_string)
            except:
                pass
            # All devices should have a part number
            try:
                name += "\\n%03X" % (d.part_number)
            except:
                pass
        else:
            name = ""
        print("  %s [label=\"%s\" shape=\"%s\"];" % (d.dotid, name, shape))
        if d.type == cs_topology.CS_DEVTYPE_ROUTER:
            print("  %sAXI [label=\"AXI\" shape=\"circle\"];" % (d.dotid))
            try:
                lab = "%u bits" % d.mem_width_bits
            except:
                lab = ""
            print("  %s -> %sAXI [label=\"%s\"];" % (d.dotid, d.dotid, lab))
        elif d.type == cs_topology.CS_DEVTYPE_PORT:
            lab = "port"
            try:
                lab += "\\n%s bits" % d.port_sizes
            except:
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


def generate_digraph(p, size="8,11", label="None"):
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

