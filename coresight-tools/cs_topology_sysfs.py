#!/usr/bin/python

"""
Reconstruct a CoreSight topology from /sys/bus/coresight or /proc/device-tree.

This might be useful as a check that the DT/ACPI is configured right.
"""

from __future__ import print_function

from cs_topology import *

import os, sys, struct


# Device type names as used in /sys/bus/coresight/devices
devtypes = {
    "tpiu":       CS_DEVTYPE_PORT,
    "etb":        CS_DEVTYPE_BUFFER,
    "tmc_etr":    CS_DEVTYPE_ROUTER,
    "funnel":     CS_DEVTYPE_FUNNEL,
    "replicator": CS_DEVTYPE_REPLICATOR,
    "etf":        CS_DEVTYPE_FIFO,
    "tmc_etf":    CS_DEVTYPE_FIFO,
    "etm":        CS_DEVTYPE_TRACE_CORE,
    "stm":        CS_DEVTYPE_TRACE_SW,
}


def read_file(fn):
    f = open(fn)
    s = f.read().strip()
    f.close()
    return s


def read_binary_file(fn):
    f = open(fn, "rb")
    s = f.read()
    f.close()
    return s


def get_cs_from_sysfs(p=None):
    cs = "/sys/bus/coresight/devices"
    if not os.path.isdir(cs):
        return p
    if p is None:
        p = Platform()
    path_to_d = {}
    for sd in os.listdir(cs):
        dp = os.path.join(cs, sd)
        base = sd
        while base[-1].isdigit():
            base = base[:-1]
        devtype = devtypes[base]
        d = Device(p, devtype, name=sd)
        try:
            cn = int(read_file(os.path.join(dp, "cpu")))
            d.set_cpu_number(cn)
        except:
            pass
        try:
            d.ram_size_bytes = int(read_file(os.path.join(dp, "buffer_size")), 16)
        except:
            pass
        rp = os.path.realpath(dp)
        path_to_d[rp] = d
        of_node = os.path.join(os.path.dirname(rp), "of_node")
        if os.path.exists(of_node):
            d.of_node = os.path.realpath(of_node)      # /sys/firmware/devicetree
    # Populate the ATB links from the 'out:' and 'in:' entries if available
    for sd in os.listdir(cs):
        dp = os.path.realpath(os.path.join(cs, sd))    # somewhere in /sys/devices/platform
        d = path_to_d[dp]
        # Scan the device's outputs.
        for opn in range(0, 2):
            outp = os.path.join(dp, "out:%u" % opn)
            if os.path.islink(outp):
                tp = os.path.realpath(outp)
                # scan the target's inputs to find the source
                ln = None
                for ipn in range(0, 8):
                    inp = os.path.join(tp, "in:%u" % ipn)
                    sp = os.path.realpath(inp)
                    if sp == dp:
                        ln = Link(d, path_to_d[tp], CS_LINK_ATB, master_port=opn, slave_port=ipn)
                        break
                if ln is None:
                    print("** failed to find link for %s -> %s" % (outp, tp), file=sys.stderr)
    return p



def device_tree_node_compatibility(dtn):
    compat = read_file(os.path.join(dtn, "compatible")).split(",")
    cl = []
    for s in compat:
        ix = s.find('\x00')
        if ix > 0:
            s = s[:ix]
        cl.append(s)
    return cl


def device_tree_node_handle(dtn, handle_name="phandle"):
    dhp = os.path.join(dtn, handle_name)
    if os.path.isfile(dhp):
        s = device_tree_node_reg(dtn, reg_name=handle_name)
    else:
        s = None
    return s


def reg_value(r):
    v = None
    if len(r) == 4:
        v = struct.unpack(">I", r)[0]
    elif len(r) == 8:
        v = struct.unpack(">Q", r)[0]
    return v


def device_tree_node_reg(dtn, reg_name="reg"):
    drp = os.path.join(dtn, reg_name)
    return reg_value(read_binary_file(drp))


def device_tree_node_property_length(dtn, prop):
    prop = "#" + prop + "-cells"
    assert dtn.startswith("/proc/device-tree/")
    while len(dtn) > 18 and not os.path.isfile(os.path.join(dtn, prop)):
        dtn = os.path.dirname(dtn)
    assert dtn != "/proc/device-tree"
    alen = device_tree_node_reg(dtn, reg_name=prop)
    alen = alen * 4    # it's counted in words
    return alen


def device_tree_node_address_length(dtn):
    alen = device_tree_node_property_length(dtn, "address")
    if alen is not None:
        assert alen in [0,4,8,16], "unexpected address length: %u" % alen
    return alen


def device_tree_node_address(dtn):
    rfn = os.path.join(dtn, "reg")
    if not os.path.isfile(rfn):
        return None
    alen = device_tree_node_address_length(dtn)
    if alen == 0:
        # this node does not have an address - the 'reg' value is something else
        return None
    return reg_value(read_binary_file(rfn)[:alen])


def device_tree_node_size_length(dtn):
    return device_tree_node_property_length(dtn, "size")


def device_tree_nodes():
    """
    Iterate through nodes in /proc/device-tree
    """
    for root, dirs, files in os.walk("/proc/device-tree"):
        for d in dirs:
            dp = os.path.join(root, d)
            dc = os.path.join(dp, "compatible")
            if os.path.isfile(dc):
                compat = device_tree_node_compatibility(dp)
                phandle = device_tree_node_handle(dp)
                yield (dp, phandle, compat)


def compat_is_coresight(dcompat):
    """
    Check if a device tree node claims compatibility with CoreSight.
    We don't check for "arm" here because an architecture-licensee core might be
    ETM-compatible but not be an Arm device.
    We also expect to see "primecell".
    """
    for dc in dcompat:
        if dc.startswith("coresight-"):
            return dc[10:]
    return None


cs_device_tree_types = {
    "etm3x":               CS_DEVTYPE_TRACE_CORE,
    "etm4x":               CS_DEVTYPE_TRACE_CORE,
    "stm":                 CS_DEVTYPE_TRACE_SW,
    "funnel":              CS_DEVTYPE_FUNNEL,   # obsolete
    "dynamic-funnel":      CS_DEVTYPE_FUNNEL,
    "dynamic-replicator":  CS_DEVTYPE_REPLICATOR,
    "tpiu":                CS_DEVTYPE_PORT,
    "etb10":               CS_DEVTYPE_BUFFER,
    "tmc":                 CS_DEVTYPE_BUFFER,
}


def get_cs_from_device_tree(p=None):
    dtd = "/proc/device-tree"
    if not os.path.isdir(dtd):
        return p
    if p is None:
        p = Platform()
    phandle_node = {}
    node_device = {}
    for d in p:
        try:
            node_device[d.of_node] = d
        except:
            pass
    for (dp, phandle, dcompat) in device_tree_nodes():
        phandle_node[phandle] = dp
        cs = compat_is_coresight(dcompat)
        if cs is not None:
            if cs not in cs_device_tree_types:
                print("** %s: unknown device tree node compatibility: %s" % (dp, dcompat), file=sys.stderr)
                continue
            devtype = cs_device_tree_types[cs]
            phys_addr = device_tree_node_address(dp)
            try:
                name = os.path.basename(dp)
                phys_addr_name = int(name[name.index('@')+1:], 16)
            except:
                phys_addr_name = 0xCDCDCDCD
            assert phys_addr == phys_addr_name, "%s: unexpected address mismatch: %s vs %s" % (dp, phys_addr, phys_addr_name)
            # "tmc" might be a buffer, router or fifo
            if cs == "tmc":
                if os.path.isdir(os.path.join(dp, "out-ports")):
                    devtype = CS_DEVTYPE_FIFO
                elif os.path.isfile(os.path.join(dp, "arm,scatter-gather")):
                    # not all ETR nodes have this, but if it does, it's definitely ETR
                    devtype = CS_DEVTYPE_ROUTER
            drp = os.path.realpath(dp)
            if drp in node_device:
                d = node_device[drp]
            else:
                d = Device(p, devtype, name=os.path.basename(dp), mem_address=phys_addr)
            if cs == "etm4x":
                d.etm_architecture = 4
            elif cs == "stm":
                r = read_binary_file(os.path.join(dp, "reg"))
                alen = device_tree_node_address_length(dp)
                slen = device_tree_node_size_length(dp)
                d.stimulus_base_address = reg_value(r[alen+slen:alen+slen+alen])
                d.stimulus_size         = reg_value(r[alen+slen+alen:])
            node_device[dp] = d
            if False:
                print("addr=%u size=%u %s" % (device_tree_node_address_length(dp), device_tree_node_property_length(dp, "size"), dp))
                os.system("ls %s" % dp)
                os.system("od -t x4 %s/reg" % dp)
    # Now construct links and affinities
    # Prepare to resolve CPU numbers.
    # CPU DT nodes don't directly have the CPU number (the 'reg' value is not generally the CPU number).
    # But there's a link from /sys/devices/system/cpu back to the device tree nodes.
    syscpus = "/sys/devices/system/cpu"
    phandle_cpu_num = {}
    for cd in os.listdir(syscpus):
        if cd.startswith("cpu"):
            try:
                cpu_num = int(cd[3:])
            except:
                continue
            cpu_dir = os.path.join(syscpus, cd)
            of_node = os.path.join(cpu_dir, "of_node")
            if os.path.isdir(of_node):
                phandle = device_tree_node_handle(of_node)
                assert phandle is not None, "%s: expect of_node to point to CPU node in DT" % of_node
                phandle_cpu_num[phandle] = cpu_num
    # Build the phandle-to-inport mapping
    phandle_inport = {}
    for (dp, phandle, dcompat) in device_tree_nodes():
        if compat_is_coresight(dcompat) is not None:
            ips = os.path.join(dp, "in-ports")
            if os.path.isdir(ips):
                for inp in os.listdir(ips):
                    idir = os.path.join(ips, inp)
                    if not os.path.isdir(idir):
                        continue
                    endpoint = os.path.join(idir, "endpoint")
                    iphandle = device_tree_node_handle(endpoint)
                    if os.path.isfile(os.path.join(idir, "reg")):
                        iportnum = device_tree_node_reg(idir)
                    else:
                        iportnum = 0
                    assert iphandle not in phandle_inport, "duplicate handle: %s vs. %s" % (idir, phandle_inport[iphandle])
                    #print("%s -> %s, %s" % (iphandle, dp, iportnum))
                    phandle_inport[iphandle] = (dp, iportnum)
    for (dp, phandle, dcompat) in device_tree_nodes():
        if compat_is_coresight(dcompat) is not None:
            cpup = os.path.join(dp, "cpu")
            cphandle = device_tree_node_handle(dp, handle_name="cpu")
            if cphandle is not None:
                if cphandle in phandle_cpu_num:
                    cpu_num = phandle_cpu_num[cphandle]
                else:
                    cpu_num = device_tree_node_reg(phandle_node[cphandle])
                node_device[dp].set_cpu_number(cpu_num)
            ops = os.path.join(dp, "out-ports")
            if os.path.isdir(ops):
                # each output port (usually only one) is a directory
                for od in os.listdir(ops):
                    odir = os.path.join(ops, od)
                    if not os.path.isdir(odir):
                        continue
                    if os.path.isfile(os.path.join(odir, "reg")):
                        oportnum = device_tree_node_reg(odir)
                    else:
                        oportnum = 0
                    endpoint = os.path.join(odir, "endpoint")
                    rphandle = device_tree_node_handle(endpoint, handle_name="remote-endpoint")
                    assert rphandle in phandle_inport, "%s: remote endpoint handle %s not found" % (odir, rphandle)
                    (sd, sportnum) = phandle_inport[rphandle]
                    #print("Connecting %s.%u -> %u.%s" % (dp, oportnum, sportnum, sd))
                    ln = Link(node_device[dp], node_device[sd], CS_LINK_ATB, master_port=oportnum, slave_port=sportnum)
    return p


if __name__ == "__main__":
    p = get_cs_from_sysfs()
    if p is None or not p.links:
        p = get_cs_from_device_tree(p)
    if p is not None:
        p.show()
        p.check()
