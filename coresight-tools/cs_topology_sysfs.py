#!/usr/bin/python

"""
Reconstruct a CoreSight topology from /sys/bus/coresight.

This might be useful as a check that the DT/ACPI is configured right.
"""

from __future__ import print_function

from cs_topology import *

import os, sys


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


def get_cs_from_sysfs():
    p = Platform()
    cs = "/sys/bus/coresight/devices"
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
    for sd in os.listdir(cs):
        dp = os.path.realpath(os.path.join(cs, sd))
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


if __name__ == "__main__":
    p = get_cs_from_sysfs()
    p.show()
    p.check()

