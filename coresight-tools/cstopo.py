#!/usr/bin/python

"""
Utility for processing CS topolgies.
"""

from __future__ import print_function


import sys


import cs_topology
import cs_topology_sdf
import cs_topology_dts
import cs_topology_dot
import cs_topology_sysfs


def load(fn):
    """
    Load a CoreSight topology description
    """
    if fn.endswith(".sdf"):
        S = cs_topology_sdf.load(fn)
    elif fn.endswith(".json"):
        S = cs_topology.load(fn)
    elif fn.endswith(".dts"):
        S = cs_topology_dts.load(fn)
    elif fn == "sysfs":
        S = cs_topology_sysfs.get_cs_from_sysfs()
    else:
        print("%s: unknown input file format" % fn, file=sys.stderr)
        sys.exit(1)
    return S


def save(S, fn):
    """
    Write out a CoreSight topology description
    """
    if fn.endswith(".sdf"):
        print("Unimplemented: can't write SDF file", file=sys.stderr)
        sys.exit(1)
    elif fn.endswith(".json"):
        print("Unimplemented: can't write JSON file", file=sys.stderr)
        sys.exit(1)
    elif fn.endswith(".dts"):
        with open(fn, "w") as f:
            cs_topology_dts.gen_dts(S, file=f)
    elif fn.endswith(".dot"):
        oo = sys.stdout
        with open(fn, "w") as f:
            sys.stdout = f
            cs_topology_dot.generate_digraph(S)     
        sys.stdout = oo
    elif fn == "-":
        S.show()
    else:
        print("%s: unknown output file format" % fn, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="CS topology converter")
    parser.add_argument("-i", "--input", type=str, required=True, help="input file")
    parser.add_argument("-o", "--output", type=str, action="append", default=[], help="output file(s)")
    parser.add_argument("--check", action="store_true", help="check topology")
    opts = parser.parse_args()
    S = load(opts.input)
    if opts.check:
        cs_topology.check_topology(S)
    for out in opts.output:
        save(S, out)
