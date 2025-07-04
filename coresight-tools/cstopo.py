#!/usr/bin/python

"""
Utility for processing CS topologies.

Reads and writes topology descriptions in various forms.
"""

from __future__ import print_function


import sys
import os


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
    def process(fn):
        S = load(fn)
        if S is None:
            print("%s: skipping as empty" % fn, file=sys.stderr)
        else:
            print("%s" % S)
            if opts.check:
                res = S.check_topology()
                if res:
                    print("%s: topology issues detected" % fn, file=sys.stderr)
        return S
    if os.path.isdir(opts.input):
        # Scan directory tree looking for SDF files, and summarize/check as needed.
        if opts.output:
            print("Can't use output when scanning directory", file=sys.stderr)
            sys.exit(1)
        for root, dirs, files in os.walk(opts.input):
            for fn in files:
                if fn.endswith(".sdf"):
                    fn = os.path.join(root, fn)
                    process(fn)
    else:
        S = process(opts.input)
        if S is not None:
            for out in opts.output:
                save(S, out)
