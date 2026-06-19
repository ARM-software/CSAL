#!/usr/bin/python

"""
Read trace files from CSAL's csprofile command.

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
"""
from __future__ import print_function

import sys, os, struct, re


# Match definitions in csprofile.c
TREC_CSTRACE = 1
TREC_CSMETA  = 2
TREC_MMAP    = 3
TREC_FILE    = 4
TREC_MEM     = 5


record_type_name = {}
for s in dir():
    if s.startswith("TREC_"):
        record_type_name[globals()[s]] = s        


def read_trace_records(fn):
    """
    Read the output of the csprofile utility.
    This is a record-oriented file roughly analogous to perf.data,
    containing a mix of embedded ETM buffer contents and metadata.
    """
    assert os.path.isfile(fn)
    f = open(fn, "rb")
    while True:
        lenh = f.read(20)     # record header: record length, type, header length, time, data length
        if lenh == '':
            break
        (rlen, type, hlen, time, dlen) = struct.unpack("IHHQI", lenh)
        data = f.read(rlen-20)
        if time == 0:
            time = None
        yield (time, type, data[:dlen])
    f.close()


def type_name(type):
    if type in record_type_name:
        return record_type_name[type]
    else:
        return "TREC_%u?" % type


def show_trace_records(fn):
    base_time = None
    for (time, type, data) in read_trace_records(fn):
        if base_time is None:
            base_time = time
        delta = time - base_time
        print("%-15d %11d  %-12s %7u" % (time, delta, type_name(type), len(data)))


if __name__ == "__main__":
    # Simple command-line interface for testing
    o_verbose = 0
    done = False
    for arg in sys.argv[1:]:
        if arg.startswith("-"):
            if arg == "--help":
                print("Usage: %s [options] trace.data" % sys.argv[0])
                print("   show profile data created by csprofile")
                print("  -v             increase verbosity level")
                print("  --kernel=<fn>  specify kernel ELF file")
                sys.exit()
            elif arg == "-v" or arg == "--verbose":
                o_verbose += 1 
            else:
                print("%s: wrong args: %s" % (sys.argv[0], arg))
                sys.exit(1)
        else:
            show_trace_records(arg)
            done = True
    if not done:
        show_trace_records("cstrace.bin")

