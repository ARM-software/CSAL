#!/usr/bin/python

"""
Decode trace files from CSAL's csprofile command.

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

import sys, os, struct, re
import ConfigParser as CP
import StringIO

from csprofile_read import *

sys.path.append(os.path.dirname(os.path.realpath(__file__)) + os.sep + "csdecode")

import cs_decode
import cs_decode_etm
import cs_viewer_ds5
import imagemap


g_map = imagemap.imagemap()

def read_trace(fn, verbose=0, decode=True, viewer=None, limit=None):
    cs_decode_etm.default_map = g_map
    cs_decode_etm.default_verbose = verbose
    decoder_cfg = {}
    if viewer is None:
        viewer = cs_viewer_ds5.ds5view(columns="*")
    tbase = None
    n_buffers = 0
    for (time, type, data) in read_trace_records(fn):
        if tbase is None:
            # use the first timestamp as baseline
            tbase = time
        if time is not None:
            tdelt = time - tbase
        else:
            tdelt = None
        if verbose:
            if tdelt is None:
                tds = "<no time>"
            else:
                tds = "+%d" % tdelt
            print >>sys.stderr, "%s: %s: record type %u len %u" % (fn, tds, type, len(data))
        if type == TREC_CSMETA:
            # coresight trace metadata
            if data[-1] == '\0':
                data = data[:-1]
            f = StringIO.StringIO(data)
            ini = CP.ConfigParser()
            ini.readfp(f, fn)
            f.close()
            regs = {}
            # convert "trcidr1(0x123)" to "TRCIDR1"
            for (k, value) in ini.items("regs"):
                nk = k.upper()
                ix = nk.find('(')
                if ix >= 0:
                    nk = nk[:ix]
                regs[nk] = int(value, 16) 
            cfg = cs_decode_etm.etm_config(regs)
            if verbose:
                print >>sys.stderr, "%s: got trace configuration for trace id %u" % (fn, cfg.traceid)
                if verbose >= 2:
                    for k in regs:
                        print >>sys.stderr, "  %-20s 0x%08x" % (k, regs[k])
            decoder_cfg[cfg.traceid] = cfg
        elif type == TREC_CSTRACE:
            # coresight trace
            n_buffers += 1
            if verbose:
                print >>sys.stderr, "%s: ETM trace buffer, size %u" % (fn, len(data))
                if verbose >= 2:
                    # Show the current memory-map for decoding this trace buffer
                    g_map.show()
            if decode:
                # For each trace buffer, we need to create a fresh set of decoders,
                # as they need to start with a clean starting state (and the first
                # byte they expect to be sent will be 'None').
                decoders = {}
                for traceid in decoder_cfg:
                    cfg = decoder_cfg[traceid]
                    assert traceid == cfg.traceid
                    decoders[traceid] = cs_decode_etm.decode_etm(cfg, traceid, viewer=viewer)
                cs_decode.buffer_decode(data, decoders, fn=fn, verbose=(verbose >= 2))
            if limit is not None and n_buffers >= limit:
                print "%s: hit limit of %u buffers" % (fn, limit)
                break
        elif type == TREC_MMAP:
            # memory mapping from file - usually an ELF executable or shared object, although it could be /etc/ld.so.cache
            # this record generally derives from a perf mmap event
            (addr, size, offset) = struct.unpack("QII", data[:16])
            name = data[16:-1]
            if verbose:
                print >>sys.stderr, "%s: mapped file \"%s\" at 0x%x-0x%x, offset 0x%x" % (fn, name, addr, addr+size, offset)
            if name[0] == '[':
                # Possibly "[vdso]" or similar pseudo file.  TBD: should these even appear as a TREC_MMAP record?
                # we expect to tget a TREC_MEM record with the actual data.
                pass
            else:
                g_map.add_file(name, addr, size=size, offset=offset)
        elif type == TREC_FILE:
            # memory mapping from file - raw binary
            (addr, size) = struct.unpack("QI", data[:12])
            name = data[12:-1]
            if verbose:
                print >>sys.stderr, "%s: mapped raw binary file \"%s\" at 0x%x" % (fn, name, addr)
            g_map.add_bin(name, addr)
        elif type == TREC_MEM:
            # memory mapping - inline data
            (addr,) = struct.unpack("Q", data[:8])
            if verbose:
                print >>sys.stderr, "%s: mapped raw data (0x%x bytes) at 0x%x" % (fn, len(data[8:]), addr)
            g_map.add_segment(data[8:], addr)
        elif type < 100:
            print >>sys.stderr, "%s: ignoring unknown record type %u" % (fn, type)
        else:
            print >>sys.stderr, "%s: trace container looks corrupt" % (fn)
            break
    if verbose:
        print "%s: processing complete." % (fn)


if __name__ == "__main__":
    # Simple command-line interface for testing
    o_verbose = 0
    o_decode = True
    done = False
    for arg in sys.argv[1:]:
        if arg.startswith("-"):
            if arg == "--help":
                print "Usage: %s [options] trace.data" % sys.argv[0]
                print "   decode profile data created by csprofile"
                print "  -v             increase verbosity level"
                print "  --decode       decode the CoreSight trace data"
                print "  --kernel=<fn>  specify kernel ELF file"
                sys.exit()
            elif arg == "-v" or arg == "--verbose":
                o_verbose += 1 
            elif arg == "--decode":
                o_decode = True
            elif arg == "--nodecode":
                o_decode = False
            elif arg.startswith("--kernel="):
                g_map.add_elf(arg[9:])
            else:
                print "%s: wrong args: %s" % (sys.argv[0], arg)
                sys.exit(1)
        else:
            read_trace(arg, decode=o_decode, verbose=o_verbose)
            done = True
    if not done:
        read_trace("cstrace.bin", decode=o_decode, verbose=o_verbose)

