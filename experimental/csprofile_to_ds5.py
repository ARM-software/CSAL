#!/usr/bin/python

"""
Generate a DS-5 snapshot from csprofile output

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

from csprofile_read import *

import os, sys


def copy_file(ffn, tfn):
    ff = open(ffn, "rb")
    ft = open(tfn, "wb")
    ft.write(ff.read())
    ft.close()
    ff.close()


def gen_ds5_snapshot(fn, snapdir):
    if not os.path.isfile(fn):
        print >>sys.stderr, "Path %s not found, expecting csprofile output" % fn
    if not os.path.isdir(snapdir):
        if os.path.isfile(snapdir):
            print >>sys.stderr, "Path %s already exists but is file, must be directory" % snapdir
            sys.exit()
        os.mkdir(snapdir)
        assert os.path.isdir(snapdir)
    srcs = []
    dumps = []
    n_buffers = 0
    for (time, type, data) in read_trace_records(fn):
        # print (type, len(data))
        if type == TREC_CSMETA:
            n = len(srcs)
            fd = open(snapdir + os.sep + "device_%u.ini" % n, "w")
            #etm_type = "ETM4"           
            #print >>fd, "[device]\nname=ETM_%u\nclass=trace_source\ntype=%s\n" % (n, etm_type)
            #print >>fd, "[regs]"
            if data[-1] == '\0':
                data = data[:-1]
            print >>fd, data
            fd.close()
            assert data.startswith("[device]\nname=")
            dlines = data.split("\n")
            src = dlines[1][5:]
            srcs.append(src)
            # print data
        elif type == TREC_CSTRACE:
            # Contents of a CoreSight trace buffer. Ignore short buffers which are likely to be content-free.
            if len(data) >= 48:
                n_buffers += 1
                if n_buffers == 1:
                    fb = open(snapdir + os.sep + "trace.bin", "wb")
                    fb.write(data)
                    fb.close()
        elif type == TREC_MEM:
            (addr,) = struct.unpack("Q", data[:8])
            dump_file = "dump%u.bin" % len(dumps)
            fd = open(snapdir + os.sep + dump_file, "wb")
            fd.write(data[8:])
            dumps.append((addr, len(data[8:]), dump_file))
        elif type == TREC_FILE:
            (addr, size) = struct.unpack("QI", data[:12])
            name = data[12:-1]
            dump_file = "dump%u.bin" % len(dumps)
            copy_file(name, snapdir + os.sep + dump_file)
            dumps.append((addr, size, dump_file))
        elif type == TREC_MMAP:
            (addr, size, offset) = struct.unpack("QII", data[:16])
            name = data[16:-1]
            # TBD ignore ELF files - in future we could extract the mapped area as a
            # binary blob and put it in the snapshot
            pass
    f = open(snapdir + os.sep + "snapshot.ini", "w")
    print >>f, "[snapshot]\nversion=1.0\n\n[device_list]"
    i = 0
    for src in srcs:
        print >>f, "device%u=cpu_%u.ini" % (i, i)
        fd = open(snapdir + os.sep + "cpu_%u.ini" % i, "w")
        print >>fd, "[device]\nname=cpu_%u\nclass=core\ntype=unknown" % i
        print >>fd
        print >>fd, "[regs]"
        print >>fd
        dn = 0
        for (daddr, dlen, dfile) in dumps:
            print >>fd, "[dump%u]" % dn
            print >>fd, "file=%s\naddress=0x%x\nlength=0x%x\n" % (dfile, daddr, dlen)
            dn += 1
        fd.close()
        i += 1
    for src in srcs:
        print >>f, "device%u=device_%u.ini" % (i, i-len(srcs))
        i += 1
    print >>f, "\n[trace]\nmetadata=trace.ini"    
    f.close()
    f = open(snapdir + os.sep + "trace.ini", "w")
    print >>f, "[trace_buffers]\nbuffers=buffer0\n"
    print >>f, "[buffer0]\nname=ETB_0\nfile=trace.bin\nformat=coresight\n"
    print >>f, "[source_buffers]"
    for src in srcs:
        print >>f, "%s=ETB_0" % (src)
    print >>f
    print >>f, "[core_trace_sources]"
    for i in range(0, len(srcs)):
        print >>f, "cpu_%u=%s" % (i, srcs[i])
    f.close()


gen_ds5_snapshot("cstrace.bin", "snapshot")


