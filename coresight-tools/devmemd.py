#!/usr/bin/python

"""
Client for devmemd, the simple daemon to handle /dev/mem
requests from a remote machine.

When run as a main program, this script provides a simple
command shell supporting read and write commands.

Copyright (C) ARM Ltd. 2021.  All rights reserved.

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

import sys, socket, struct

# devmemd request codes: see devmemd.c
REQ_NOP     = 0
REQ_READ    = 1
REQ_WRITE   = 2
REQ_CLOSE   = 3
REQ_NOISE   = 4
REQ_RESET   = 5
REQ_PAGE    = 6

# devmemd response codes: see devmemd.c
ERR_OK      = 0
ERR_MMAP    = 1
ERR_ALIGN   = 2
ERR_BADREQ  = 3
ERR_BUS     = 4


class DevmemException(Exception):
    pass


class Devmem:
    """
    The client end of a connection to devmemd.
    """
    def __init__(self, addr, port, verbosity=1):
        self.remote_addr = addr
        self.remote_port = port
        self.verbosity = verbosity
        self.seq = 0
        self.connect()

    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.verbosity >= 1:
            print("connecting to %s:%u..." % (self.remote_addr, self.remote_port))
        self.s.connect((self.remote_addr, self.remote_port))
        if self.verbosity >= 1:
            print("connected to %s:%u" % (self.remote_addr, self.remote_port))
        (status, data) = self.send_raw(REQ_NOP)
        if status != ERR_OK:
            print("could not establish command session with initial NOP")

    def send_raw(self, code, size=0, addr=0, data=0):
        self.seq += 1
        seq = self.seq
        if self.verbosity >= 2:
            print("send seq=0x%04x req=%u size=%u addr=0x%x data=0x%x" % (seq, code, size, addr, data))
        req = struct.pack("HBBB3xQQ", seq, 24, code, size, addr, data)
        assert len(req) == 24
        self.s.sendall(req)      # sendall() ensures all bytes are sent
        rsp = self.s.recv(16)
        if not rsp:
            print("remote devmemd connection closed unexpectedly", file=sys.stderr)
            raise IOError
        if len(rsp) < 16:
            print("recv only received %u bytes" % len(rsp))
        (rseq, _, status, data) = struct.unpack("HBB4xQ", rsp)
        if self.verbosity >= 2:
            print("recv seq=0x%04x status=%d data=0x%x" % (rseq, status, data))
        if status != ERR_OK:
            print("status = %d" % status)
        return (status, data)

    def send(self, code, size=0, addr=0, data=0):
        (status, data) = self.send_raw(code, size, addr, data)
        if status != ERR_OK:
            raise DevmemException
        return (status, data)
    
    def read(self, size, addr):
        """
        Read a value from physical memory.
        """
        assert size in [1,2,4,8], "bad read size: %u" % size
        (status, data) = self.send(REQ_READ, size, addr, 0)
        return data

    def write(self, size, addr, data):
        """
        Write a value to physical memory.
        """
        assert size in [1,2,4,8], "bad write size: %u" % size
        (status, _) = self.send(REQ_WRITE, size, addr, data)

    def map(self, base, size):
        """
        Return an mmap-compatible object.
        """
        return DevmemMap(self, base, size)

    def close(self):
        self.s.close()

    def __del__(self):
        self.close()


class DevmemMap:
    """
    A mmap-compatible object that redirects via Devmem.
    """
    def __init__(self, devmem, base, size):
        assert isinstance(devmem, Devmem)
        self.devmemd = devmem
        self.map_base = base
        self.map_size = size

    def __getslice__(self, start, end):
        size = end - start
        assert size in [1,2,4,8], "bad read size: 0x%x..0x%x" % (start, end)
        data = self.devmemd.read(size, self.map_base+start)
        return struct.pack(".BH.I...Q"[size], data)

    def __setslice__(self, start, end, data):
        size = end - start
        assert size in [1,2,4,8], "bad write size: 0x%x..0x%x" % (start, end)
        value = struct.unpack(".BH.I...Q"[size], data)[0]
        self.devmemd.write(size, self.map_base+start, value)


if __name__ == "__main__":
    import sys, argparse
    parser = argparse.ArgumentParser(description="test client for devmemd")
    parser.add_argument("-v", "--verbose", default=0, action="count", help="increase verbosity level")
    parser.add_argument("target", type=str, help="target internet address and port")
    opts = parser.parse_args()
    (addr, port) = opts.target.split(':')
    port = int(port)
    m = Devmem(addr, port, verbosity=opts.verbose) 
    while True:
        ln = raw_input("devmem> ")
        toks = ln.strip().split()
        print(toks)
        if (not toks) or toks[0].startswith('#'):
            continue
        req = toks[0].upper()
        if req == 'R':
            print("%x" % m.read(int(toks[1]), int(toks[2],16)))
        elif req == 'W':
            m.write(int(toks[1]), int(toks[2],16), int(toks[3],16))
        elif req == 'Q':
            break
        else:
            print("R <size> <addr>")
            print("W <size> <addr> <data>")
    m.close()

