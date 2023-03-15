#!/usr/bin/python

"""
Helper functions to read the buffer of a trace sink (ETR/ETF/ETB).
Readout in general needs write access to the device, and affects its current state
(notably the read pointer).

---
Copyright (C) ARM Ltd. 2018-2022.  All rights reserved.

SPDX-License-Identifer: Apache 2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
---


"""

from __future__ import print_function

import sys, struct


# These numerical values are our convention, and must match sink_state_from_bits() below
ETF_DISABLING = 0   # TraceCaptEn=0, TMCReady=0: waiting for formatter empty, -> DISABLED
ETF_DISABLED  = 1   # TraceCaptEn=0, TMCready=1
ETF_ACTIVE    = 2   # TraceCaptEn=1, TMCready=0: running/stopping/draining
ETF_STOPPED   = 3   # TraceCaptEn=1, TMCReady=1


def bits(x,p,n):
    return (x >> p) & ((1<<n)-1)


def is_etr(etf):
    devtype = etf.read32(0xFCC)
    devid = etf.read32(0xFC8)
    if devtype == 0x32:
        return False    # ETF: trace link
    elif devtype == 0x21:    # x1: trace sink. x2: trace link
        return bits(devid,6,2) == 1
    assert False, "bad trace device: %s (devtype=0x%x, devid=0x%x)" % (etf, devtype, devid)


def sink_state_from_bits(TraceCaptEn, TMCReady):
    return 2*TraceCaptEn + TMCReady


def sink_state_bits(etf):
    TraceCaptEn = int(etf.test32(0x020,0x01))
    TMCReady = int(etf.test32(0x00C,0x04))
    return (TraceCaptEn, TMCReady)


def sink_state(etf):
    (TraceCaptEn, TMCReady) = sink_state_bits(etf)
    return sink_state_from_bits(TraceCaptEn, TMCReady)


def sink_show_config(etf):
    devid = etf.read32(0xFC8)
    memwidth_field = bits(devid,8,3)
    memwidth_bits = 8 << memwidth_field
    print("TMC/ETR %s:" % (etf))
    print("  devid    = 0x%08x, %u-bit memory" % (devid, memwidth_bits))
    axictl = etf.read32(0x110)
    print("  axictl   = 0x%08x" % (axictl))


def sink_show_status(etf, title=None):
    if title is not None:
        title = " (%s)" % title
    else:
        title = ""
    print("ETF %s%s:" % (etf, title))
    mode = etf.read32(0x028)
    ffcr = etf.read32(0x304)
    status = etf.read32(0x00C)
    flushstatus = etf.read32(0x300)
    control = etf.read32(0x020)
    TraceCaptEn = control & 1
    TMCReady = (status >> 2) & 1
    st = sink_state_from_bits(TraceCaptEn, TMCReady)
    etfstate = {ETF_DISABLED:"Disabled",ETF_ACTIVE:"Running/Stopping/Draining",ETF_STOPPED:"Stopped",ETF_DISABLING:"Disabling"}[st]
    print("  ETF state: TraceCaptEn=%u, TMCReady=%u: %s" % (TraceCaptEn, TMCReady, etfstate))
    print("  ETF     028  mode:   0x%08x %s" % (mode, ["CB","SWF1","?","SWF2"][mode]))
    print("  ETF 11C/118  DBA:    0x%016x" % etf.read32x2(0x11C,0x118))
    print("  ETF     004  size:   0x%08x words" % etf.read32(0x004))
    print("  ETF     020  ctl:    0x%08x" % etf.read32(0x020))
    print("  ETF     00C  status: 0x%08x" % status, end="")
    if status & 0x01:
        # Circular buffer mode: RAM write pointer has wrapped around top of buffer.
        # Software/Hardware FIFO modes, non ETR Scatter/Gather: current space in memory is <= BUFWM.
        # Software/Hardware FIFO modes, ETR Scatter/Gather: Trace memory currently full.
        print(" wrapped/full", end="")
    if status & 0x02:
        # Trace capture in progress and TMC has detected a Trigger event. Circular buffer mode only.
        print(" triggered", end="")
    if status & 0x04:
        # Trace capture has stopped, and internal pipelines and buffers have drained. AXI interface is not busy.
        print(" TMCReady", end="")
    if status & 0x08:
        # Trace capture has stopped, and internal pipelines and buffers have drained.
        print(" FtEmpty", end="")
    if status & 0x10:
        # TMC does not contain any valid trace data. This bit is valid only when TraceCaptEn=1.
        print(" Empty", end="")
    if status & 0x20:
        # AXI memory error has occurred. Formatter has stopped / is stopping.
        print(" **MemErr**", end="")
    print()
    print("  ETF     304  ffcr:   0x%08x" % ffcr, end="")
    if ffcr & 0x1:
        print(" formatting", end="")
    if ffcr & 0x1000:
        print(" stop-on-flush", end="")
    print()
    print("  ETF     300  ffstat: 0x%08x" % flushstatus, end="")
    if flushstatus & 0x01:
        print(" FlInProg", end="")
    if flushstatus & 0x02:
        print(" FtStopped", end="")    # deprecated, backwards compatibility, same as FtEmpty
    print()
    #print("  ETF     02C  latch:  0x%08x" % (etf.read32(0x02C)*4))        # LBUFLEVEL - read is side-effecting
    #if TraceCaptEn:
    #    print("  ETF     030  cfill:  0x%08x" % (etf.read32(0x030)*4))        # CBUFLEVEL
    print("  ETF 038/014  read:   0x%016x" % (etf.read32x2(0x038,0x014))) # RRP
    print("  ETF 03C/018  write:  0x%016x" % (etf.read32x2(0x03C,0x018))) # RWP
    #print("  ETF     FB4  lock:   0x%08x" % etf.read32(0xFB4))


def sink_is_stopped(etf):
    return sink_state(etf) == ETF_STOPPED


def sink_is_wrapped(etf):
    return (etf.read32(0x00C) & 1) != 0


def sink_buffer_range(etf, ignore_empty=False):
    """
    Given an ETF/ETR, return (start_offset, n_bytes)
    This is non-destructive, i.e. it does not modify any registers.
    """
    buffer_size_bytes = etf.read32(0x004) * 4     # TBD: check how much was written, if not wrapped
    if (etf.read32(0x00C) & 0x10) == 0 or ignore_empty:    # test for STS.Empty not being set
        # If the buffer has wrapped, return [wp...<wrap>...wp-1].
        # Otherwise, return [rp...wp-1].
        if is_etr(etf):
            dba = etf.read32x2(0x11C,0x118)
            rp = etf.read32x2(0x038,0x014)
            wp = etf.read32x2(0x03C,0x018)
            if not ignore_empty:
                assert wp >= dba and wp < dba+buffer_size_bytes, "ETF bad RWP: DBA=0x%x, size=0x%x, RWP=0x%x" % (dba, buffer_size_bytes, wp)
        else:
            dba = 0
            rp = etf.read32(0x014)
            wp = etf.read32(0x018)
        if sink_is_wrapped(etf):
            start = wp
            avail_bytes = buffer_size_bytes
        else:
            start = dba
            avail_bytes = wp - start
    else:
        # Buffer is empty
        start = 0
        avail_bytes = 0
    assert avail_bytes <= buffer_size_bytes, "ETF buffer size %u bytes, avail=%u" % (buffer_size_bytes, avail_bytes)
    return (start, avail_bytes)


def sink_set_read_pointer(etf, start):
    #print("Setting ETF read pointer to 0x%x" % start)
    if is_etr(etf):
        etf.write32x2(0x038,0x014,start)
    else:
        etf.write32(0x014,start)


def sink_buffer(etf, max_bytes=None, ignore_empty=False):
    """
    Read ETF/ETB contents, returning as a bytearray.
    Contents are returned starting from the current write pointer, i.e. oldest data first.
    """
    # When reading trace via RRD, the sink should be in Stopped rather than Disabled state,
    # i.e. TraceCaptEn=1, TMCReady=1. This ensures RRP wraps correctly.
    workaround_disabled_read = False
    if is_etr(etf) and not sink_is_stopped(etf):
        if False:
            print("warning: ETF is not in Stopped state", file=sys.stderr)
        workaround_disabled_read = True
    s = b""
    (start, avail_bytes) = sink_buffer_range(etf, ignore_empty=ignore_empty)
    # Get the write pointer and set the read pointer
    if False:
        sink_set_read_pointer(etf, start)
    # Deal with ETR failure to wrap RRP when in Disabled state
    if workaround_disabled_read:
        dba = etf.read32x2(0x11C,0x118)
        n_bytes = etf.read32(0x004)*4
        assert start >= dba and start < dba+n_bytes
        n_words_to_end = (dba+n_bytes - start) // 4
    if max_bytes is not None and avail_bytes > max_bytes:
        avail_bytes = max_bytes
    for i in range(0, avail_bytes//4):
        # read from RRD. After a full width of data has been read, the RRP register is incremented.
        x = etf.read32(0x010)    # destructive - increments read pointer
        #print("read 0x%x, RRP=0x%x" % (x, etf.read32x2(0x038,0x014)))
        if workaround_disabled_read:
            n_words_to_end -= 1
            if n_words_to_end == 0:
                rrp = etf.read32x2(0x038,0x014)
                assert rrp == dba + n_bytes, "expected read pointer 0x%x, got 0x%x" % (dba+n_bytes, rrp)
                etf.write32x2(0x038,0x014,dba)    # back to the start
        if x == 0xffffffff:
            # end-of-trace marker: never valid in a formatted frame (but what about unformatted?)
            # we don't expect this, since we calculated how many words to read
            print("unexpected: end-of-buffer read")
            break
        s += struct.pack("I", x)
    etf.clr32(0x020, 0x01)    # clear TraceCaptEn to disable ETF
    # Restore the read pointer
    sink_set_read_pointer(etf, start)
    return bytearray(s)


def dump_buffer(data, width=32):
    for (i, c) in enumerate(data):
        if (i % width) == 0:
            print("%5u: " % i, end="")
        print(" %02x" % c, end="")
        if ((i+1) % width) == 0 or i+1 == len(data):
            print("")


if __name__ == "__main__":
    import argparse
    import csscan
    def inthex(s):
        return int(s,16)    
    parser = argparse.ArgumentParser(description="read sink buffer")
    parser.add_argument("--sink", type=inthex, help="device address", required=True)
    parser.add_argument("--buffer", type=inthex, help="set new ETR buffer address")
    parser.add_argument("--size", type=inthex, help="ETR buffer size in bytes")
    parser.add_argument("--width", type=int, default=32, help="text output width")
    parser.add_argument("--ignore-empty", action="store_true")
    parser.add_argument("--predisable", action="store_true", help="disable sink before reading")
    parser.add_argument("--no-read", action="store_true", help="don't read contents")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    CS = csscan.CSROM()
    sink = CS.create_device_at(opts.sink, unlock=True, write=True)
    if opts.verbose:
        sink_show_config(sink)
        sink_show_status(sink, title="before any action")
    if opts.predisable:
        sink.clr32(0x020, 0x01)    # clear TraceCaptEn to disable ETF
        if sink.read32(0x020) & 1:
            print("can't disable sink", file=sys.stderr)
            sys.exit()
    if opts.buffer:
        assert is_etr(sink)
        sink.write32x2(0x11C,0x118, opts.buffer)
        sink.write32(0x004, opts.size//4)          # size in words, aligned to granule
        sink.write32x2(0x038,0x014, opts.buffer)
        sink.write32x2(0x03C,0x018, opts.buffer+opts.size, check=True)  # byte address, aligned to granule
        #sink.write32x2(0x03C,0x018, opts.buffer)
        if opts.verbose:
            sink_show_status(sink, title="after configuring buffer")
    (start, nbytes) = sink_buffer_range(sink, ignore_empty=opts.ignore_empty)
    print("Buffer start: 0x%x size: 0x%x" % (start, nbytes))
    if opts.no_read:
        sys.exit()
    data = sink_buffer(sink, max_bytes=opts.size, ignore_empty=opts.ignore_empty)
    print("Data length: %u" % len(data))
    dump_buffer(data, width=opts.width)
    if opts.verbose:
        sink_show_status(sink, title="after data readout")
