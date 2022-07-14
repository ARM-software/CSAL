#!/usr/bin/python

"""
Read /proc/self/pagemap to get the VA-to-PA mapping.

Since 4.2 this requires CAP_SYS_ADMIN. Users without this capability
may see the PTE as zeroes.

Note that if we're in a VM, we might only be seeing intermediate addresses.
Memory might not be physically backed at all, or PAs may change at any time.

Copyright (C) ARM Ltd. 2019.  All rights reserved.

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

"""
Note that the "PA" is the physical address as seen by the OS.
If running under virtualization it might be an IPA.
So this is not suitable (in general) for getting physical addresses
to program into MMU-less devices.

Further information about the physical page can be found in
  /proc/kpageflags
which is an array of 64-bit flags words indexed by PFN.
"""


import os, sys, struct


class PTE:
    """
    Page Table Entry as managed by the kernel
    """
    entry_size = 8

    def __init__(self, bytes, size=None):
        assert len(bytes) == 8, "PTE must be 8 bytes"
        self.raw = struct.unpack("L", bytes)[0]
        if size is None:
            size = os.sysconf("SC_PAGE_SIZE")
        self.page_size = size
        if self.is_present():
            self.pfn = self.raw & 0x3fffffffffffff
        else:
            self.pfn = None

    def bit(self, n):
        return ((self.raw >> n) & 1) != 0

    def is_present(self):
        return self.bit(63)
    
    def is_swapped(self):
        return self.bit(62)

    def is_file_mapped(self):
        return self.bit(61)

    def pa(self):
        if self.is_present():
            return self.pfn * self.page_size
        else:
            return None

    def __str__(self):
        s = "%03x  " % (self.raw >> 52)
        if self.is_present():
            s += "PA:%16x" % self.pa()
        else:
            s += "-"
        if self.bit(61):
            s += " mapped/anon"
        if self.bit(56):
            s += " exclusive"
        if self.bit(55):
            s += " soft-dirty"
        return s


class PageMapping:
    """
    Mapping of one VA range to a PA range (if mapped).
    """
    def __init__(self, va=None):
        self.n_pages = 1
        self.va = va
        self.pte = None
        self.size = None

    def is_mapped(self):
        return self.pte.is_present()

    def pa(self):
        if self.is_mapped():
            return self.pte.pa()
        else:
            return None

    def end_pa(self):
        pa = self.pa()
        if pa is not None:
            return pa + self.size
        else:
            return None

    def __str__(self):
        s = "VA:0x%x -> " % (self.va)
        if self.is_mapped():
            s += "PA:0x%x" % self.pa()
        else:
            s += "<unmapped>"
        if self.n_pages > 1:
            s += " (%u)" % self.n_pages
        return s


class PAMap:
    """
    Get the complete VA-to-PA mapping from /proc/self/pagemap.
    This allows VAs to be looked up to a PTE, and to a PA.

    We use OS file operations to avoid Python's buffering.
    """
    page_size = os.sysconf("SC_PAGE_SIZE")

    def __init__(self, pid="self"):
        if pid == -1:
            pid = "self"
        self.fn = "/proc/" + str(pid) + "/pagemap"
        self.fd = os.open(self.fn, os.O_RDONLY)

    def round_down(self, addr):
        return addr - (addr % self.page_size)

    def entry(self, va):
        """
        Get the kernel PTE for a virtual address.
        Return None if the virtual address is unmapped.
        """
        vp = va / self.page_size
        off = vp * PTE.entry_size
        rc = os.lseek(self.fd, off, os.SEEK_SET)
        if rc < 0:
            print("** %s: failed to seek to 0x%x" % (self.fn, off), file=sys.stderr)
            return None
        ebs = os.read(self.fd, PTE.entry_size)
        if not ebs:
            print("** %s: failed to read %u bytes at 0x%x" % (self.fn, PTE.entry_size, off), file=sys.stderr)
            return None
        assert len(ebs) == PTE.entry_size
        return PTE(ebs)

    def mapping(self, va):
        """
        Get a PageMapping object for a given virtual address
        """
        va = self.round_down(va)
        m = PageMapping(va=va)
        m.size = self.page_size
        m.pte = self.entry(va)
        return m

    def pa(self, va):
        """
        Translate a VA to a PA.
        """
        e = self.entry(va)
        if e.is_present():
            # if the PFN has been zeroed, we didn't have the right permissions
            assert e.pfn != 0, "PFN reads as zero: you don't have permissions for this operation"
            return (e.pfn * self.page_size) + (va % self.page_size)
        else:
            return None

    def pa_range(self, va, size):
        """
        Given a range of VAs, find all the physical pages spanning the range.
        Return a list of PageMapping objects.
        Currently we do this simplistically.
        """
        size += (va % self.page_size)
        if (size % self.page_size) != 0:
            size += (self.page_size - (size % self.page_size))
        n_pages = size // self.page_size
        va = self.round_down(va)
        maps = []
        for v in range(va, va+size, self.page_size):
            m = self.mapping(v)
            if m.is_mapped() and len(maps) >= 1 and m.pa() == maps[-1].end_pa():
                maps[-1].n_pages += 1
                maps[-1].size += self.page_size
            elif not m.is_mapped() and len(maps) >= 1 and not maps[-1].is_mapped():
                maps[-1].n_pages += 1
                maps[-1].size += self.page_size
            else:
                maps.append(m)
        return maps

    def __del__(self):
        os.close(self.fd)


class SystemRAMRange:
    """
    A range of physical addresses known to the system and described in /proc/iomem.
    """
    def __init__(self, start, size):
        self.start = start    # Start PA
        self.size = size      # Size in bytes
        self.index = -1

    def contains(self, pa):
        return self.start <= pa and pa < (self.start + self.size)

    def __str__(self):
        return "#%d PA:0x%x (%uMb)" % (self.index, self.start, self.size/(1024*1024))


def system_RAM_ranges():
    """
    Get the physical ranges of System RAM known to the OS, by reading /proc/iomem.
    """
    page_size = os.sysconf("SC_PAGE_SIZE")
    assert page_size != 0, "cannot determine system page size"
    f = open("/proc/iomem")
    for ln in f:        
        ln = ln.strip('\n')      
        if ln.endswith("System RAM"):
            toks = ln.split(None, 2)
            print(toks)
            (a0, a1) = toks[0].split('-')
            astart = int(a0, 16)
            aend = int(a1, 16)
            if astart == 0 and aend == 0:
                # Kernel reports range as 00000000-00000000. We're not privileged enough.
                print("error: /proc/iomem is not disclosing memory addresses. Run with increased privilege.", file=sys.stderr)
                sys.exit(1)
            assert aend > astart, "invalid system memory range: %s" % ln
            size = aend+1 - astart
            assert (astart % page_size) == 0, "error: /proc/iomem entry not %u-aligned" % (page_size, ln)
            assert (size % page_size) == 0
            yield SystemRAMRange(astart, size)
    f.close()


class SystemRAMMap:
    """
    List of System RAM ranges (as described by /proc/iomem), so we can find
    out which range a given PFN is in.
    """
    def __init__(self):
        self.ranges = list(system_RAM_ranges())
        for (i, r) in enumerate(self.ranges):
            r.index = i
        
    def addr_index(self, pa):
        """
        Given a PA, find the /proc/iomem range containing this PA.
        """
        for r in self.ranges:
            if r.contains(pa):
                return r
        return None


def show_system_RAM():
    print("Physical memory ranges")
    for (astart, size) in system_RAM_ranges():
        aend = astart + size - 1
        print("{:16x} - {:16x} {:17,d} {:11x}".format(astart, aend, size, size))


if __name__ == "__main__":
    def auto_int(x):
        # support 0x... hex numbers
        return int(x, 0)
    import argparse
    parser = argparse.ArgumentParser(description="Page map explorer")
    parser.add_argument("address", nargs='?', type=auto_int, default=0, help="base address of memory range")
    parser.add_argument("-p", type=int, default=-1, help="target process (default self)")
    parser.add_argument("--size", type=auto_int, default=0, help="size of memory range")
    opts = parser.parse_args()
    pidstr = "self"
    if opts.p != -1:
        pidstr = str(opts.p)
    # Show the VA and (I)PA of the current process address space
    def proc_maps(fn="/proc/self/maps"):
        f = open(fn)
        for ln in f:
            k = ln.split()
            (addr, aend) = k[0].split('-')
            yield (ln[:-1], int(addr, 16), int(aend, 16))
    m = PAMap(pid=opts.p)
    sysram = SystemRAMMap()
    # Scan the virtual memory ranges allocated to the target process.
    for (ln, vaddr, vaend) in proc_maps("/proc/" + pidstr + "/maps"):
        printed = False
        # Scan this range in page-sized chunks. Each page may have a different mapping.
        assert (vaddr % m.page_size) == 0 and (vaend % m.page_size) == 0, "not 0x%x-aligned:" % (m.page_size, ln)
        if True:
            maps = m.pa_range(vaddr, vaend-vaddr)
            for m in maps:
                print("  %s" % m)
            sys.exit()
        while vaddr < vaend:
            if (vaddr + m.page_size) <= opts.address:
                # this entry is before the range we're interested in
                pass
            elif opts.address != 0 and vaddr > (opts.address + opts.size):
                # this entry is after the range we're interested in
                pass
            else:
                pte = m.entry(vaddr)
                if not printed:
                    print("%s:" % ln)
                    printed = True
                if pte.pfn is not None:
                    # virtual memory is physically backed
                    paddr = pte.pfn * m.page_size
                    sram_range = sysram.addr_index(paddr)    # /proc/iomem entry containing this PA
                else:
                    sram_range = None
                print("  PA=%16x  PTE=%s" % (vaddr, pte), end="")
                if sram_range is not None:
                    print("  from: %s" % (sram_range), end="")
                print()
                assert pte is not None
            vaddr += m.page_size
