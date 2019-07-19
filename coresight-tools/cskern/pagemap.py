#!/usr/bin/python

"""
Read /proc/self/pagemap to get the VA-to-PA mapping.

Since 4.2 this requires CAP_SYS_ADMIN. Users without this capability
may see the PTE as zeroes.

Note that the "PA" is the physical address as seen by the OS.
If running under virtualization it might be an IPA.
So this is not suitable (in general) for getting physical addresses
to program into MMU-less devices.

Further information about the physical page can be found in
  /proc/kpageflags
which is an array of 64-bit flags words indexed by PFN.
"""

from __future__ import print_function

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

    def __str__(self):
        s = "%03x  " % (self.raw >> 52)
        if self.is_present():
            s += "%16x" % (self.pfn * self.page_size)
        else:
            s += "-"
        if self.bit(61):
            s += " mapped/anon"
        if self.bit(56):
            s += " exclusive"
        if self.bit(55):
            s += " soft-dirty"
        return s


class PAMap:
    """
    Get the complete VA-to-PA mapping from /proc/self/pagemap.

    We use OS file operations to avoid Python's buffering.
    """
    page_size = os.sysconf("SC_PAGE_SIZE")

    def __init__(self, pid="self"):
        if pid == -1:
            pid = "self"
        self.fn = "/proc/" + str(pid) + "/pagemap"
        self.fd = os.open(self.fn, os.O_RDONLY)

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

    def pa(self, va):
        e = self.entry(va, size=self.page_size)
        if e.is_present():
            # if the PFN has been zeroed, we didn't have the right permissions
            assert e.pfn != 0, "PFN reads as zero: you don't have permissions for this operation"
            return (e.pfn * self.page_size) + (va % self.page_size)
        else:
            return None

    def __del__(self):
        os.close(self.fd)


class SystemRAMRange:
    def __init__(self, start, size):
        self.start = start
        self.size = size

    def contains(self, pa):
        return self.start <= pa and pa < (self.start + self.size)


def system_RAM_ranges():
    # Get the ranges of System RAM known to the OS
    f = open("/proc/iomem")
    for ln in f:        
        ln = ln.strip('\n')      
        if ln.endswith("System RAM"):
            addrs = ln.split()[0]
            (a0, a1) = addrs.split('-')
            astart = int(a0, 16)
            aend = int(a1, 16)
            assert aend > astart
            size = aend+1 - astart
            assert (size % os.sysconf("SC_PAGE_SIZE")) == 0
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
    for (ln, vaddr, vaend) in proc_maps("/proc/" + pidstr + "/maps"):
        printed = False
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
                    paddr = pte.pfn * m.page_size
                    sram_range = sysram.addr_index(paddr)
                else:
                    sram_range = None
                print("  %16x  %s" % (vaddr, pte), end="")
                if sram_range is not None:
                    print("  #%u: size=%uMb" % (sram_range.index, sram_range.size/(1024*1024)), end="")
                print()
                assert pte is not None
            vaddr += m.page_size
