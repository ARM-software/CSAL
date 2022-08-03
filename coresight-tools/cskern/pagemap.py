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
"""


import os, sys, struct


"""
The kernel (fs/proc/task_mmu.c) exports "page table entries" in /proc/x/pagemap.
Instead they are in a cross-architecture format and each one describes an area exactly SC_PAGE_SIZE large.
See https://www.kernel.org/doc/html/latest/admin-guide/mm/pagemap.html .

These are not the actual hardware PTEs described by e.g.
  arch/arm64/include/asm/pgtable-hwdef.h
which might describe pages of various sizes (4K, 2M etc.).
"""
_PM_PFRAME_BITS     = 55      # PFN is in the low bits. For swapped pages, other data is here.
_PM_PFRAME_MASK     = (1 << _PM_PFRAME_BITS) - 1
_PM_SOFT_DIRTY      = 55
_PM_MMAP_EXCLUSIVE  = 56
_PM_FILE            = 61
_PM_SWAP            = 62
_PM_PRESENT         = 63


"""
Further information about the physical page can be found in
  /proc/kpageflags
which is an array of 64-bit KPF_ flags words indexed by PFN.
Exported by fs/proc/page.c.
See https://www.kernel.org/doc/html/latest/admin-guide/mm/pagemap.html?highlight=kpageflags
include/uapi/linux/kernel-page-flags.h lists the publicly documented flags.
"""
_KPF_LOCKED         = 0
_KPF_REFERENCED     = 2
_KPF_UPTODATE       = 3
_KPF_DIRTY          = 4
_KPF_LRU            = 5
_KPF_ACTIVE         = 6
_KPF_MMAP           = 11
_KPF_ANON           = 12
_KPF_SWAPCACHE      = 13
_KPF_SWAPBACKED     = 14
_KPF_COMPOUND_HEAD  = 15
_KPF_COMPOUND_TAIL  = 16
_KPF_HUGE           = 17
# Following are documented in include/linux/kernel-page-flags.h
_KPF_RESERVED       = 32       # i.e. the page is reserved (PageReserved)
_KPF_MAPPEDTODISK   = 34
_KPF_PRIVATE        = 35
_KPF_OWNER_PRIVATE  = 37
_KPF_ARCH           = 38


kpf_flag = {}
for s in list(globals()):
    if s.startswith("_KPF_"):
        kpf_flag[globals()[s]] = s[5:]

def kpf_string(flags):
    sl = []
    for i in range(0,64):
        if (flags & (1<<i)) != 0:
            if i in kpf_flag:
                sl.append(kpf_flag[i])
            else:
                sl.append("flag:%u" % i)
    return ' '.join(sl)


class PTE:
    """
    Page Table Entry as managed by the kernel and accessed via /proc/x/pagemap.
    This file is exported by fs/proc/task_mmu.c.
    """
    entry_size = 8

    def __init__(self, raw, size=None, pagemap=None):
        self.raw = raw
        self.pagemap = pagemap
        if size is None:
            size = os.sysconf("SC_PAGE_SIZE")
        self.page_size = size
        if self.is_present():
            self.pfn = self.raw & _PM_PFRAME_MASK
        else:
            self.pfn = None

    def bit(self, n):
        return ((self.raw >> n) & 1) != 0

    def is_present(self):
        return self.bit(_PM_PRESENT)
    
    def is_swapped(self):
        return self.bit(_PM_SWAP)

    def is_file_mapped(self):
        return self.bit(_PM_FILE)

    def kpageflags(self):
        if self.pfn is not None:
            return self.pagemap.kpageflags_array().read(self.pfn)
        else:
            return None

    def pa(self):
        if self.is_present():
            return self.pfn * self.page_size
        else:
            return None

    def __str__(self):
        s = "flags:%03x  " % (self.raw >> 52)     # Flags
        if self.is_present():
            s += "PA:%16x" % self.pa()
        else:
            s += "-"
        if self.bit(_PM_FILE):
            s += " mapped/anon"
        if self.bit(_PM_MMAP_EXCLUSIVE):
            s += " exclusive"
        if self.bit(_PM_SOFT_DIRTY):
            s += " soft-dirty"
        return s


class PageMapping:
    """
    Mapping of one VA range to a contiguous PA range (if mapped).
    The PTE should be for the first page in the range, and other pages should have similar properties.
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


class ProcArray:
    """
    Manage a memory properties array as exported in procfs.
    This is suitable for /proc/self/pagemap, /proc/kpageflags etc.
    """
    def __init__(self, fn, entry_size=8):
        self.entry_size = entry_size
        self.fn = fn
        self.fd = None
        self.fd = os.open(self.fn, os.O_RDONLY)

    def read(self, n):
        off = n * self.entry_size
        rc = os.lseek(self.fd, off, os.SEEK_SET)
        if rc != off:
            print("** %s: failed to seek to 0x%x (rc=%d)" % (self.fn, off, rc), file=sys.stderr)
            return None
        data = os.read(self.fd, self.entry_size)
        if not data:
            print("** %s: failed to read %u bytes at 0x%x" % (self.fn, self.entry_size, off), file=sys.stderr)
            return None
        assert len(data) == self.entry_size
        if self.entry_size == 8:
            data = struct.unpack("Q", data)[0]
        elif self.entry_size == 4:
            data = struct.unpack("I", data)[0]
        else:
            assert False, "unhandled entry size %u" % self.entry_size
        return data

    def __del__(self):
        if self.fd is not None:
            os.close(self.fd)


class PAMap:
    """
    Get the complete VA-to-PA mapping from /proc/.../pagemap, for a single process.
    This allows VAs to be looked up to a PTE, and to a PA.

    We use OS file operations to avoid Python's buffering.
    """
    page_size = os.sysconf("SC_PAGE_SIZE")

    def __init__(self, pid="self"):
        if pid == -1:
            pid = "self"
        self.fn = "/proc/" + str(pid) + "/pagemap"
        self.pagemap = ProcArray(self.fn)
        self._kpageflags = None

    def round_down(self, addr):
        return addr - (addr % self.page_size)

    def entry(self, va):
        """
        Get the kernel PTE for a virtual address.
        Return None if the virtual address is unmapped.
        """
        vp = va // self.page_size
        ebs = self.pagemap.read(vp)
        if ebs is not None:
            return PTE(ebs, pagemap=self)
        else:
            return None

    def kpageflags_array(self):
        if self._kpageflags is None:
            self._kpageflags = ProcArray("/proc/kpageflags")
        return self._kpageflags

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
        Given a range of VAs (not necessarily page-aligned), find all the physical pages spanning the range.
        Return a list of PageMapping objects representing contiguous physical ranges.
        Currently we do this simplistically, extending the current range one page at a time
        when we discover the next page to be physically contiguous.
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
            (a0, a1) = toks[0].split('-')
            astart = int(a0, 16)
            aend = int(a1, 16)
            if astart == 0 and aend == 0:
                # Kernel reports range as 00000000-00000000. We're not privileged enough.
                print("error: /proc/iomem is not disclosing memory addresses. Run with increased privilege.", file=sys.stderr)
                sys.exit(1)
            assert aend > astart, "invalid system memory range: %s" % ln
            size = aend+1 - astart
            if False:
                # Although system RAM blocks would normally be well aligned, they don't have to be, so disable this check.
                assert (astart % page_size) == 0, "error: /proc/iomem entry not %u-aligned: %s" % (page_size, ln)
                assert (size % page_size) == 0, "error: /proc/iomem entry size not multiple of %u: %s" % (page_size, ln)
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
    parser.add_argument("--size", type=auto_int, default=0, help="size of memory range")
    parser.add_argument("-p", "--pid", type=int, default=-1, help="target process (default self)")
    parser.add_argument("-k", "--kernel", action="store_true", help="target kernel memory")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    opts = parser.parse_args()
    pidstr = "self"
    if opts.pid != -1:
        pidstr = str(opts.pid)
    # Show the VA and (I)PA of the current process address space
    def proc_maps(fn="/proc/self/maps"):
        f = open(fn)
        for ln in f:
            k = ln.split()
            (addr, aend) = k[0].split('-')
            yield (ln[:-1], int(addr, 16), int(aend, 16))
    def kernel_areas():
        f = open("/proc/vmallocinfo")
        for ln in f:
            k = ln.split()
            (addr, aend) = k[0].split('-')
            yield (ln[:-1], int(addr, 16), int(aend, 16))
    m = PAMap(pid=opts.pid)
    sysram = SystemRAMMap()
    # Scan the virtual memory ranges allocated to the target process.
    if opts.kernel:
        areas = kernel_areas()
    else:
        areas = proc_maps("/proc/" + pidstr + "/maps")
    for (ln, vaddr, vaend) in areas:
        printed = False
        # Scan this range in page-sized chunks. Each page may have a different mapping.
        if opts.verbose:
            print(">> %s" % ln)
        assert (vaddr % m.page_size) == 0 and (vaend % m.page_size) == 0, "not 0x%x-aligned:" % (m.page_size, ln)
        if False:
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
                if not printed:
                    print("%s:" % ln)
                    printed = True
                print("  VA=%16x" % (vaddr), end="")
                pte = m.entry(vaddr)
                if pte is None:
                    # likely a permissions error, e.g. [vsyscall]
                    print("  PTE is inaccessible")
                else:
                    if pte.pfn is not None:
                        # virtual memory is physically backed
                        paddr = pte.pfn * m.page_size
                        sram_range = sysram.addr_index(paddr)    # /proc/iomem entry containing this PA
                    else:
                        sram_range = None
                    print("  PTE=[%s]" % (pte), end="")
                    if sram_range is not None:
                        # Show the range of physical memory (from /proc/iomem) that this is taken from
                        print("  from: %s" % (sram_range), end="")
                    if pte.pfn is not None:
                        print("  PFN:%7u" % pte.pfn, end="")
                        kflags = pte.kpageflags()
                        if kflags is not None:
                            #print("  kflags=0x%x" % (kflags), end="")
                            print("  %s" % (kpf_string(kflags)), end="")
                    print()
            vaddr += m.page_size
