#!/usr/bin/python

"""
Allocate physical memory

---
Copyright (C) ARM Ltd. 2022. All rights reserved.

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

Allocate some physical memory.

This is achieved by
 - using mmap() to allocate some virtual memory
 - using mlock() to pin the memory into RAM
 - finding out the physical address(es) of the memory

Note that in a VM, the 'physical' address space is that presented by the hypervisor.
"""

from __future__ import print_function

import ctypes, sys, os, mmap
_MAP_LOCKED  = 0x2000
_MAP_HUGETLB = 0x40000
_MADV_HUGEPAGE = 14

sys.path.append("./cskern")
import pagemap

libc = ctypes.CDLL(None)
libc_mmap = libc.mmap
libc_mmap.restype = ctypes.c_void_p
libc_mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_ulonglong]
libc_munmap = libc.munmap
libc_munmap.restype = ctypes.c_int
libc_munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc_mlock = libc.mlock
libc_mlock.restype = ctypes.c_int
libc_mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc_munlock = libc.munlock
libc_munlock.restype = ctypes.c_int
libc_munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc_madvise = libc.madvise
libc.madvise.restype = ctypes.c_int
libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]


HUGE_NOT      = 0    # don't try to use huge pages
HUGE_ADVISE   = 1    # advise use of THP
HUGE_ALLOC    = 2    # allocate from huge pool, else advise
HUGE_FORCE    = 3    # allocate from huge pool or fail


class PhysMem:
    """
    A contiguous block of virtual addresses which we can lock into physical memory.
    This may span multiple pages, and be discontiguous in physical memory.

    We can try allocating with MAP_HUGETLB, but this may fail if the system hasn't
    been set up with any huge pages.

    Or, we can allocate (without using MAP_LOCKED) and then use madvise to request
    transparent huge pages. But the VA range has already been allocated by that point.

    'huge' parameter can be:
      0 to not care about huge pages
      1 to request huge pages if available (using madvise() if MAP_HUGETLB doesn't work)
      2 to force huge pages, using MAP_HUGETLB
    """
    def __init__(self, size, lock=True, huge=HUGE_NOT, contiguous=False, init=None):
        self.requested_size = size         
        self.page_size = os.sysconf("SC_PAGE_SIZE")
        self.va = None
        self.is_locked = False
        self.pa_map = pagemap.PAMap()        # map of our own process
        self.pa_range_cached = None
        self.ctype_buffer_cached = None
        # Round up requested page size
        if (size % self.page_size) != 0:
            size += (self.page_size - (size % self.page_size))
        self.alloc_size = size
        flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
        if lock:
            flags |= _MAP_LOCKED
        if huge >= HUGE_ALLOC:
            flags |= _MAP_HUGETLB
        self.va = libc_mmap(0, size, mmap.PROT_WRITE|mmap.PROT_READ, flags, -1, 0)
        if (self.va & 0xfff) == 0xfff:
            if (flags & _MAP_HUGETLB) != 0:
                # Failed to allocate with MAP_HUGETLB. Either there are none in the pool or
                # they are all in use.
                if huge == HUGE_FORCE:
                    if n_sys_huge_pages() == 0:
                        print("mmap failed: no huge pages, set /proc/sys/vm/nr_hugepages", file=sys.stderr)
                    raise EnvironmentError
                # retry with THP
                flags &= ~_MAP_HUGETLB
                flags &= ~_MAP_LOCKED
                self.va = libc_mmap(0, size, mmap.PROT_WRITE|mmap.PROT_READ, flags, -1, 0)
            if (self.va & 0xfff) == 0xfff:
                print("mmap failed (errno=%u) size=0x%x flags=0x%x" % (ctypes.get_errno(), size, flags), file=sys.stderr)
                raise EnvironmentError
        if (flags & _MAP_HUGETLB) == 0:
            if huge >= HUGE_ADVISE:
                self.madvise(_MADV_HUGEPAGE)
            if lock:
                self.lock()
        if contiguous:
            assert self.is_contiguous(), "failed to allocate contiguous physical memory"
        if init is not None:
            b = self.buffer()
            for i in range(0,self.alloc_size):
                b[i] = init

    def lock(self):
        """
        Lock the allocated VA page range into physical memory. This will map any currently unmapped pages.
        """
        assert self.va is not None
        rc = libc_mlock(self.va, self.alloc_size)
        if rc != 0:
            raise OSError
        self.is_locked = True
        
    def unlock(self):
        assert self.is_locked, "block is already unlocked"
        rc = libc_munlock(self.va, self.alloc_size)
        self.is_locked = False
        self.pa_range_cached = None

    def madvise(self, option, start=None, length=None):
        if start is None:
            start = self.va
        if length is None:
            length = self.va + self.alloc_size - start
        rc = libc_madvise(start, length, _MADV_HUGEPAGE)
        if rc != 0:
            raise OSError
        return rc

    def buffer(self):
        assert self.alloc_size > 0
        if self.ctype_buffer_cached is None:
            self.ctype_buffer_cached = (ctypes.c_char * self.alloc_size).from_address(self.va)
        assert len(self.ctype_buffer_cached.raw) == self.alloc_size
        return self.ctype_buffer_cached

    def pa_range(self, refresh=False):
        """
        Return the list of physical page ranges for this memory block.
        Since this shouldn't change, should we cache it?
        """
        if self.pa_range_cached is None or refresh:
            self.pa_range_cached = self.pa_map.pa_range(self.va, self.alloc_size)
        return self.pa_range_cached

    def pa(self, refresh=False):
        pr = self.pa_range(refresh=refresh)
        if pr is None:
            return None
        elif len(pr) == 1:
            return pr[0].pa()
        else:
            return None

    def is_contiguous(self):
        """
        Return true if the block is in physically contiguous memory.
        """
        return len(self.pa_range()) == 1

    def is_in_memory(self):
        """
        Return true if the block is entirely in memory.
        """
        for r in self.pa_range():
            if not r.is_mapped():
                return False
        return True

    def close(self):
        if self.va is not None:
            if self.is_locked:
                self.unlock()
            libc_munmap(self.va, self.alloc_size)
            self.va = None
            self.pa_range_cached = None
            self.ctype_buffer_cached = None

    def __del__(self):
        self.close()

    def __str__(self):
        s = "size:0x%x" % self.alloc_size
        if self.va is not None:
            s += ",VA:0x%x" % self.va
            # Find physical address of start TBD: might not be contiguous in PA. Should find range of PAs.
            pa = self.pa_map.pa(self.va)
            if pa is not None:
                s += ",PA:0x%x" % pa
            if not self.is_contiguous():
                s += ",discontiguous"
            if not self.is_in_memory():
                s += ",unalloc"
            if self.is_locked:
                s += ",locked"            
        return "{%s}" % s


def _readn(fn):
    """
    Read a number from a file in e.g. sysfs
    """
    with open(fn) as f:
        return int(f.read().strip())


def n_sys_huge_pages():
    """
    Return the number of huge pages in the pool for MAP_HUGETLB.
    """
    return _readn("/proc/sys/vm/nr_hugepages")


def show_huge_page_config():
    print("Huge pages:")
    print("  THP: %s" % open("/sys/kernel/mm/transparent_hugepage/enabled").read().strip())
    print("  nr_hugepages: %u" % n_sys_huge_pages())
    hpc = "/sys/kernel/mm/hugepages"
    hpsizes = sorted([int(x[10:-2]) for x in os.listdir(hpc)])
    for ps in hpsizes:
        d = os.path.join(hpc, "hugepages-%ukB" % ps)
        assert os.path.isdir(d)
        pnr = _readn(os.path.join(d, "nr_hugepages")) 
        pfree = _readn(os.path.join(d, "free_hugepages"))
        print("  %9ukB %9u %9u" % (ps, pnr, pfree))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="test physical memory allocation")
    parser.add_argument("--pages", type=int, default=3, help="number of pages to allocate")
    parser.add_argument("--blocks", type=int, default=1, help="number of blocks")
    parser.add_argument("--huge", type=int, default=0, help="0: don't care, 1: if available, 2: force")
    parser.add_argument("--no-lock", action="store_true", help="don't lock block in memory")
    parser.add_argument("--set-huge", type=int, help="set OS global number of huge pages")
    parser.add_argument("--show-huge", action="store_true", help="show OS global huge page configuration")
    opts = parser.parse_args()
    if opts.show_huge:
        show_huge_page_config()
    if opts.set_huge is not None:
        with open("/proc/sys/vm/nr_hugepages", "w") as f:
            f.write("%u" % opts.set_huge)
        with open("/proc/sys/vm/nr_hugepages") as f:
            print("Huge pages set to %s" % f.read().strip())
        sys.exit()
    blocks = []
    size = opts.pages * os.sysconf("SC_PAGE_SIZE")
    for i in range(0, opts.blocks):
        b = PhysMem(size, huge=opts.huge, lock=(not opts.no_lock))
        print(b)
        for m in b.pa_range():
            print("  %s" % m)
        buf = b.buffer()
        buf[3] = b'x'
        blocks.append(b)
    for b in blocks:
        buf = b.buffer()
        assert buf[3] == b'x'
        if b.is_locked:
            b.unlock()
