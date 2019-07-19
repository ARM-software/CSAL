#!/usr/bin/python

"""
Reimplementation of the standard Python mmap module with better control over access width,
to support memory-mapped I/O.
"""

from __future__ import print_function

import os, ctypes, struct, subprocess

import mmap as real_mmap
for x in real_mmap.__dict__:
    if x.startswith("PROT_") or x.startswith("MAP_"):
        globals()[x] = real_mmap.__dict__[x]
assert PROT_READ == real_mmap.PROT_READ
del real_mmap


def get_syscall_numbers(fns):
    """
    Get a selection of integers for syscalls, by using the C preprocessor.
    This relies on the system headers defining the numbers as macros.
    """
    p = subprocess.Popen(["cc", "-E", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    p.stdin.write("#include <sys/syscall.h>\n".encode())
    for fn in fns:
        p.stdin.write(("SYS_%s\n" % fn).encode())
    p.stdin.close()
    lns = list(p.stdout)
    ns = [int(x) for x in lns[-len(fns):]]
    return ns


[SYS_mmap, SYS_munmap] = get_syscall_numbers(["mmap", "munmap"])

libc = ctypes.CDLL(None)
syscall = libc.syscall


class mmap:
    def __init__(self, fno, size, flags=MAP_SHARED, prot=(PROT_WRITE|PROT_READ), offset=0):
        syscall.restype = ctypes.c_void_p
        syscall.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_ulonglong]
        assert size > 0
        assert (size % os.sysconf("SC_PAGE_SIZE")) == 0
        assert offset >= 0
        self.size = size
        self.addr = syscall(SYS_mmap, 0, size, prot, flags, fno, offset)
        if (self.addr & 0xfff) == 0xfff:
            raise EnvironmentError

    def close(self):
        syscall.restype = ctypes.c_int
        syscall.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        syscall(SYS_munmap, self.addr, self.size)

    def seek(self, pos):
        self.pos = pos

    def read(self, nbytes):
        return self.__getslice__(self.pos, self.pos+nbytes)

    def __getitem__(self, item):
        # Python3 forwarder
        if isinstance(item, slice):
            assert item.step is None or item.step == 1
            return self.__getslice__(item.start, item.stop)
        else:
            raise TypeError("non-slice indexing not supported")

    def __getslice__(self, start, end):
        nbytes = end - start
        if nbytes == 1:
            x = ctypes.c_ubyte.from_address(self.addr + start)
            x = struct.pack("B", x.value)
        elif nbytes == 4:
            x = ctypes.c_uint.from_address(self.addr + start)
            x = struct.pack("I", x.value)
        elif nbytes == 8:
            x = ctypes.c_ulonglong.from_address(self.addr + start)
            x = struct.pack("Q", x.value)
        else:
            x = None
        return x

    def __setitem__(self, item, value):
        if isinstance(item, slice):
            assert item.step is None or item.step == 1
            self.__setslice__(item.start, item.stop, value)
        else:
            raise TypeError("non-slice indexing not supported")

    def __setslice__(self, start, end, value):
        nbytes = end - start
        if nbytes == 1:
            x = ctypes.c_ubyte.from_address(self.addr + start)
            n = struct.unpack("B", value)[0]
        if nbytes == 4:
            x = ctypes.c_uint.from_address(self.addr + start)
            n = struct.unpack("I", value)[0]
        elif nbytes == 8:
            x = ctypes.c_ulonglong.from_address(self.addr + start)
            n = struct.unpack("Q", value)[0]
        else:
            assert False
        x.value = n


if __name__ == "__main__":
    print("SYS_mmap = %u" % SYS_mmap)
    print("SYS_munmap = %u" % SYS_munmap)
    f = open(__file__, "rb")
    m = mmap(f.fileno(), os.sysconf("SC_PAGE_SIZE"), MAP_SHARED, PROT_READ, 0)
    s = m[4:8]
    assert s == "sr/b".encode(), "unexpected string: '%s'" % s
    m.close()
    f.close()
    print("Test ok.")
