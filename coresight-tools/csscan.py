#!/usr/bin/python

"""
Scan the ROM table and report on CoreSight devices.
Also do ATB and CTI topology detection.

---
Copyright (C) ARM Ltd. 2018-2021.  All rights reserved.

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

We report three levels of status:
  - the "hard wired" configuration selected at SoC design time
  - the "programming" configuration, e.g. address comparator settings
  - the actual status, e.g. busy/ready bits, values of counters etc.

To do:
  - ETMv3.x/PTF
  - power requestors
"""

from __future__ import print_function

import os, sys, struct, time, json

# We provide our own implementation of the mmap module which gives us
# more control over access to volatile registers.
import iommap as mmap

# We support accessing a remote device via our simple 'devmemd' daemon
import devmemd


o_max_devices = 9999999
o_top_only = False
o_verbose = 0
o_show_programming = False
o_show_all_status = False
o_show_integration = False
o_show_authstatus = False
o_show_sample = False        # Destructive sampling
o_exclusions = []

g_devmem = None              # Physical memory provider


def bit(x, pos):
    return (x >> pos) & 1


def bits(x, pos, n):
    return (x >> pos) & ((1<<n)-1)


# JEDEC codes: lower 7 bits are the main code, higher bits are the
# continuation code. So Arm is 4 continuation codes followed by 0x3b.
JEDEC_ARM = 0x23b

jedec_designers = {
    JEDEC_ARM:"Arm"
}


# Device architectures defined by Arm (i.e. vaild when Arm is the architect)
# Sources:
#   IHI0029E CoreSight Architecture Specification 3.0, Table B2-8
#   other product information
#
# The CoreSight architecture defines:
#   DEVARCH[15:0]   ARCHID
#   DEVARCH[19:16]  REVISION
#
# Conventionally Arm uses:
#   DEVARCH[11:0]   ARCHPART  architecture
#   DEVARCH[15:12]  ARCHREV   major-rev
#   DEVARCH[19:16]  REVISION  minor-rev

ARM_ARCHID_ETM      = 0x4a13
ARM_ARCHID_CTI      = 0x1a14
ARM_ARCHID_PMU      = 0x2a16
ARM_ARCHID_MEMAP    = 0x0a17
ARM_ARCHID_STM      = 0x0a63
ARM_ARCHID_ELA      = 0x0a75
ARM_ARCHID_ROM      = 0x0af7

#
# Architecture identifiers indicate the programming interface which a device conforms to.
# Multiple parts may have the same architecture identifier.
#
arm_archids = {
    0x0a00:"RAS",
    0x1a01:"ITM",
    0x1a02:"DWT",
    0x2a04:"v8-M",
    0x6a05:"v8-R",
    0x0a11:"ETR",
    0x4a13:"ETMv4",      # REVISION indicates the ETMv4 minor version
    0x1a14:"CTI",
    0x6a15:"v8.0-A",
    0x7a15:"v8.1-A",
    0x8a15:"v8.2-A",
    0x2a16:"PMUv3",
    0x0a17:"MEM-AP",
    0x0a34:"pwr-rq",     # not 0x0a37 as stated in Issue E
    0x0a41:"CATU",
    0x0a50:"HSSTP",
    0x0a63:"STM",
    0x0a75:"ELA",
    0x0af7:"ROM"
}

# match [11:0] if the major-rev doesn't match (Arm-defined architecture only)
arm_archparts = {
    0xa13:"cpu-trace",
    0xa15:"v8A-debug",
    0xa16:"PMU"
}


# Source: CoreSight Architecture Specification 3.0 Table B2-9
cs_majors = {1:"sink", 2:"link", 3:"source", 4:"control", 5:"logic", 6:"PMU"}
cs_types = {(1,1):"port", (1,2):"buffer", (1,3):"router",
            (2,1):"funnel", (2,2):"replicator", (2,3):"fifo",
            (3,1):"ETM", (3,4):"HTM", (3,6):"STM",
            (4,1):"CTI", (4,2):"auth", (4,3):"power",
            (5,1):"core-debug", (5,7):"ELA",
            (6,1):"PMU (core)", (6,5):"PMU (SMMU)"}


#
# Read the 3-digit hex part numbers from part-numbers.json.
# Where DEVARCH is not set, the part numbers can be used to find the
# programmer's model for the part.
#
# For older CPUs, there will be separate CPU-specific part numbers for
# the CPU's separate interfaces: debug, ETM, PMU, CTI, ELA etc.
#
# More recent CPUs have the same part number for all these,
# relying on the combination of that common part number,
# DEVTYPE and DEVARCH to indicate the programming model.
#
arm_part_numbers = {}
with open(os.path.join(os.path.dirname(__file__), "part-numbers.json")) as f:
    pj = json.load(f)
    for p in pj["parts"]:
        pn = int(p["part"],16)
        assert pn not in arm_part_numbers, "duplicate part number: 0x%03x" % part_no
        arm_part_numbers[pn] = p["name"]


def binstr(n,w=None):
    if w is None:
        return "{0:b}".format(n)
    else:
        return ("{0:0%ub}" % w).format(n)


def bits_set(w,m):
    s = []
    for k in sorted(m.keys()):
        if bit(w,k):
            s.append(m[k])
    if s:
        return ' '.join(s)
    else:
        return "-"

assert bits_set(0x011,{0:"x",2:"y",4:"z"}) == "x z"


def decode_one_hot(x,n):
    bs = []
    for i in range(n):
        if bit(x,i):
            bs.append(i)
    if len(bs) == 1:
        return str(bs[0])
    else:
        return "?%s" % str(bs)


class DeviceTimeout(Exception):
    def __init__(self, dev, off, mask):
        self.device = dev
        self.off = off
        self.mask = mask

    def __str__(self):
        s = "device %s reg 0x%03x did not set 0x%08x" % (self.device, self.off, self.mask)
        return s


class DevicePhy:
    """
    Access a memory-mapped device
    """
    def __init__(self, devmem, base_address, write=False):
        self.devmem = devmem
        self.memap = None
        self.mmap_offset = base_address % devmem.page_size
        mmap_address = base_address - self.mmap_offset
        self.m = None         # avoid cleanup errors if exception in next line
        self.m = devmem.map(mmap_address, write=write)

    def __del__(self):
        if self.m is not None:
            self.devmem.unmap(self.m)

    def read32(self, off):
        off += self.mmap_offset
        raw = self.m[off:off+4]
        x = struct.unpack("I", raw)[0]
        return x

    def write32(self, off, value):
        s = struct.pack("I", value)
        off += self.mmap_offset
        self.m[off:off+4] = s

    def write64(self, off, value):
        s = struct.pack("Q", value)
        off += self.mmap_offset
        self.m[off:off+8] = s


class MemAP:
    """
    MEM-AP device, with some optimization e.g. use of Direct Access registers
    and local cacheing of the current value of TAR.

    For more details of MEM-AP operation, see
    "Arm Debug Interface (ADI) Architecture Specification".
    """
    def __init__(self, memap):
        assert isinstance(memap, Device)
        assert memap.is_arm_architecture(ARM_ARCHID_MEMAP), "%s: expected MEM-AP" % memap
        self.memap = memap
        self.n_client_reads = 0
        self.n_client_writes = 0
        self.memap.claim()       # Claim for self-hosted use
        self.current_TAR = None
        # Using direct/banked access register banks minimizes address writes.
        self.CFG = self.memap.read32(0xDF4)
        self.use_DAR = (bits(self.CFG,4,4) == 0xA)
        self.use_BDR = True    # only in effect if not using DAR

    def __str__(self):
        return "MEM-AP(%s)" % self.memap

    def align(self, addr):
        """
        Align an address to the granule suitable for the transfer register(s).
        """
        if self.use_DAR:
            return addr & ~0x3ff
        elif self.use_BDR:
            return addr & ~0xf
        else:
            return addr

    def set_TAR(self, addr):
        """
        Prepare to transfer to/from an address. Set the TAR if necessary
        and return the offset of a data transfer register (DAR, BDR or DRR).
        """
        eaddr = self.align(addr)
        if self.current_TAR is None or eaddr != self.current_TAR:
            self.memap.write32(0xD04, eaddr)  # write Transfer Address Register
            self.current_TAR = eaddr
        if self.use_DAR:
            return 0x000 + (addr - eaddr)   # Direct Access Register 0..255
        elif self.use_BDR:
            return 0xD10 + (addr - eaddr)   # Banked Data Register 0..3
        else:
            return 0xD0C           # Data Read/Write Register

    def read32(self, addr):
        self.n_client_reads += 1
        return self.memap.read32(self.set_TAR(addr))

    def write32(self, addr, data):
        self.n_client_writes += 1
        self.memap.write32(self.set_TAR(addr), data)


class DeviceViaMemAP:
    """
    Device accessed via a MEM-AP. This is not the MEM-AP device itself.
    """
    def __init__(self, memap, base_address, write=False):
        assert isinstance(memap, MemAP)
        self.memap = memap
        self.offset = base_address      # Device base offset within MEM-AP's target space

    def read32(self, off):
        return self.memap.read32(off + self.offset)

    def write32(self, off, data):
        self.memap.write32(off + self.offset, data)


class Device:
    """
    A single CoreSight device mapped by a ROM table (including ROM tables themselves).    
    """

    def __init__(self, cs, addr, write=False, unlock=False, checking=False):
        """
        Construct a device object at the given address.
        'cs' is the device map (e.g. virtual memory via CSROM(), or a MEM-AP) through which we access the device.
        """
        if unlock:
            write = True
        self.we_unlocked = False
        self.we_claimed = 0
        self.n_reads = 0
        self.n_writes = 0
        self.phy = None
        self.cs = cs                 # Device address space
        assert (addr & 0xfff) == 0, "Device must be located on 4K boundary: 0x%x" % addr
        self.base_address = addr     # Device base address within its address space
        self.affine_core = None      # Link to the Device object for the core debug block
        self.affinity_group = None   # AffinityGroup containing related devices
        self.map_is_write = write
        self.map(write=write)
        # For convenience, CIDR is formed from CIDR3..CIDR0.
        self.CIDR = self.idbytes([0xFFC, 0xFF8, 0xFF4, 0xFF0])
        self.PIDR = self.idbytes([0xFD0, 0xFEC, 0xFE8, 0xFE4, 0xFE0])
        self.jedec_designer = (((self.PIDR>>32)&15) << 7) | ((self.PIDR >> 12) & 0x3f)
        # The part number is selected by the component designer.
        self.part_number = self.PIDR & 0xfff
        self.devtype = None
        self.devarch = None
        self.is_checking = checking or (o_verbose >= 1)
        if self.is_coresight():            
            arch = self.read32(0xFBC)     # DEVARCH
            if (arch & 0x00100000) != 0:
                self.devarch = arch
            self.devtype = self.read32(0xFCC)
        if unlock:
            self.unlock()

    def map(self, write=False):
        # The mmap() base address must be a multiple of the OS page size.
        # But CoreSight devices might be on a smaller granularity.
        # E.g. devices might be at 4K boundaries but the OS is using 64K pages.
        # So we need to adjust the mmap address and size to page granularity.
        # This might mean we end up mapping the same page-sized range several
        # times for different 4K devices located within it.
        if self.phy is None:
            if self.cs.devmem is not None:
                self.phy = DevicePhy(self.cs.devmem, self.base_address, write=write)
            else:
                self.phy = DeviceViaMemAP(self.cs.memap, self.base_address, write=write)

    def unmap(self):
        if self.phy is not None:
            self.phy = None

    def write_enable(self):
        if not self.map_is_write:
            if o_verbose:
                print("%s: enabling for write" % str(self))
            self.unmap()
            self.map(write=True)
            self.map_is_write = True

    def address_string(self):
        """
        A string describing how to locate this device.
        """
        s = "@0x%x" % self.base_address
        if self.phy is not None and self.phy.memap is not None:
            s = self.phy.memap.memap.address_string() + "." + s
        return s

    def __str__(self):
        s = self.cs_device_type_name()
        if s == "UNKNOWN":
            aname = self.architecture_name()
            if aname is not None:
                s = aname
        s += " %s" % self.address_string()
        if self.is_affine_to_core():
            s += " (core)"
        return s

    def __del__(self):
        self.close()

    def close(self):
        if self.we_claimed:
            self.unclaim(self.we_claimed)
        if self.we_unlocked and self.cs.restore_locks:
            self.lock()
        self.unmap()

    def read32(self, off):
        """
        Read a device register. The register may be volatile, so we should take
        care to only read it once.
        """
        self.n_reads += 1
        self.map()
        if o_verbose >= 2:
            print("  0x%x[%03x] R4" % (self.base_address, off), end="")
            if o_verbose >= 3:
                time.sleep(0.1)
        x = self.phy.read32(off)
        if o_verbose >= 2:
            print("  = 0x%08x" % x)
        return x

    def test32(self, off, mask):
        return (self.read32(off) & mask) == mask

    def wait(self, off, mask, timeout=0):
        """
        Wait for a bit to become set.
        Raise an exception if it isn't set within the timeout.
        Default timeout is "a few times".
        """
        default_iters = 10
        for i in range(0, default_iters):
            if self.test32(off, mask):
                return
        # Taking some time, switch to timeout mode
        if timeout > 0:
            t = time.time() + timeout
            while time.time() < t:
                if self.test32(off, mask):
                    return
        raise DeviceTimeout(self, off, mask)

    def do_check(self, check):
        # We can read-back to check that the write has taken effect.
        # But not when the caller has indicated that the register is volatile.
        return (check is None and self.is_checking) or check == True

    def write32(self, off, value, check=None, mask=None):
        assert self.map_is_write, "0x%x: device should have been write-enabled" % self.base_address
        if mask is not None:
            # Write value under mask. The mask specifies the bits to act on.
            # Other bits retain their previous value.
            assert (value | mask) == mask, "trying to write value 0x%x outside mask 0x%x" % (value, mask)
            ovalue = self.read32(off)
            value = (ovalue & ~mask) | value
        if o_verbose >= 2:
            print("  0x%x[%03x] W4 := 0x%08x" % (self.base_address, off, value))
            if o_verbose >= 3:
                time.sleep(0.1)
        self.n_writes += 1
        self.phy.write32(off, value)
        if self.do_check(check):
            readback = self.read32(off)
            if readback != value:
                print("  0x%x[%03x] wrote 0x%08x but read back 0x%08x" % (self.base_address, off, value, readback))
            return readback == value

    def set32(self, off, value, check=None):
        self.write32(off, self.read32(off) | value, check=False)
        if self.do_check(check):
            return (self.read32(off) & value) == value

    def clr32(self, off, value, check=None):
        self.write32(off, self.read32(off) & ~value, check=False)
        if self.do_check(check):
            return (self.read32(off) & value) == 0

    def write64(self, off, value):
        # Write an aligned 64-bit value, atomically. Cannot do with MEM-AP?
        if o_verbose >= 2:
            print("  0x%x[%03x] W8 := 0x%016x" % (self.base_address, off, value))
        self.phy.write64(off, value)

    def read32x2(self, hi, lo):
        # CoreSight (APB-connected) devices are generally 32-bit wide,
        # and 64-bit values are read as a pair of registers.
        # We assume that we're not dealing with volatile data (e.g. counters)
        # where special action is needed to return a consistent result.
        return (self.read32(hi) << 32) | self.read32(lo)

    def write32x2(self, hi, lo, value):
        # Write a 64-bit value to hi and lo registers, non-atomically.
        self.write32(hi, value >> 32)
        self.write32(lo, value & 0xffffffff)

    def read64(self, off):
        # assume little-endian
        return self.read32x2(off+4,off)

    def read64counter(self, hi, lo):
        # Read a live 64-bit counter value from a pair of registers.
        # We follow the usual procedure of reading the low word between
        # two reads of the high word, which we require to be identical.
        vhia = self.read32(hi)
        while True:
            vlo = self.read32(lo)
            vhib = self.read32(hi)
            if vhia == vhib:
                break
            vhia = vhib
        return (vhib << 32) | vlo

    def idbytes(self, x):
        id = 0
        for wa in x:
            id = (id << 8) | (self.read32(wa) & 0xff)
        return id

    def is_arm_part(self):
        return self.jedec_designer == JEDEC_ARM

    def is_arm_part_number(self, n=None):
        return self.is_arm_part() and (n is None or self.part_number == n)

    def arm_part_number(self):
        if self.is_arm_part():
            return self.part_number
        else:
            return None

    def device_class(self):
        # The overall device class (9 for CoreSight, 15 for generic PrimeCell, 1 for old-style ROM tables)
        return (self.CIDR >> 12) & 15

    def is_coresight(self):
        return self.device_class() == 9
   
    def is_coresight_timestamp(self):
        # Strangely, a CoreSight global timestamp generator doesn't report as a CoreSight device
        return self.device_class() == 0xF and self.is_arm_part_number(0x101)

    def is_rom_table(self):
        return self.device_class() == 1 or (self.is_coresight() and self.is_arm_architecture(ARM_ARCHID_ROM))

    def coresight_device_type(self):
        assert self.is_coresight()
        assert self.devtype is not None        
        major = self.devtype & 15
        minor = (self.devtype >> 4) & 15
        return (major, minor)

    def is_coresight_device_type(self, major, minor=None):
        if self.is_coresight():
            (dmaj, dmin) = self.coresight_device_type()
            return (dmaj == major) and (minor is None or dmin == minor)
        else:
            return False

    def is_core_trace(self):
        return self.is_coresight_device_type(3,1)

    def is_core_trace_etm(self):
        """
        Check for ETM-compatible (ETMv3, PFT, ETMv4, ETE) core trace.
        Anything that sets ARCHID ETM should also be reporting DEVTYPE (3,1) so the
        below test is slightly redundant. If we ever encountered non-ETM trace we
        might need to include/exclude on the basis of part number.
        """
        return self.is_core_trace() or self.is_arm_architecture(ARM_ARCHID_ETM)

    def is_core_debug(self):
        return self.is_coresight_device_type(5,1)

    def is_funnel(self):
        return self.is_coresight_device_type(2,1)

    def is_replicator(self):
        return self.is_coresight_device_type(2,2)

    def is_cti(self):
        return self.is_arm_architecture(ARM_ARCHID_CTI) or self.is_arm_part_number(0x906) or self.is_arm_part_number(0x9ED)

    def cs_device_type_name(self):
        devtype = self.coresight_device_type()
        (major, minor) = devtype
        if devtype in cs_types:
            desc = cs_types[devtype]
        elif major in cs_majors:
            desc = "UNKNOWN %s" % cs_majors[major]
        elif devtype != (0,0):
            desc = "UNKNOWN %s" % str(devtype)
        else:
            desc = "UNKNOWN"
        return desc

    def architecture_name(self):
        if self.architecture() is None:
            return None
        if self.is_arm_architecture():
            archid = self.architecture()
            archpart = archid & 0xfff
            archrev = (self.devarch >> 16) & 15
            if archid in arm_archids:
                archdesc = "Arm %s rev%u" % (arm_archids[archid], archrev)
            elif archpart in arm_archparts:
                archdesc = "?Arm %s rev%u.%u" % (arm_archparts[archpart], (archid >> 12), archrev)
            else:
                archdesc = "?Arm:0x%04x rev %u" % (archid, archrev)
        else:
            archdesc = "?ARCH:0x%x:0x%x" % (self.architect(), self.architecture())
        return archdesc

    def atb_in_ports(self):
        if self.is_funnel():
            # TBD: strictly, device-type=funnel doesn't mean it has the CoreSight programming interface
            return self.read32(0xFC8) & 15    # read DEVID
        elif self.coresight_device_type()[0] in [1,2]:   # sink or link
            return 1
        else:
            return 0

    def atb_out_ports(self):
        if self.is_replicator():
            return 2
        elif self.coresight_device_type()[0] in [2,3]:   # link or source
            return 1
        elif self.is_arm_architecture(ARM_ARCHID_ELA):
            # ELA-600 may be configured with ATB, but doesn't change its DEVTYPE
            devid = self.read32(0xFC8)
            return [0,1][bits(devid,0,4)!=0]
        else:
            return 0

    def affinity_id(self):        
        # Return the affinity descriptor as reported by the device.
        # Architecturally, this is only standardized for CoreSight devices.
        if self.is_coresight():
            aff = self.read32x2(0xFAC,0xFA8)
            if aff != 0:
                return aff
        return None

    def is_affine_to_core(self):
        """
        Check if the device is affine to a core.
        Clearly true if affinity has already been detected, but we might also be able to report
        true on the basis of DEVTYPE e.g. (5,1) is specifically a core PMU and not an uncore PMU.
        """
        return self.affine_core is not None

    def affine_device(self, typ):
        if self.is_affine_to_core:
            return self.affinity_group.affine_device(typ)
        else:
            return None

    def architect(self):
        # CoreSight devices have a DEVARCH register which specifies the architect and architecture as a JEDEC code.
        assert self.is_coresight()
        if self.devarch is None:
            return None
        return self.devarch >> 21

    def architecture(self):
        assert self.is_coresight()
        if self.devarch is None:
            return None
        return self.devarch & 0xffff

    def is_arm_architecture(self, arch=None):
        return self.is_coresight() and (self.architect() == JEDEC_ARM) and (arch is None or arch == self.architecture())
    
    def is_arm_architecture_core(self):
        # Return true if the device is (the debug interface to) an Arm-architecture core
        return self.is_arm_architecture() and (self.architecture() & 0x0fff) == 0x0a15

    def is_unlocked(self):
        """
        Return True if the device is unlocked and writeable. This is only
        valid for CoreSight devices.
        """
        return (self.read32(0xFB4) & 0x02) == 0

    def is_claimed(self, mask=0xffffffff):
        """
        Read CLAIMCLR and check if any of the mask bits (default all) are set
        """
        return self.read32(0xFA4) & mask

    def claim(self, mask=0x01):
        """
        Write CLAIMSET to set claim tag(s).
        """
        assert mask != 0
        self.write32(0xFA0, mask)
        self.we_claimed |= mask

    def unclaim(self, mask=0x01):
        """
        Write CLAIMCLR to release claim tag(s).
        """
        if mask:
            self.write32(0xFA4, mask)
            self.we_claimed &= ~mask

    def is_in_integration_mode(self):
        return (self.read32(0xF00) & 0x01) != 0

    def unlock(self):
        self.write_enable()
        if not self.is_unlocked():
            if o_verbose >= 2:
                print("%s: unlocking" % self)
            self.write32(0xFB0, 0xC5ACCE55, check=False)
            self.we_unlocked = True

    def lock(self):
        if self.is_unlocked():
            self.write32(0xFB0, 0x00000000, check=False)

    def set_integration_mode(self, flag):
        if flag:
            self.set32(0xF00, 0x00000001, check=True)
        else:
            self.clr32(0xF00, 0x00000001, check=True)


class ROMTableEntry:
    """
    An entry in a ROM table. Contains information from the table itself.
    """
    def __init__(self, td, offset, width, e):
        self.table = td            # table device
        self.offset = offset       # byte offset of the entry within the table
        self.width = width         # entry width in bytes
        self.descriptor = e        # the 4-byte or 8-byte table entry (device offset, power req)
        self.device = None         # may be populated later
        self.is_inaccessible = False   # set to True if we can't create a device for it

    def __str__(self):
        s = "0x%x[0x%03x]: " % (self.table.base_address, self.offset)
        s += ("%%0%ux" % (self.width*2)) % self.descriptor
        if self.is_present():
            s += " -> 0x%x" % self.device_address()
        return s

    def is_present(self):
        return (self.descriptor & 1) != 0
          
    def device_offset(self): 
        # offset is at the top of the word and can be negative
        if self.width == 4:
            off = (self.descriptor & 0xfffff000)
            if (off & 0x80000000) != 0:
                off -= 0x100000000
        else:
            off = (self.descriptor & 0xfffffffffffff000)
            if (off & 0x8000000000000000) != 0:
                off -= 0x10000000000000000
        return off

    def device_address(self):
        return self.table.base_address + self.device_offset()


class AffinityGroup:
    """
    An affinity group groups related components together, e.g.
    a core debug, PMU, ETM and CTI.
    The grouping may be by DEVAFF or by proximity in the ROM table.
    """
    def __init__(self, id=None):
        self.id = id
        self.devices = {}     # indexed by type

    def set_affine_device(self, d, typ):
        assert typ not in self.devices, "attempt to put two devices of type '%s' in group %s" % (typ, self)
        self.devices[typ] = d
        # As well as its affinity group, each device has a direct link to its core
        # We fix this up regardless of the order in which we add the devices to the affinity group
        if typ == "core":
            for od in self.devices.values():
                od.affine_core = d
        elif "core" in self.devices:
            d.affine_core = self.devices["core"]

    def affine_device(self, typ):
        if typ in self.devices:
            return self.devices[typ]
        else:
            return None

    def __str__(self):
        return "AffinityGroup(0x%016x)" % self.id


class DevMem:
    """
    Access physical memory via /dev/mem. This object creates mappings into
    page-aligned regions of physical address space.

    Object construction will raise PermissionError if not privileged.
    """

    def __init__(self):
        self.page_size = os.sysconf("SC_PAGE_SIZE")
        self.fd = None
        if os.path.isfile("/dev/csmem"):
            devmem = "/dev/csmem"
        else:
            devmem = "/dev/mem"
        try:
            # This may fail because not present or access-restricted.
            self.fd = open(devmem, "r+b")
        except FileNotFoundError:
            print("physical memory %s not found - rebuild kernel" % devmem)
            raise
        except PermissionError:
            print("can't access %s - try running as superuser" % devmem)
            raise
        self.fno = self.fd.fileno()
        self.n_mappings = 0

    def __del__(self):
        if self.fd is not None:
            self.fd.close()

    def map(self, addr, write=False):
        """
        Return a memory area mapping that can be used to access a CoreSight peripheral.
        The address passed in must be page-aligned (even if the device is not
        (e.g. 4K-aligned devices with 64K OS pages) - the caller is responsible for
        sorting that out.

        The caller is also responsible for releasing the mapping when finished with.

        If the kernel is built with CONFIG_IO_STRICT_DEVMEM, this mmap() may fail
        with EPERM if the area is already registered to the kernel.
        """
        try:
            if write:
                prot = (mmap.PROT_READ|mmap.PROT_WRITE)
            else:
                prot = mmap.PROT_READ
            m = mmap.mmap(self.fno, self.page_size, mmap.MAP_SHARED, prot, offset=addr)
        except PermissionError:
            raise
        except EnvironmentError as e:
            print("** failed to map 0x%x size 0x%x on fileno %d (currently %u mappings): %s" % (addr, self.page_size, self.fno, self.n_mappings, e))
            raise
        self.n_mappings += 1
        return m

    def unmap(self, m):
        """
        Unmap device memory. Called when a device object is deleted.
        """
        m.close()
        self.n_mappings -= 1


class DevMemRemote:
    """
    Compatible with class DevMem, but accesses remote via devmemd.
    """
    def __init__(self, addr, port):
        self.page_size = 4096
        self.devmemd = devmemd.Devmem(addr, port)

    def map(self, addr, write=False):
        """
        Return a mmap-compatible object that indirects via devmemd.
        """
        return self.devmemd.map(addr, self.page_size)

    def unmap(self, m):
        pass


class CSROM:
    """
    Container for the overall ROM table scan.
    Owns the mechanism by which we access physical memory - e.g. a
    mapping on to /dev/mem. Individual device mappings are owned by the
    device objects.
    """
    def __init__(self, memap=None):
        self.fd = None
        self.memap = memap
        self.device_by_base_address = {}
        self.affinity_group_map = {}
        self.restore_locks = True
        if memap is None:
            if g_devmem is not None:
                self.devmem = g_devmem
            else:
                self.devmem = DevMem()
        else:
            self.devmem = None

    def close(self):
        for d in self.device_by_base_address.values():
            d.close()
        self.device_by_base_address = {}

    def __del__(self):
        self.close()

    def map(self, addr, write=False):
        if self.devmem is not None:
            return self.devmem.map(addr, write)
        else:
            return None

    def unmap(self, addr):
        if self.devmem is not None:
            return self.devmem.unmap(addr)
        else:
            return None

    def device_at(self, addr, unlock=False):
        """
        Return the device at a given address, which must already have been registered.
        """
        assert addr in self.device_by_base_address, "missing device at 0x%x" % addr
        d = self.device_by_base_address[addr]
        if unlock:
            d.unlock()         # This will enable for write if not already
        return d

    def create_device_at(self, addr, rom_table_entry=None, write=False, unlock=False):
        assert not addr in self.device_by_base_address, "device at 0x%x already collected" % addr
        d = Device(self, addr)
        d.rom_table_entry = rom_table_entry
        self.device_by_base_address[addr] = d
        if write:
            d.write_enable()
        if unlock:
            d.unlock()
        return d

    def affinity_group(self, id):
        if id not in self.affinity_group_map:
            self.affinity_group_map[id] = AffinityGroup(id)
        return self.affinity_group_map[id]

    def list_table(self, td, include_empty=False, recurse=True):
        """
        Iterate (perhaps recursively) over a ROM Table, returning
        ROMTableEntry objects which contain device objects.

        We assume ROM tables all have the same format. They may have a
        vendor part number, and DEVARCH is not set, but the CIDR device class
        identifies them as a Class 1 ROM table.

        The first entry is at address 0x000. Each subsequent entry is at
        the next 4-byte boundary, until a value of 0x00000000 is read which
        is the final entry.
        """
        assert td.is_rom_table()
        if td.is_coresight():
            # Class 9 (new) ROM Table
            etop = 0x800
            devid = td.read32(0xFC8)
            format = devid & 15
            if format == 0:
                ewidth = 4
            elif format == 1:
                ewidth = 8
            else:
                assert False, "unknown Class 9 ROM Table format: %u" % format
        else:
            # Class 1 (old) ROM Table
            etop = 0xF00
            ewidth = 4
        cpus_in_this_table = []
        for a in range(0, etop, ewidth):
            if ewidth == 4:
                eword = td.read32(a)
            else:
                eword = td.read64(a)
            if eword == 0:
                break            
            if (eword & 1) == 0 and not include_empty:
                continue
            e = ROMTableEntry(td, a, ewidth, eword)
            if e.is_present():
                if e.device_offset() == 0:
                    # ROM table points back to itself - shouldn't happen
                    continue
                if e.device_address() in o_exclusions:
                    e.is_inaccessible = True
                    yield e
                    continue
                # We don't want to fault when we encounter the same device in multiple
                # ROM tables. Ideally, for a given recursive scan, we'd return each device
                # at most once.
                if e.device_address() in self.device_by_base_address:
                    dd = self.device_by_base_address[e.device_address()]
                    if dd.rom_table_entry is not None:
                        print("** note: redundant ROM table entries for device 0x%x:" % e.device_address())
                        print("  %s" % dd.rom_table_entry)
                        print("  %s" % e)
                    continue
                # if we're scanning recursively, we have to map the device even if
                # we aren't otherwise interested in devices. A ROM Table entry doesn't
                # indicate that it points to a sub-table as opposed to some other device -
                # we have to map the device and find out if it's another table.
                try:
                    d = self.create_device_at(e.device_address(), rom_table_entry=e)
                except PermissionError:
                    e.is_inaccessible = True
                    yield e
                    continue
                e.device = d
                # Fix up device affinity - in the absence of anywhere better.
                # We could either do this using DEVAFF or heuristically.
                id = d.affinity_id()
                if id:
                    d.affinity_group = self.affinity_group(id)
                adtype = None
                if d.is_coresight_device_type(6,1):
                    adtype = "PMU"
                elif d.is_coresight_device_type(3,1):
                    adtype = "ETM"
                elif d.is_coresight_device_type(4,1):
                    adtype = "CTI"
                if d.is_core_debug():
                    if not id:
                        d.affinity_group = AffinityGroup()    # anonymous group
                    d.affinity_group.set_affine_device(d, "core")
                    cpus_in_this_table.append(d)
                elif adtype is not None:
                    if id:
                        d.affinity_group.set_affine_device(d, adtype)
                    else:
                        # Allocate to the first CPU that hasn't yet got an affine device of this type 
                        for c in cpus_in_this_table:
                            if c.affine_device(adtype) is None:
                                # If not using DEVAFF, core should be at -64K offset from the CTI
                                if adtype == "CTI" and c.base_address != (d.base_address - 0x10000):
                                    continue
                                c.affinity_group.set_affine_device(d, adtype)
                                break
                yield e
                if recurse and d.is_rom_table():
                    for se in self.list_table(d, include_empty=include_empty, recurse=True):
                        yield se
                # after yielding the device to whoever wants it, unmap it so we
                # don't run out of memory mappings. Even a limit of 1000 will be
                # exhausted if we have a 300-core SoC with 5 devices per core.
                d.unmap()
            else:
                yield e 

    @staticmethod
    def show_coresight_device(d):
        """
        Show some information about the device.
        We organize this to show information progressively from the static
        and abstract, to the dynamic and device-specific:
          - device class: e.g. trace source
          - architecture or product: e.g. ETMv4.1, or CoreSight ETB
          - configuration chosen by designer: e.g. ETMv4.1 with four counters, 16K ETB
          - programming: e.g. ETM counter transition rules, ETF in circular mode
          - state: ETM current counter values, ETB buffer occupancy 
        """

        # Registers architected by CoreSight, with architected values
        devtype = d.coresight_device_type()
        desc = d.cs_device_type_name()
        archdesc = d.architecture_name()
        if archdesc is None:
            archdesc = "<no arch>"

        # architected regs with imp def values
        affinity = d.affinity_id()
        devid = d.read32(0xFC8)

        authstatus = d.read32(0xFB8)
        if o_show_authstatus:
            # Authorization status works in three dimensions:
            #   functionality: invasive debug / non-invasive debug
            #   accessor: nonsecure, secure, hypervisor
            #   status: unsupported, supported and disabled, supported and enabled
            print("", end=" ")
            #print("auth=%04x" % authstatus, end=" ")
            # Invasive, NonInvasive are considered independent functionality
            for (iix, inv) in enumerate(["I","NI"]):
                # NonSecure, Secure, HypervisorNonSecure: only some combinations make sense?
                # SID implies NSID etc. But we might have SID supported but disabled, NSID enabled
                for (dix, dom) in zip([1,2,0],["S","HN","NS"]):
                    stat = bits(authstatus, dix*4+iix*2, 2)
                    dtype = "%s%sD" % (dom, inv)
                    if stat != 0:
                        if stat == 2:
                            # functionality disabled
                            dtype = dtype.lower()
                        print("%-5s" % (dtype), end=" ")
                    else:
                        print("     ", end=" ")
            print("", end=" ")

        print("%-14s %-16s" % (desc, archdesc), end="")
        if o_verbose:
            print(" devid=0x%x" % devid, end="")
        if affinity is not None:
            print(" aff=0x%x" % affinity, end="")
        if False and d.is_affine_to_core():
            print(" affine_core=@0x%x" % d.affine_core.base_address, end="")
        arm_part = d.arm_part_number()    # Will be None if not an ARM part
        # don't print here, already printed in show_device() to cope with non-CoreSight devices
        if False and arm_part is not None and arm_part in arm_part_numbers:
            print(" %s" % arm_part_numbers[arm_part], end="")
            
        # Now extract additional device-specific information. In general, we can establish
        # the type of device, and our ability to determine further information, in two ways:
        #
        #   - DEVARCH, when present, may indicate that it implements an Arm-defined
        #     architecture (such as ETM, PMU or core debug), irrespective of who it
        #     was designed by.  We can then reference Arm's architecture reference manual
        #     (ARM ARM, or CoreSight architecture manual). Note that DEVARCH might not
        #     be present, indicated by reading as zero.
        #
        #   - PIDR may indicate that it is an Arm-designed device (such as CTI, Funnel etc.
        #     from the CoreSight IP product portfolio), and we can then reference Arm's
        #     product Technical Reference Manual (TRM).
        # 
        # We should always check one or other of DEVARCH and PIDR. It is not sufficient
        # just to look at DEVTYPE.
        # 
        # Some functionality might be implementation-defined (product-specific) even for
        # devices that implement an architecture.

        # Further registers might be in the Core power domain (this will be specified
        # in the manual). Reading powered-off registers might cause a bus error.

        core_powered_off = False       # core-affine devices may override below
        if d.is_arm_architecture_core():
            # Arm v8 debug architecture: core debug, external view (ED... registers)
            edprsr = d.read32(0x314)
            core_powered_off = ((edprsr & 0x1) == 0)
            if (edprsr & 0x1) == 0:        
                print(" powered-down", end="")
            if (edprsr & 0x4) == 1:
                print(" halted", end="")
            if not core_powered_off:
                midr = d.read32(0xD00)
                print(" midr=0x%08x" % midr, end="")
                pfr = d.read32x2(0xD24,0xD20)     # EDPFR: External Debug Processor Feature Register
                if True or o_verbose:
                    print(" pfr=0x%x" % (pfr), end="")
                if bits(pfr,44,4):
                    print(" AMU", end="")
                dfr = d.read32x2(0xD2C,0xD28)     # EDDFR: External Debug Feature Register
                if True or o_verbose:
                    print(" dfr=0x%x" % (dfr), end="")
                pmuver = bits(dfr,8,4)
                print(" bkpt:%u wpt:%u" % (bits(dfr,12,4)+1, bits(dfr,20,4)+1), end="")
                pmuvers = {
                    0x1: "PMUv3",
                    0x4: "PMUv3-v8.1",
                    0x5: "PMUv3-v8.4",
                    0x6: "PMUv3-v8.5",
                    0xf: "PMU-impdef"
                }
                if pmuver in pmuvers:
                    print(" %s" % pmuvers[pmuver], end="")
                if bits(dfr,40,4):
                    print(" self-hosted-trace", end="")
                if bits(devid,0,4):
                    print(" pc-sampling:%u" % bits(devid,0,4), end="")
                if bits(devid,4,4):
                    print(" DoPD", end="")
        elif d.is_arm_architecture(ARM_ARCHID_PMU):
            # PMU doesn't have a register of its own to indicate power state - you have to find the affine core.
            if not d.is_affine_to_core():
                core_powered_off = True
            else:
                edprsr = d.affine_core.read32(0x314)
                core_powered_off = ((edprsr & 0x1) == 0)
            if not core_powered_off:
                config = d.read32(0xE00)
                n_counters = config & 0xff
                csize = bits(config,8,6)+1
                if o_verbose:
                    print(" config:0x%08x" % (config), end="")
                print(" counters:%u" % (n_counters), end="")
                print(" %u-bit" % (csize), end="")
                if bit(config,15):
                    print(" prescale", end="")
                if bit(config,16):
                    print(" exportable", end="")
                else:
                    print(" not-exportable", end="")
                if bit(config,19):
                    print(" user-enable", end="")
                pmmir = d.read32(0xE40)
                n_slots = bits(pmmir,0,8)
                if n_slots:
                    print(" slots:%u" % (n_slots), end="")
                if bits(devid,0,4):
                    # ARMv8.2 moves PC sampling from core debug into PMU
                    print(" pc-sampling:%u" % bits(devid,0,4), end="")
        elif d.is_core_trace_etm():
            # Test if the registers are invalid/unreadable, either because the core power domain
            # is powered off or because the ETM hasn't been initialized since reset.
            #   TRCPDSR.STICKYPD[1]  indicates that trace register power has been removed
            #                        since TRCPDSR was last read, to indicate that programming
            #                        state has been lost. It is cleared after a read of TRCPDSR.
            #   TRCPDSR.POWER[0]     indicates the ETM trace unit is powered and all registers
            #                        are accessible.
            pdsr = d.read32(0x314)
            core_powered_off = ((pdsr & 0x1) == 0) or ((pdsr & 0x2) != 0)
            print(" pdsr=0x%08x" % pdsr, end="")
            etmid1 = d.read32(0x1E4)
            if o_verbose:
                print(" etmid1=0x%08x" % etmid1, end="")
            emajor = bits(etmid1,8,4)
            eminor = bits(etmid1,4,4)
            if emajor < 3:             
                earch = "ETMv%u" % (emajor+1)
            elif emajor == 3:
                earch = "PFTv1"
            else:
                earch = "ETMv%u" % (emajor)
            earch += ".%u" % eminor
            print(" %s" % (earch), end="")
            if emajor >= 4:
                etmid0 = d.read32(0x1E0)
                etmid3 = d.read32(0x1EC)
                etmid4 = d.read32(0x1F0)
                etmid5 = d.read32(0x1F4)
                if o_verbose:
                    print(" etmid0=0x%08x etmid3=0x%08x etmid4=0x%08x etmid5=0x%08x" % (etmid0, etmid3, etmid4, etmid5), end="")
                print(" ts:%u" % (8*bits(etmid0,24,5)), end="")
                if bit(etmid0,5):
                    print(" bb", end="")
                if bit(etmid0,6):
                    print(" cond", end="")
                if bit(etmid0,7):
                    print(" cc", end="")
                    print(" min-ccit:%u" % bits(etmid3,0,11), end="")
                if bit(etmid0,9):
                    print(" retstack", end="")
                if bit(etmid3,27):
                    print(" stall", end="")
                if bit(etmid3,25):
                    print(" fixed-sync", end="")
                n_resource_selectors = bits(etmid4,16,4)*2 + 2
                n_address_comparator_pairs = bits(etmid4,0,4)
                n_pe_comparators = bits(etmid4,12,4)
                n_single_shot = bits(etmid4,20,4)
                n_events = bits(etmid0,10,2)+1
                n_counters = bits(etmid5,28,3)
                n_seqstates = bits(etmid5,25,3)
                n_extin = bits(etmid5,0,9)
                n_extinsel = bits(etmid5,9,3)
                if emajor > 4 or eminor >= 3:
                    if bits(etmid4,16,4) == 0:
                        n_resource_selectors = 0
                        n_events = 0       
                print(" events:%u resources:%u addrcomp:%u ssc:%u pecomp:%u counters:%u seqstates:%u extin:%u extinsel:%u" % (n_events, n_resource_selectors, n_address_comparator_pairs, n_single_shot, n_pe_comparators, n_counters, n_seqstates, n_extin, n_extinsel), end="")
                if bit(etmid5,31):
                    print(" reduced-function-counter", end="")
        elif d.is_arm_architecture(ARM_ARCHID_STM):
            # CoreSight STM
            n_ports = devid & 0x1ffff
            print(" ports:%u" % n_ports, end="")
        elif d.is_arm_architecture(ARM_ARCHID_MEMAP):
            idr = d.read32(0xDFC)
            print(" idr:0x%08x" % idr, end="")
            aptype = bits(idr,0,4)
            aptypes = { 0: "JTAG", 1: "AHB3", 2: "APB2", 4: "AXI", 6: "APB4", 7: "AXI5", 8: "AHB5+HPROT" }
            if aptype in aptypes:
                saptype = aptypes[aptype]
            else:
                saptype = str(aptype)
            print(" type:%s" % saptype, end="")
            cfg = d.read32(0xDF4)
            if bit(cfg,1):
                print(" long-address", end="")
            if bit(cfg,2):
                print(" large-data", end="")
            if bits(cfg,4,4):
                print(" DAR:%u" % (1<<bits(cfg,4,4)), end="")
            if bits(cfg,8,4):
                print(" TRR", end="")
            if bits(cfg,16,4):
                print(" TARINC:%u" % (9+bits(cfg,16,4)), end="")
            if cfg & 0xfff0fe09:
                print(" CFG:0x%08x" % cfg, end="")
            rombase = d.read32x2(0xDF0,0xDF8)
            if rombase not in [0x0,0x2]:
                print(" ROM:%#x" % rombase, end="")
        elif d.is_arm_architecture(ARM_ARCHID_ELA):
            devid1 = d.read32(0xFC4)
            devid2 = d.read32(0xFC0)
            ram_addr_width = bits(devid,8,8)    # SRAM address width in bits, e.g. 6 bits => 64 entries
            # Show ELA-500 version from PIDR2
            prod_rev = (d.PIDR >> 20) & 15       # PIDR2.REVISION
            if d.is_arm_part_number(0x9B8):     # ELA-500
                rev_names = ["r0p0","r1p0","r2p0","r2p1","r2p2"]
            elif d.is_arm_part_number(0x9D0):   # ELA-600
                rev_names = ["r0p0","r1p0","r2p0"]
            else:
                rev_names = None
            if rev_names is not None and prod_rev < len(rev_names):
                print(" %s" % rev_names[prod_rev], end="")
            else:
                print(" revcode=%u" % prod_rev, end="")
            print(" devid:0x%08x entries:%u" % (devid, (1<<ram_addr_width)), end="")
            print(" trace-format-%u" % bits(devid,4,4), end="")
            if bits(devid,0,4):
                print(" ATB", end="")
            if bits(devid,16,4):
                print(" COND_TRIG:%u" % bits(devid,16,4), end="")
            print(" id-capture:%u" % bits(devid,20,5), end="")
            if bits(devid,25,4) == 1:
                print(" scrambler", end="")
            print(" groupwidth=%u" % ((bits(devid1,8,8)+1)*8), end="")
            print(" trigstates=%u" % bits(devid1,16,8), end="")
            if bits(devid2,8,8):
                print(" compwidth=%u" % ((bits(devid2,8,8)+1)*8), end="")
        elif d.is_cti():
            # CoreSight CTI (SoC400) or CoreSight CTI (SoC600) or core CTI
            # n.b. SoC600 CTI is fixed at 4 channels
            print(" channels:%u triggers:%u" % (((devid>>16)&0xf), ((devid>>8)&0xff)), end="")
            if bits(devid,24,2):
                print(" gate", end="")
        elif d.is_arm_part_number(0x908) or d.is_arm_part_number(0x9eb):
            # CoreSight trace funnel (SoC400 or SoC600)
            in_ports = devid & 15
            print(" in-ports:%u" % in_ports, end="")
            if (devid & 0xf0) == 3:
                print(" priority-scheme")
        elif d.is_arm_part_number(0x909) or d.is_arm_part_number(0x9ec):
            # CoreSight trace replicator (SoC400 or SoC600)
            out_ports = devid & 15
            print(" out-ports:%u" % out_ports, end="")
            if (devid & 0xf0) == 3:
                print(" priority-scheme")
        elif d.is_arm_part_number(0x912) or d.is_arm_part_number(0x9e7):
            # CoreSight TPIU
            print(" TPIU", end="")
        elif d.is_arm_part_number(0x914):
            # CoreSight SWO
            print(" SWO", end="")
        elif d.is_arm_part_number(0x907):
            # CoreSight ETB
            print(" ETB size:%u" % (d.read32(0x004)*4), end="")
        elif d.arm_part_number() in [0x961, 0x9e8, 0x9e9, 0x9ea]:
            # CoreSight TMC (SoC400 generation, or SoC600)
            configtype = (devid >> 6) & 3
            print(" TMC:%s" % ["ETB","ETR","ETF","?3"][configtype], end="")
            if configtype != 1:
                print(" size:%u" % (d.read32(0x004)*4), end="")   # for ETB/ETF this is fixed, for ETR it's the buffer size
            memwidth = (devid >> 8) & 7
            print(" memwidth:%u" % (8<<memwidth), end="")
            if configtype == 1:
                wbdepth = (devid >> 11) & 7
                print(" wb:%u" % (1<<wbdepth), end="")
        else:
            # No more information for this part
            print(" -", end="")

        # dynamic information, but generic for all CoreSight devices
        if d.is_unlocked():
            print(" unlocked", end="")
        if not core_powered_off:
            claimed = d.read32(0xFA4)
            if claimed:
                print(" claimed:0x%x" % claimed, end="")
        if d.is_in_integration_mode():
            print(" integration", end="")
        print()

        """
        Show the device programming and current state.

        We might in future separate this into a different routine, but for now
        we rely on some variables we set in the configuration discovery.
        """

        if not o_show_programming:
            return
        if core_powered_off:
            return

        integration_regs = []

        if d.is_arm_architecture_core():
            # Core debug interface: show the current status
            dscr = d.read32(0x088)
            dstatus = dscr & 0x3f
            dstatus_str = {
                0x1: "PE restarting",
                0x2: "PE in non-debug state",
                0x7: "breakpoint",
                0x13: "external debug request",
                0x1b: "halting step, normal",
                0x1f: "halting step, exclusive",
                0x23: "OS unlock catch",
                0x27: "reset catch",
                0x2b: "watchpoint",
                0x2f: "HLT instruction",
                0x33: "software access to debug register",
                0x37: "exception catch",
                0x3b: "halting step, no syndrome"
            }
            if dstatus in dstatus_str:
                sd = dstatus_str[dstatus]
            else:
                sd = "status 0x%x?" % dstatus
            print("  dscr: 0x%08x (%s)" % (dscr, sd))
            print("  halting debug for bkpt/wpt/hlt (HDE): %s" % ["disabled","enabled"][bit(dscr,14)])
            print("  secure debug (SDD): %s" % ["enabled","disabled"][bit(dscr,16)])
            print("  access mode: %s" % ["normal","memory"][bit(dscr,20)])
            if bit(dscr,25):
                print("  pipeline advanced")
            if bit(dscr,29):
                print("  TX full")
            if bit(dscr,30):
                print("  RX full")
            if dstatus != 2:
                # in debug state (only), some other status fields are meaningful
                print("  EL%u" % bits(dscr,8,2))
                if not bit(dscr,18):
                    print("  Secure")
                if bit(dscr,24):
                    print("  ITR empty")
        elif d.is_arm_architecture(ARM_ARCHID_PMU):
            # Show dynamic configuration and current state for PMU
            pmcr = d.read32(0xE04)
            print("  pmcr: 0x%08x" % pmcr)
            ovs = d.read32(0xC80)
            cen = d.read32(0xC00)
            ccntr = d.read64(0x0F8)
            print("  ccntr: 0x%016x" % ccntr, end="")
            if bit(cen,31):
                print(" enabled", end="")
            if bit(ovs,31):
                print(" overflowed", end="")
            print()
            for i in range(0,n_counters):
                evcnt = d.read64(0x000+i*8)
                evtyp = d.read32(0x400+i*4)
                print("  #%u: 0x%08x 0x%016x" % (i, evtyp, evcnt), end="")
                if bit(cen,i):
                    print(" enabled", end="")
                if bit(ovs,i):
                    print(" overflowed", end="")
                print()
        elif d.is_core_trace_etm():
            # Show dynamic configuration and current state for ETM-like core trace
            if emajor >= 4:
                def res_str(rn):
                    # ETMv4 4.4.2
                    if rn == 0:
                        return "FALSE"
                    elif rn == 1:
                        return "TRUE"
                    else:
                        return "R%u" % rn
                def esel_str(e):
                    if not bit(e,7):
                        return res_str(bits(e,0,5))
                    else:                        
                        pair = bits(e,0,4)*2
                        if bit(e,4) or (bit(e,7) and pair == 0):
                            return "?%x" % e
                        return res_str(pair) + "/" + res_str(pair+1)
                def blist(pfx,bs,n=32,inv=False):
                    bl = []
                    for i in range(0,n):
                        if (not inv and bit(bs,i)) or (inv and not bit(bs,i)):
                            bl.append(pfx+"%u" % i)
                    return bl
                # Ideally, we only print ETM configuration elements that are used,
                # but discovering which are used is in general recursive.
                # E.g. a counter decrement condition may depend on a resource,
                # which in turn depends on a counter reaching zero.
                # Currently we show all resources and all their dependents.
                ac_used = 0
                pec_used = 0
                ssc_used = 0
                ctr_used = 0
                # show stability
                status = d.read32(0x00C)
                if not bit(status,1):
                    # NOT "The programmer's model is stable. When polled, the trace unit
                    #      registers return stable data."
                    print("  unstable")
                if bit(status,0):
                    print("  idle")
                oslsr = d.read32(0x304)
                print("  oslsr: 0x%08x" % oslsr)
                # show main configuration: branch-broadcasting etc.
                enabled = bit(d.read32(0x004),0)
                if enabled:
                    print("  enabled")
                config = d.read32(0x010)
                print("  config: 0x%08x:" % config, end="")
                if bit(config,3):
                    # show which ACs are used to include/exclude branch-broadcast
                    bbctl = d.read32(0x03C)
                    print(" branch-broadcast:0x%x" % (bbctl), end="")
                    for i in range(0, 8):
                        if bit(bbctl,i):
                            ac_used |= (3 << (i*2))
                if bit(config,4):
                    print(" cycle-count:%u" % (d.read32(0x038)), end="")
                if bit(config,11):
                    tsctl = d.read32(0x030)
                    print(" timestamp-event: %s" % (esel_str(bits(tsctl,0,8))), end="")
                if bit(config,12):
                    print(" return-stack", end="")
                if bit(config,6):
                    print(" cxid", end="")
                if bit(config,7):
                    print(" vmid", end="")
                print()
                # TRCVICTLR: ViewInst Control. Controls instruction trace filtering.
                vic = d.read32(0x080)
                event = bits(vic,0,8)
                print("  instruction trace-enable: 0x%08x %s %s" % (vic, esel_str(event), '|'.join(blist("EL",bits(vic,20,3),n=3,inv=True))))
                if n_address_comparator_pairs > 0 or n_pe_comparators > 0:
                    if bit(vic,9):
                        print("  start/stop logic is started")
                    else:
                        print("  start/stop logic is stopped")
                if n_address_comparator_pairs > 0:
                    # TRCVIIECTLR: ViewInst Include-Exclude Control Register
                    vie = d.read32(0x084)
                    print("  instruction include/exclude: 0x%08x" % vie, end="")
                    for i in range(0, n_address_comparator_pairs):
                        if bit(vie,i):
                            ac_used |= (3 << (i*2))
                            print(" include AC%u..AC%u" % (i*2,i*2+1), end="")
                        if bit(vie,i+16):
                            ac_used |= (3 << (i*2))
                            print(" exclude AC%u..AC%u" % (i*2,i*2+1), end="")
                    print()
                    # TRCVISSCTLR: ViewInst Start/Stop Control
                    viss = d.read32(0x088)
                    print("  instruction start/stop: 0x%08x" % viss, end="")
                    for i in range(0, n_address_comparator_pairs*2):
                        if bit(viss,i):
                            ac_used |= (1 << i)
                            print(" start AC%u" % (i), end="")
                        if bit(viss,i+16):
                            ac_used |= (1 << i)
                            print(" stop AC%u" % (i), end="")
                    print()
                if n_pe_comparators:
                    vissp = d.read32(0x08C)
                    print("  instruction PE comparator control: 0x%08x" % vissp, end="")
                    for i in range(0, n_pe_comparators):
                        if bit(vissp,i):
                            pec_used |= (1 << i)
                            print(" start PEC%u" % (i), end="")
                        if bit(vissp,i+16):
                            pec_used |= (1 << i)
                            print(" stop PEC%u" % (i), end="")
                    print()
                # show resources
                for rn in range(2,n_resource_selectors):
                    rs = d.read32(0x200+4*rn)
                    if rs == 0:
                        # no external inputs: never true
                        continue
                    print("  resource #%u: 0x%08x" % (rn,rs), end="")
                    if bit(rs,20):
                        print(" INV", end="")
                    if bit(rs,21):
                        print(" PAIRINV", end="")
                    group = bits(rs,16,4)
                    sel = bits(rs,0,16)
                    bl = []
                    if group == 0:
                        bl = blist("EXTSEL",sel)
                    elif group == 1:
                        bl = blist("PECOMP",sel)
                        pec_used |= sel
                    elif group == 2:
                        bl = blist("SEQ==",sel>>4) + blist("ZERO:C",sel&15)
                        ctr_used |= (sel & 15)
                    elif group == 3:
                        bl = blist("SSC",sel)
                        ssc_used |= sel
                    elif group == 4:
                        bl = blist("SAC",sel)
                        ac_used |= sel
                    elif group == 5:
                        bl = blist("AR",sel)
                        for i in range(0,8):
                            if bit(sel, i):
                                ac_used |= (3 << (i*2))
                    elif group == 6:
                        bl = blist("CXID",sel)
                    elif group == 7:
                        bl = blist("VCXID",sel)
                    else:
                        bl = blist("?",sel)
                    print(" %s" % "|".join(bl))
                # Show external inputs.
                if n_extinsel:
                    eis = d.read32(0x120)
                    for ei in range(0,n_extinsel):
                        print("  extin #%u: %u" % (ei, bits(eis,8*ei,8)))
                # Show trace events. These are traced in ETM event packets and as ETM external outputs.
                if n_events:
                    ectl0 = d.read32(0x020)
                    ectl1 = d.read32(0x024)
                    for en in range(0,n_events):
                        SEL = bits(ectl0,en*8,8)
                        print("  trace-event #%u: %s" % (en, esel_str(SEL)), end="")
                        if bit(ectl1,en):
                            print(" enabled", end="")
                        if en == 0 and bit(ectl1,11):
                            print(" trigger", end="")
                        print()
                # show single-shot control
                for n in range(0,n_single_shot):
                    ssctrl = d.read32(0x280+n*4)
                    ssstat = d.read32(0x2A0+n*4)
                    print("  single-shot #%u: ctrl=0x%08x status=0x%08x" % (n, ssctrl, ssstat), end="")
                    for i in range(0,n_address_comparator_pairs*2):
                        if bit(ssctrl,i):
                            ac_used |= (1 << i)
                            print(" AC%u" % i, end="")
                    for i in range(0,n_address_comparator_pairs):
                        if bit(ssctrl,i+16):
                            ac_used |= (3 << (i*2))
                            print(" AC%u..AC%u" % (i*2, i*2+1), end="")
                    print()
                # show address range comparators
                for n in range(0,n_address_comparator_pairs*2):
                    if not o_show_all_status and not bit(ac_used,n):
                        continue
                    aval = d.read64(0x400+n*8)
                    atyp = d.read64(0x480+n*8)
                    print("  address comparator #%u: value=0x%016x type=0x%08x" % (n, aval, atyp), end="")
                    print(" %s" % ('|'.join(blist("EL",bits(atyp,12,3),n=3,inv=True))), end="")
                    print(" %s" % ["inst", "load", "store", "load/store"][bits(atyp,0,2)], end="")
                    print()
                # show counters                
                for n in range(0,n_counters):
                    reload_value = d.read32(0x140+n*4)
                    control = d.read32(0x150+n*4)
                    value = d.read32(0x160+n*4)
                    if value == 0 and control == 0:
                        # if it's never counting or reloading, probably never programmed
                        continue
                    # print counter details: mostly programming, but the value is current status
                    print("  counter #%u: value:%u reload:%u control:0x%08x" % (n, value, reload_value, control), end="")
                    print(" count:%s reload:%s" % (esel_str(bits(control,0,8)), esel_str(bits(control,8,8))), end="")
                    if bit(control,16):
                        print(" self-reload", end="")
                    if bit(control,17):
                        print(" chain", end="")
                    print()
                if n_seqstates > 1:
                    print("  seqreset: %s" % esel_str(d.read32(0x118)))
                    for sr in range(0,n_seqstates-1):
                        seqev = d.read32(0x100+sr*4)
                        sf = bits(seqev,0,8)
                        sb = bits(seqev,8,8)
                        if sf:
                            print("  seq%u -> seq%u: %s" % (sr, sr+1, esel_str(sf)))
                        if sb:
                            print("  seq%u <- seq%u: %s" % (sr, sr+1, esel_str(sb)))
                    print("  seqstate: %u" % d.read32(0x11C))    # current status
                # probe for integration regs
                if True:
                    any_integration_reg = False
                    for a in range(0xE80,0xFA0,4):                        
                        r = d.read32(a)
                        if r != 0:
                            print("  @%03x: 0x%08x" % (a,r))
                            any_integration_reg = True
                    if not any_integration_reg:
                        print("  no integration registers set")
            else:
                # TBD show older ETMs
                pass
        elif d.is_arm_architecture(ARM_ARCHID_ELA):
            n_trig_states = bits(devid1,16,8)
            group_width = (bits(devid1,8,8)+1)*8
            if bits(devid2,8,8):
                comp_width = (bits(devid2,8,8)+1)*8
            else:
                comp_width = group_width
            ctrl = d.read32(0x000)
            timectrl = d.read32(0x004)
            tssr = d.read32(0x008)
            pta = d.read32(0x010)
            print("  %s" % ["disabled (programming permitted)","enabled"][bit(ctrl,0)])
            def action_str(ac):
                return "0x%08x (trace:%u stopclock:%u trigout:0x%x elaout:0x%x)" % (ac, bit(ac,3), bit(ac,2), bits(ac,0,2), bits(ac,4,4))
            print("  timestamp: 0x%08x (%s)" % (timectrl, ["disabled","enabled"][bit(timectrl,16)]))
            print("  PTA: %s" % (action_str(pta)))
            n_comp_words = comp_width // 32
            def print_words(d, off, n):
                for j in range(n):
                    w = n - 1 - j
                    print(" %08x" % (d.read32(off + (w*4))), end="")
            # Show the rules for each trigger state. Each rule has a matching condition and an action.
            for i in range(0,n_trig_states):
                b = i*0x100
                print("  trigger state #%u:" % i)
                print("    group:%u ctrl:0x%08x" % (d.read32(b+0x100),d.read32(b+0x104)))
                print("    ext: mask:%08x comp:%08x countcomp:%08x" % (d.read32(b+0x130),d.read32(b+0x134),d.read32(b+0x120)))
                print("    mask:", end="")
                print_words(d, b+0x140, n_comp_words)
                print()
                print("    comp:", end="")
                print_words(d, b+0x180, n_comp_words)
                print()
                # Now show what happens when the trigger matches
                ac = d.read32(b+0x10C)
                print("    action:    %s  next:0x%x" % (action_str(ac),d.read32(b+0x108)))
                print("    altaction: %s  altnext:0x%x" % (action_str(d.read32(b+0x114)),d.read32(b+0x110)))
            # Reading CTSR takes a snapshot into CCVR and CAVR
            if o_show_sample:
                ctsr = d.read32(0x020)
                ccvr = d.read32(0x024)
                cavr = d.read32(0x028)
                print("  state:")
                # Trigger state is one-hot in CTSR. ELA-500 TRM says that the trigger state is RAZ when CTRL.RUN=0, but it appears not to be
                print("    %s" % ["tracing","stopped"][bit(ctsr,31)])
                soh = bits(ctsr,0,n_trig_states)
                print("    state:%s" % decode_one_hot(soh,n_trig_states))
                print("    counter:0x%x" % ccvr)
                print("    captid:0x%x" % d.read32(0x02C))
            ram_addr_width = bits(devid,8,8)    # SRAM address width in bits, e.g. 6 bits => 64 entries
            n_ram_entries = 1 << ram_addr_width
            rwa = d.read32(0x048)    # Next entry to be written
            if not (rwa & 0x80000000):
                # RAM has not wrapped
                ram_lo = 0
                ram_n = rwa
            else:
                # RAM has wrapped
                ram_lo = rwa & 0x7FFFFFFF
                ram_n = n_ram_entries
            print("  RAM read:0x%08x write:0x%08x: %u entries from %u" % (d.read32(0x040), rwa, ram_n, ram_lo))
            if o_show_all_status:
                # Show contents of trace SRAM: see ELA-500 2.4.4 "Trace SRAM format"
                # We can either dump out the raw data from entry 0, or we can dump out the range indicated by RWAR
                saved_rra = d.read32(0x040)
                n_group_words = group_width // 32
                might_be_scrambled = (bits(devid,25,4) == 1)
                d.write_enable()
                # Set RRA to the beginning of the internal RAM. "Writes to the RRA cause
                # the trace SRAM data at this address to be transferred into the holding register.
                # After the SRAM read data is transferred to the holding register,
                # RRA increments by one."
                d.write32(0x040,ram_lo)
                # So if we read it back now, it would read back as 1.
                # Read out whole captured lines from the RAM.
                for i in range(ram_n):
                    print("    %3u @%04x:" % (i, ((ram_lo+i)%n_ram_entries)), end="")
                    # "The first read of the RRD after an RRA update returns the trace data header byte value"
                    header = d.read32(0x044)
                    print(" [%08x]" % header, end="")
                    rtype = bits(header,0,2)        # 1: captured group, 2: timestamp
                    rstate = bits(header,2,3)       # trigger state when captured
                    roverwrite = bit(header,5)      # data was overwritten by TS4
                    rcount = bits(header,6,2)
                    print(" c:%u st:%u" % (rcount, rstate), end="")    # trigger state shows what was traced, look at SIGSEL<rstate>
                    data = []
                    for j in range(n_group_words):
                        dat = d.read32(0x044)
                        data.append(dat)       # automatically increments RRA
                    if rtype == 2:
                        print(" -- timestamp: %08x%08x --" % (data[1], data[0]), end="")
                        if len(data) >= 2:
                            # Timestamp should be padded with zeroes. But if this is an uninitialized
                            # SRAM buffer it might contain anything.
                            if data[2] != 0x00000000:
                                print(" ** timestamp not padded with zeroes", end="")
                    else:
                        # Print data, high word first
                        for dat in reversed(data):
                            print(" %08x" % dat, end="")
                        dbits = 0
                        for (di, dat) in enumerate(data):
                            dbits = dbits | (dat << (di*32))
                    print()
                # After reading all the lines, the RRA is already 0, and reaing the last word via RRD
                # causes the next line (i.e. the very first one) to be read to the holding register,
                # and the RRA then auto-increments to 1. So that's what we expect to see here.
                assert d.read32(0x040) == ((ram_lo+ram_n+1) % n_ram_entries), "RRA should have wrapped: 0x%08x" % d.read32(0x040)
                d.write32(0x040,saved_rra)
        elif d.is_arm_architecture(ARM_ARCHID_MEMAP):
            idr = d.read32(0xDFC)
            aptype = bits(idr,0,4)
            csw = d.read32(0xD00)
            print("  CSW: 0x%08x (%s)" % (csw, ["disabled","enabled"][bit(csw,6)]))
            bprot = bits(csw,24,7)
            btype = bits(csw,12,4)
            if bit(csw,7):
                print("  Transfer in progress")
            if bits(csw,8,4) != 0:
                print("  Barrier support enabled")
            if bit(csw,16):
                print("  Errors are not passed upstream")
            if bit(csw,17):
                print("  Stop on error")
            print("  Type/Prot=0x%x/0x%x" % (btype, bprot), end="")
            # Recommendations for bus-specific CSW fields are defined by ADI Appendix E
            if aptype == 4:
                # AXI
                print(" %s" % (["S","NS"][bit(bprot,5)]), end="")
                print(" %s" % (["data","code"][bit(bprot,6)]), end="")
                print(" %s" % (["unpriv","priv"][bit(bprot,4)]), end="")
                print(" AxCACHE:0x%x" % bits(bprot,0,4), end="")
            elif aptype == 6:
                # APB4
                print(" %s" % (["S","NS"][bit(bprot,5)]), end="")
            print()
            print("  TAR: 0x%08x" % (d.read32(0xD04)))
            if (d.read32(0xD24) & 1) != 0:
                print("  Error response logged")
        elif d.arm_part_number() in [0x907, 0x961, 0x9e8, 0x9e9, 0x9ea]:
            # CoreSight SoC400 ETB or TMC trace buffer or SoC600 TMC.
            # Trace buffer management is complicated by the variety of design-time
            # and programming-time configuration choices:
            #   1. Product: integration-time product selection, from e.g.
            #     - Arm CoreSight SoC-400 ETB (0x907)
            #     - Arm CoreSight TMC (0x961)
            #     - Arm CoreSight SoC-600 TMC (0x9e8, 0x9e9, 0x9ea)
            #   2. Configuration: integration-time choices
            #      for the old ETB, there wasn't much choice, but for a TMC, it can be
            #      configured as a trace router (ETR, with an AXI bus master interface)
            #      or as an ETB with internal buffer or ETF FIFO
            #     - for 0x961 TMC, the configuration is indicated by a register
            #     - for SoC-600 TMC, the configuration is indicated by part id
            #     - other design-time configuration includes bus width, ETB buffer size etc.
            #   3. Mode: programming-time choices
            #     - is the TMC in circular-buffer mode or draining mode
            #     - is the TMC mapping its buffer linearly or by scatter-gather
            #     - is trace formatting enabled
            #   4. State: the state the buffer is currently in
            #     - e.g. Running, Stopped, Disabled
            is_TMC = d.is_arm_part_number(0x961)
            if is_TMC:
                # Check whether ETR, ETB or ETF
                configtype = (devid >> 6) & 3
                is_ETR = (configtype == 1)
                is_ETF = (configtype == 2)
            else:
                is_ETR = False
                is_ETF = False
            # Mode is a programming choice: e.g. is it set up as a circular buffer or a draining FIFO
            mode = d.read32(0x028) & 3
            print("  mode:           %s" % ["circular buffer","software FIFO","hardware FIFO","?3"][mode])
            if is_ETR:
                axi_control = d.read32(0x110)
                print("  AXI control:    0x%08x" % axi_control)
                scatter_gather = bit(axi_control,7)     # n/a in SoC-600 TMC?
                etr_memory = d.read64(0x118)    # DBALO, DBAHI
                if not scatter_gather:
                    # base address of trace buffer in system memory
                    print("  buffer address: 0x%x" % etr_memory)
                    print("  buffer size:    0x%x" % (d.read32(0x004)*4))
                else:
                    # address of first page table entry in linked list
                    print("  scatter-gather table: 0x%x" % etr_memory)
                    # ideally we'd read the scatter-gather table from physical memory,
                    # to show where the ETR was actually writing the data
            ctl = d.read32(0x020)
            TraceCaptEn = bit(ctl, 0)
            print("  control:        0x%08x  %s" % (ctl, bits_set(ctl,{0:"TraceCaptEn"})))
            ffcr = d.read32(0x304)
            ffcr_map = {0:"formatting",1:"format-triggers",4:"FOnFlIn",5:"flush-on-trigger",6:"FlushMan",12:"stop-on-flush",13:"stop-on-trigger"}
            print("  flush control:  0x%08x  %s" % (ffcr, bits_set(ffcr,ffcr_map)))
            # from here, report current status
            ffsr = d.read32(0x300)
            status = d.read32(0x00C)    # STS
            print("  status:         0x%08x" % status, end="")
            if not is_TMC:
                print("  %s" % bits_set(status,{0:"Full",1:"Triggered",2:"AcqComp",3:"FtEmpty"}))
                print("  state:         %s" % ["disabled","enabled"][TraceCaptEn])
            else:
                print("  %s" % bits_set(status,{0:"Full",1:"Triggered",2:"TMCready",3:"FtEmpty",4:"Empty",5:"MemErr"}))
                TMCReady = bit(status,2)
                if not TraceCaptEn:
                    if not TMCReady:
                        tmcstate = "Disabling (CTL=0x%08x, STS=0x%08x, FFCR=0x%08x, FFSR=0x%08x, RRP=0x%08x, RWP=0x%08x)" % (d.read32(0x020), status, ffcr, ffsr, d.read32(0x014), d.read32(0x018))
                    else:
                        tmcstate = "Disabled"
                else:
                    if not TMCReady:
                        if mode == 0:
                            # Draining only happens in circular buffer mode
                            tmcstate = "Running/Stopping/Draining"
                        else:
                            tmcstate = "Running/Stopping"
                    else:
                        tmcstate = "Stopped"
                print("  state:          %s" % tmcstate)
            if is_ETR:
                rwp = d.read32x2(0x03C,0x018)
            else:
                rwp = d.read32(0x018)
            print("  write pointer:  0x%x" % rwp)
            if TraceCaptEn:
                print("  buffer fill level (current): 0x%08x" % d.read32(0x030))
            if False:
                # Reading the latched fill level returns the max fill level since
                # it was last read, and also updates with the current fill level.
                print("  buffer fill level (latched): 0x%08x" % d.read32(0x02C))
            integration_regs = [0xEF0, 0xEF4, 0xEF8]
            if is_ETF:
                integration_regs = [0xED0, 0xED4, 0xED8, 0xEDC] + integration_regs
        elif d.is_cti():
            # CoreSight CTI or core CTI
            n_trigs = (devid>>8) & 0xff
            n_channels = (devid>>16) & 0xf
            # Pulsed trigger inputs will generally read as 0. We could read the latched
            # value from the integration-test input register, but that's destructive.
            print("  CTI %s" % (["disabled","enabled"][bit(d.read32(0x000),0)]))
            # Show the channel-to-trigger connections and the system gate
            for c in range(0,n_channels):
                cin = d.read32(0x020 + c*4)
                cout = d.read32(0x0A0 + c*4)
                if cin:
                    print("  channel #%u <- %s" % (c, binstr(cin,n_trigs)))
                if cout:
                    print("  channel #%u -> %s" % (c, binstr(cout,n_trigs)))
            print("  channel gate:    %s" % (binstr(d.read32(0x140),n_channels)))
            print("  trigger inputs:  %s" % (binstr(d.read32(0x130),n_trigs)))
            if o_show_sample:
                print("    latched:       %s" % (binstr(d.read32(0xEF8),n_trigs)))
            print("  trigger outputs: %s" % (binstr(d.read32(0x134),n_trigs)))
            print("  channel inputs:  %s" % (binstr(d.read32(0x138),n_channels)))
            print("  channel outputs: %s" % (binstr(d.read32(0x13C),n_channels)))
        elif d.arm_part_number() in [0x908, 0x9eb]:
            # CoreSight funnel
            ctrl = d.read32(0x000)
            print("  ports enabled: %s" % (binstr((ctrl & 0xff),in_ports)))
            print("  hold time: %u" % bits(ctrl,8,4))
            if bit(d.read32(0xEF0), 1):
                print("  downstream requested flush")
            integration_regs = [0xEF0, 0xEF4, 0xEF8]
        elif d.arm_part_number() in [0x909, 0x9ec]:
            # CoreSight replicator
            for rep_port in [0,1]:
                rep_filter = d.read32(0x000 + rep_port*4)
                print("  id filter port %u: 0x%x" % (rep_port, rep_filter), end="")
                if rep_filter == 0:
                    print(" (all IDs enabled)", end="")
                print()
            integration_regs = [0xEF8]
        elif d.is_arm_part_number(0x912) or d.is_arm_part_number(0x9e7):
            # CoreSight TPIU
            ffcr = d.read32(0x304)
            print("  FFCR:   0x%08x" % ffcr)
            ffsr = d.read32(0x300)
            print("  FFSR:   0x%08x" % ffsr)
        elif d.is_arm_part_number(0x9ee):
            # CoreSight Address Translation Unit (CATU)
            catu_control = d.read(0x000)
            catu_mode = d.read(0x004)
            catu_status = d.read(0x100)
            print("  %s" % ["disabled","enabled"][catu_control&1])
            print("  %s" % ["pass-through","translate"][catu_mode&1])
            if catu_status & 0x0001:
                print("  address error")
            if catu_status & 0x0010:
                print("  AXI error")
            if catu_status & 0x0100:
                print("  ready")
        else:
            # unknown device - can't show status
            pass

        if o_show_sample:
            pc = 0
            cxid = None
            cxid_el2 = None
            vmid = None
            if d.is_arm_architecture_core():
                # Core debug interface
                if bits(devid,0,4):
                    pc = d.read32x2(0x0AC,0x0A0)       # EDPCSR: not consecutive
                    cxid = d.read32(0x0A4) 
                    vmid = d.read32(0x0A8)
            elif d.is_arm_architecture(ARM_ARCHID_PMU):
                if bits(devid,0,4):
                    pc = d.read32x2(0x204,0x200)       # PMPCSR
                    cxid = d.read32(0x208)             # PMCID1SR
                    cxid_el2 = d.read32(0x22C)         # PMCID2SR
                    vmid = d.read32(0x20C)             # PMVIDSR
            if pc:
                print("  PC: 0x%x EL%u %sS" % (bits(pc,0,56), bits(pc,61,2), "N"[0:bit(pc,63)]))
                print("  CXID_EL1: 0x%08x" % cxid)
            if cxid_el2 is not None:
                print("  CXID_EL2: 0x%08x" % cxid_el2)
            if vmid is not None:
                print("  VMID: 0x%08x" % vmid)

        if o_show_integration:
            for r in integration_regs:
                print("  r%X = 0x%x" % (r, d.read32(r)))

    @staticmethod
    def show_device(d):
        """
        Show device details on a single line.
        """
        rev = (d.PIDR >> 20) & 15       # PIDR2.REVISION
        patch = (d.PIDR >> 28) & 15     # PIDR3.REVAND
        print("%s " % (d.address_string()), end=" ")
        # Note that Arm CoreSight SoC uses PIDR2.REVISION to count successive
        # major/minor releases of each block. The overall release of CoreSight SoC
        # can only be deduced from the combination of block releases seen.
        # For example SoC-400 r3p1 has funnel rev r1p0 indicated by REVISION=2,
        # while SoC-400 r3p2 has funnel rev r1p1 indicated by REVISION=3.
        print("  0x%03x 0x%03x r%u.%u  " % (d.jedec_designer, d.part_number, rev, patch), end="")
        if (d.CIDR & 0xffff0fff) != 0xb105000d:
            if d.CIDR:
                print("unexpected CIDR: 0x%08x " % d.CIDR, end="")
            else:
                print("no CIDR ", end="")
        if d.is_arm_part() and d.part_number in arm_part_numbers:
            part_string = arm_part_numbers[d.part_number]
        elif d.is_rom_table():
            part_string = ""      # ROM table part numbers tend not to mean much
        else:
            part_string = "<unknown part>"
        print("%-22s" % part_string, end="")
        if d.is_rom_table():            
            print("ROM table")
        elif d.is_coresight_timestamp():
            print("CoreSight timestamp generator")
            if o_show_programming:
                ctrl = d.read32(0x000)
                print("  %s" % ["disabled","enabled"][bit(ctrl,0)])
                print("  frequency: %uHz" % d.read32(0x020))
                test_time = 0.01
                count = d.read64counter(0x00C,0x008)
                time.sleep(test_time)
                count2 = d.read64counter(0x00C,0x008)
                print("  time: %x" % count)
                print("  time: %x" % count2)
                print("  measured frequency: %uMHz" % int((count2-count)/test_time/1.0e6))
                for i in range(0, 10):
                    print("    %08x %08x" % (d.read32(0x00C), d.read32(0x008)))
        elif d.is_coresight():
            show_coresight_device(d)
        elif d.device_class() == 0xF:
            # might be worth reading DEVARCH even though Class 0xF doesn't guarantee to have it (and it might not be readable
            # could also look up part number
            print("generic PrimeCell peripheral: DEVARCH=0x%08x DEVAFF=0x%08x" % (d.read32(0xFBC), d.read32(0xFA8)))
            # might be Arm RAS architecture
            if False and d.read32(0xFBC) == 0x47700a00:
                print("  0xE80: %08x" % d.read32(0xE80))
                print("  0xFC8: %08x" % d.read32(0xFC8))
                for a in range(0,0x030,8):
                    print("  0x%03x: %08x" % (a, d.read32(a)))
        else: 
            print("class:%u" % (d.device_class()))



def show_coresight_device(d):
    CSROM.show_coresight_device(d)


def show_device(d):
    CSROM.show_device(d)


def topology_detection_atb(atb_devices, topo):
    """
    Run the CoreSight topology detection procedure as described in
    [CoreSight Architecture 2.0] D6.4, Detection Algorithm.
    We put the devices into integration mode, and toggle integration
    registers that cause signal changes (on ATVALID and ATREADY lines)
    to be observable in other devices.
    """
    print("\nATB topology detection")
    # Set integration mode. Ideally, we would quiesce and disable each device,
    # using a device-specific procedure - e.g. wait for a trace buffer formatter
    # to drain. For the time being, we assume that the CoreSight subsystem
    # has not been in use.
    def enable_funnel_input(d, n):
        # Funnels don't have separate bits in the ingration register for
        # each input ATB port. Instead, you have to select the input.
        assert n < d.atb_in_ports()
        d.write32(0x000, ((d.read32(0x000) & 0xFFFFFF00) | (1<<n)))
    def set_ATVALIDM(d, n, flag):
        # Set ATVALID on a downstream ATB interface.
        reg = 0xEF8
        mask = 0x01
        if d.is_arm_part_number(0x9eb):
            # CSSoC-600 funnel is different from old one
            (reg, mask) = (0xEFC, 0x01)
        elif d.is_arm_part_number(0x9ec):
            # CSSoC-600 replicator is different from old one
            (reg, mask) = (0xEF8, (1 << (n*2)))
        elif d.is_replicator():
            # A replicator has two ATB output ports, but controlled from the same register
            reg = 0xEFC
            mask = (1 << (n*2))
        elif d.is_coresight_device_type(2,3):
            # ETF
            reg = 0xEDC
        elif d.is_coresight_device_type(3,1):
            # ETM
            if d.atb_out_ports() == 2:
                # ETMv4 with separate instruction and data trace ports.
                # R-profile or M-profile core. 0xEFC is for instructions.
                reg = [0xEFC, 0xEF8][n]
            else:
                reg = 0xEF8
                etmver = bits(d.read32(0x1E4),8,4)
                if etmver >= 4:
                    # Some ETMv4 implementations have the integration reg
                    # at 0xEFC rather than 0xEF8.
                    # We set both, just in case. It should be harmless.                
                    d.write32(0xEFC, flag*mask, check=False)
                    # as noted above, we set both: we now falll through to set 0xEF8.
        elif d.is_arm_architecture(ARM_ARCHID_ELA):
            reg = 0xEF4      # ITATBCTR0
        else:
            reg = 0xEF8
        if False and flag:
            print("    set ATVALIDM: 0x%03x %08x" % (reg, mask))
        d.write32(reg, flag*mask, check=False)
    def set_ATREADYS(d, n, flag):
        if d.is_funnel():
            enable_funnel_input(d, n)
        if d.is_arm_part_number(0x9eb):
            (reg, mask) = (0xEF4, 0x01)
        elif d.is_replicator():
            (reg, mask) = (0xEFC, 0x10)
        else:
            (reg, mask) = (0xEF0, 0x01)
        d.write32(reg, flag*mask, check=False)
    def get_ATVALIDS(d, n):
        if d.is_funnel():
            enable_funnel_input(d, n)
        (reg, mask) = (0xEF8, 0x01)
        if d.is_arm_part_number(0x9eb):
            # CSSoC-600 funnel
            (reg, mask) = (0xEFC, 0x01)
        elif d.is_arm_part_number(0x9ec):
            # CSSoC-600 replicator
            (reg, mask) = (0xEFC, 0x08)
        elif d.is_replicator():
            mask = 0x08
        return (d.read32(reg) & mask) != 0
    for d in atb_devices:
        d.unlock()
        d.set_integration_mode(True)
        def clear_integration_regs(d):
            d.write32(0xEF0, 0, check=False)
            if d.is_arm_part_number(0x9eb):
                d.write32(0xEF4, 0, check=False)
            d.write32(0xEF8, 0, check=False)
            d.write32(0xEFC, 0, check=False)
            if d.is_coresight_device_type(2,3):  # ETF
                d.write32(0xEDC, 0, check=False)
        if d.is_funnel():
            for i in range(0, d.atb_in_ports()):
                enable_funnel_input(d, i)
                clear_integration_regs(d)
            d.clr32(0x000, 0xFF)
        else:
            clear_integration_regs(d)
    # For each ATB output port, assert its ATVALIDM and look for it to
    # be observed as ATVALIDS on an input port on one or more downstream devices.
    # Where there is a non-programmable funnel in between, we might have several
    # ATB outputs apparently connected to one input.
    # Where there is a non-programmable replicator in between, we might see
    # the ATVALIDM observed on several input ports.
    for dm in atb_devices:
        if dm.atb_out_ports():
            print("ATB scan... ", end="")
            c.show_device(dm)
        for mp in range(0, dm.atb_out_ports()):
            n_downstream = 0
            set_ATVALIDM(dm, mp, 1)
            # Scan all other devices to see if they are downstream of this one
            for ds in atb_devices:
                if ds == dm:
                    continue    # No loopbacks in ATB, so no point checking
                if not ds.atb_in_ports():
                    continue
                if False:       # Debugging
                    print("    ", end="")
                    c.show_device(ds)
                    print("    ", end="")
                    for r in range(0xEF0, 0xF00, 4):
                        print("  0x%03x: %08x " % (r, ds.read32(r)), end="")
                    print()
                for sp in range(0, ds.atb_in_ports()):
                    if get_ATVALIDS(ds, sp):
                        def jport(d, p):
                            return [("0x%x" % d.base_address), p]
                        ld = {"type": "ATB", "from": jport(dm, mp), "to": jport(ds, sp)}
                        topo["links"].append(ld)
                        n_downstream += 1
                        print("  %u->%u  " % (mp, sp), end="")
                        c.show_device(ds)   # will be shown indented
                        set_ATREADYS(ds, sp, 1)
                        set_ATVALIDM(dm, mp, 0)
                        set_ATVALIDM(dm, mp, 1) # ready for next time
                        break
                if ds.is_funnel():
                    d.clr32(0x000, 0xFF)
            set_ATVALIDM(dm, mp, 0)
            if not n_downstream:
                print("  %u: no downstream device found" % (mp))
    # Finally, put the devices back into production mode.
    for d in atb_devices:
        d.set_integration_mode(False)
        d.lock()
    # At this point, the system isn't guaranteed to be in a usable
    # (mission-mode) state. In practice, it often works.
    print("ATB topology detection complete.")


class TopologyDetectionCTI:
    """
    CTI topology detection.
    For each device, assert its outputs and search other devices for corresponding inputs.

    For core-affine CTIs (indicated with DEVAFF) the relationship between a core and its CTI is not discoverable
    via topology detection. Instead the relationship is fixed and documented in the architecture spec
    (for v8 this is H5.4), or the CPU or SU TRM:

    Core CTI inputs:
      0: cross-halt
      1: PMU overflow
      2: SPE sample trigger event (n.b. there is no way externally to detect if SPE is present)
      3: reserved
      4-7: ETM trace output
      8-9: ELA trigger output (imp def)
    Core CTI outputs:
      0: debug request
      1: restart
      2: GIC generic CTI interrupt
      3: reserved
      4-7: ETM external input
      8-9: ELA trigger input (imp def)
    """
    def __init__(self, devices, topo):
        self.devices = [d for d in devices if self.has_triggers(d)]
        self.out_map = {}
        self.in_map = {}

    @staticmethod
    def pin_out(d):
        # Yield the ouptut triggers: output assert register and bit.
        if d.arm_part_number() in [0x907, 0x961, 0x9e8, 0x9e9, 0x9ea]:
            yield ("ACQCOMP", 0xEE0, 0)
            yield ("FULL", 0xEE0, 1)
        elif d.is_coresight_device_type(3,1):
            # ETM
            for i in range(0, 4):
                yield ("ETMEXTOUT%u" % i, 0xEDC, i+8)
        elif d.is_core_debug():
            yield ("DBGCROSS", None, None)
        elif d.is_coresight_device_type(6,1):
            yield ("OVERFLOW", None, None)
        elif d.is_arm_architecture(ARM_ARCHID_STM):
            yield ("TRIGOUTSPTE", 0xEE8, 0)
            yield ("TRIGOUTSW", 0xEE8, 1)
            yield ("TRIGOUTHETE", 0xEE8, 2)
            yield ("ASYNCOUT", 0xEE8, 3)
        elif d.is_arm_architecture(ARM_ARCHID_ELA):
            yield ("CTTRIGOUT0", 0xEE8, 0)
            yield ("CTTRIGOUT1", 0xEE8, 1)
        elif d.is_cti():
            n_triggers = ((d.read32(0xFC8)>>8)&0xff)
            # Testing core-affine CTIs currently disabled to avoid halting our own core
            if d.is_affine_to_core():
                ireg = None
            else:
                ireg = 0xEE8 
            for i in range(0, n_triggers):
                yield ("TRIGOUT%u" % i, ireg, i)
        else:
            pass

    @staticmethod
    def pin_in(d):
        # Yield the input sensing register and bit, and also the input acknowledge register if present
        # We assume bit position in sense register and ack register is the same.
        if d.is_arm_part_number(0x907) or d.is_arm_part_number(0x961) or d.is_arm_part_number(0x912):
            yield ("TRIGIN", 0xEE8, 0, 0xEE4)
            yield ("FLUSHIN", 0xEE8, 1, 0xEE4)
        elif d.is_coresight_device_type(3,1):
            # ETM - integration registers not architected, may be specific to core, this is a guess
            #etmid5 = d.read32(0x1F4)
            #n_extin = bits(etmid5,0,9)
            n_extin = 4        # ignore all the PMU inputs
            for i in range(0, n_extin):
                yield ("ETMEXTIN%u" % i, 0xEE0, i, None)
        elif d.is_core_debug():
            yield ("DBGREQ", None, None, None)
            yield ("DBGRST", None, None, None)
        elif d.is_arm_architecture(ARM_ARCHID_ELA):
            yield ("CTTRIGIN0", 0xEF8, 0, None)
            yield ("CTTRIGIN1", 0xEF8, 1, None)
        elif d.is_cti():
            n_triggers = ((d.read32(0xFC8)>>8)&0xff)
            if d.is_affine_to_core():
                ireg = None
            else:
                ireg = 0xEF8
            for i in range(0, n_triggers):
                yield ("TRIGIN%u" % i, ireg, i, 0xEE0)
        else:
            pass

    def has_triggers(self, d):
        return d.is_cti() or len(list(self.pin_out(d))) > 0 or len(list(self.pin_in(d))) > 0

    def preamble(self):
        # Put all devices into integration mode, and do the master preamble
        for d in self.devices:
            c.show_device(d)
            d.unlock()
            d.set_integration_mode(True)
            for (name, reg, b) in self.pin_out(d):
                if reg is not None:
                    d.clr32(reg, 1<<b)
        # Slave preamble, and check if any input pins are already asserted...
        for ds in self.devices:
            for (sname, sreg, sb, inack) in self.pin_in(ds):
                if sreg is None:
                    continue
                if inack is not None:
                    d.clr32(inack, 1<<sb)
                if bit(ds.read32(sreg), sb):
                    print("%s %s already asserted" % (ds, sname))

    def detect(self):
        print("\nCTI topology detection")
        self.preamble()
        print("CTI outputs:")
        for dm in self.devices:
            if len(list(self.pin_out(dm))):
                self.detect_master(dm)
        self.postamble()
        self.show_inputs()
        print("CTI topology detection complete.")

    def add(self, dm, mname, ds, sname):
        print("    %s -> %s %s" % (mname, ds, sname))
        mkey = (dm, mname)
        skey = (ds, sname)
        if mkey in self.out_map:
            print("       multiple outputs!")
        if skey in self.in_map:
            (da, aname) = self.in_map[skey]
            print("       multiple inputs: already connected to %s %s" % (da, aname))
        self.out_map[mkey] = skey
        self.in_map[skey] = mkey

    def detect_master(self, dm):
        print("  %s" % dm)
        if dm.is_affine_to_core():
            if dm.is_cti():
                # Add the trigger connections defined in the architecture (non discoverable)
                self.add(dm, "TRIGOUT0", dm.affine_core, "DBGREQ")
                self.add(dm, "TRIGOUT1", dm.affine_core, "DBGRST")
                etm = dm.affine_device("ETM")
                for i in range(0, 4):
                    self.add(dm, "TRIGOUT" + str(i+4), etm, "ETMEXTIN" + str(i))
            elif dm.is_core_debug():
                self.add(dm, "DBGCROSS", dm.affine_device("CTI"), "TRIGIN0")
                # TRIGIN2 is the SPE sample event - but there's no non-invasive way to detect SPE
            elif dm.is_coresight_device_type(6,1):
                self.add(dm, "OVERFLOW", dm.affine_device("CTI"), "TRIGIN1")
            elif dm.is_coresight_device_type(3,1):
                for i in range(0, 4):
                    self.add(dm, "EXTMEXTOUT" + str(i), dm.affine_device("CTI"), "TRIGIN" + str(i+4))
            return
        for (mname, mreg, mb) in self.pin_out(dm):
            if mreg is None:
                continue
            mkey = (dm, mname)
            dm.set32(mreg, 1<<mb)
            for ds in self.devices:
                for (sname, sreg, sb, inack) in self.pin_in(ds):
                    if sreg is None:
                        continue
                    if bit(ds.read32(sreg), sb):
                        if inack is not None:
                            ds.set32(inack, 1<<sb)
                            ds.clr32(inack, 1<<sb)
                        self.add(dm, mname, ds, sname)
            dm.clr32(mreg, 1<<mb)
            if mkey not in self.out_map:
                print("    %s not connected" % (mname))

    def show_inputs(self):
        print("CTI inputs:")
        for ds in self.devices:
            if len(list(self.pin_in(ds))):
                print("  %s" % ds)
            for (sname, sreg, sb, inack) in self.pin_in(ds):
                skey = (ds, sname)
                if skey in self.in_map:
                    (dm, mname) = self.in_map[skey]
                    print("    %s <- %s %s" % (sname, dm, mname))
                else:
                    print("    %s not connected" % (sname))

    def postamble(self):
        for d in self.devices:
            d.set_integration_mode(False)
            d.lock()


def topology_detection_cti(devices, topo):
    d = TopologyDetectionCTI(devices, topo)
    d.detect()


def scan_rom(c, table_addr, recurse=True, detect_topology=False, detect_topology_cti=False, enable_timestamps=False):
    """
    Scan a ROM Table recursively, showing devices as we go.
    We can also use this to list a single device.
    """
    table = c.create_device_at(table_addr)
    c.show_device(table)
    if not table.is_rom_table():
        return
    n = 0
    devices = []
    ts = []
    for e in c.list_table(table, recurse=recurse):
        assert e.device is not None or e.is_inaccessible
        if e.device is not None:
            if e.device.is_coresight():
                devices.append(e.device)
            if e.device.is_coresight_timestamp():
                ts.append(e.device)
        n += 1
        if n <= o_max_devices:
            if e.device is None:
                print("@0x%x - device excluded from scan" % e.device_address())
            else:
                c.show_device(e.device)
        elif n == (o_max_devices+1):
            print("... further devices not shown.")
        else:
            pass
    if False:
        print("Affinity groups:")
        for ag in sorted(c.affinity_group_map.values()):
            print("  %s" % ag)
            for (typ, d) in ag.devices.items():
                print("    %-5s %s" % (typ, d))
    # Prepare to generate a topology JSON file, that can be used to create
    # a Linux device tree.
    atb_devices = []
    for d in devices:
        if d.atb_in_ports() or d.atb_out_ports():
            atb_devices.append(d)
    topo = {"devices": [], "links": []}
    for d in atb_devices + ts:
        dd = {
            "address": "0x%x" % d.base_address
        }
        if d.is_coresight_timestamp():
            dd["type"] = [0,1]     # our convention for timestamp devices
        else:
            dd["type"] = list(d.coresight_device_type())
        if d.is_coresight_device_type(3,1):
            # A CPU trace source of some kind. Not necessarily an ARM-architecture ETM.
            def get_etm_architecture(d):
                etm_version = None
                if d.is_arm_architecture(ARM_ARCHID_ETM):
                    etm_version = bits(d.read32(0x1E4),8,4)
                return etm_version
            etm_version = get_etm_architecture(d)
            if etm_version is not None:
                dd["architecture"] = ["ETM", etm_version]
        elif d.is_arm_architecture(ARM_ARCHID_STM):
            # STM: we should add the memory-mapped stimulus base address and size.
            pass
        topo["devices"].append(dd)
    if detect_topology:
        topology_detection_atb(atb_devices, topo)
    if detect_topology_cti:
        topology_detection_cti(devices, topo)
    if enable_timestamps:
        n_found = 0
        print("Enabling global timestamps:")
        for d in ts:
            if d.is_coresight_timestamp():
                d.write_enable()
                n_found += 1
                print("  Timestamp at 0x%x: " % d.base_address, end="")
                if (d.read32(0x000) & 0x01) != 0:
                    print("already enabled")
                elif d.set32(0x000, 0x01, check=True):
                    print("now enabled")
                else:
                    print("- failed to enable")
        if not n_found:
            print("No timestamp devices found")
    fn = "topology.json"
    f = open(fn, "w")
    json.dump(topo, f, indent=4)
    f.close()


def disable_stdout_buffering():
    sys.stdout = os.fdopen(sys.stdout.fileno(), "w", 0)


if __name__ == "__main__":
    # we don't use argparse because it's not available on Python 2.6
    def help():
        print("%s [--exclude=<addr>] [--status] <addr>" % sys.argv[0])
        print("  --exclude=<addr>     don't access device at this address")
        print("  --status             show device status as well as configuration")
        print("  --limit=<n>          stop scan after n devices")
        print("  --topology           detect ATB topology")
        print("  --topology-cti       detect CTI topology")
        print("  --enable-timestamps  enable global CoreSight timestamps")
        print("  --remote=<net>       access remote device via devmemd")
        print("  -v/--verbose         increase verbosity level")
        sys.exit(1)
    c = None
    done = False
    o_detect_topology = False
    o_detect_topology_cti = False
    o_enable_timestamps = False
    o_force_memap = False
    d_memap = None
    cssys = []
    def enable_devmemd(remote):
        (addr, port) = remote.split(':')
        global g_devmem
        g_devmem = DevMemRemote(addr, int(port))
    if 'DEVMEMD' in os.environ:
        enable_devmemd(os.environ['DEVMEMD'])
    for arg in sys.argv[1:]:
        if arg == "-v" or arg == "--verbose":
            o_verbose += 1
        elif arg == "-vv":
            o_verbose += 2
        elif arg == "-vvv":
            o_verbose += 3
        elif arg.startswith("--exclude="):
            eaddr = int(arg[10:],16)
            o_exclusions.append(eaddr)
        elif arg == "--status":
            o_show_programming = True
            o_show_sample = True
        elif arg == "--all-status":
            o_show_programming = True
            o_show_sample = True
            o_show_all_status = True
        elif arg == "--integration":
            o_show_integration = True
        elif arg == "--topology":
            o_detect_topology = True
        elif arg == "--topology-cti":
            o_detect_topology_cti = True
        elif arg == "--enable-timestamps":
            o_enable_timestamps = True
        elif arg == "--force-memap":
            o_force_memap = True
        elif arg == "--authstatus":
            o_show_authstatus = True
        elif arg.startswith("--limit="):
            o_max_devices = int(arg[8:])
        elif arg.startswith("--memap="):
            # CoreSight devices are accessed via a MEM-AP gateway in the main address space
            maddr = int(arg[8:], 16)
            ctop = CSROM()                     # The main physical address space
            cssys.append(ctop)
            memap_device = ctop.create_device_at(maddr, write=True)
            if memap_device.is_claimed(0x02):
                print("MEM-AP at 0x%x is claimed for external debug" % (maddr), file=sys.stderr)
                if not o_force_memap:
                    sys.exit(1)
            d_memap = MemAP(memap_device)      # The gateway device
        elif arg.startswith("--remote="):
            # Access physical memory on a network-connected target running devmemd
            enable_devmemd(arg[9:])
        elif arg == "--top-only":
            o_top_only = True
        else:
            if o_verbose >= 2:
                disable_stdout_buffering()
            table_addr = int(arg, 16)
            if c is None:
                try:
                    c = CSROM(memap=d_memap)
                    cssys.append(c)
                except:
                    if os.geteuid() != 0:
                        print("** failed to access CoreSight devices - try running as superuser")
                    else:
                        print("** failed to access CoreSight devices even as superuser")
                    sys.exit(1)
            scan_rom(c, table_addr, recurse=(not o_top_only), detect_topology=o_detect_topology, detect_topology_cti=o_detect_topology_cti, enable_timestamps=o_enable_timestamps)
            done = True
    if not done:
        help()
    if d_memap is not None:
        print("MEM-AP statistics for %s:" % d_memap)
        print("  target reads: %7u" % d_memap.n_client_reads)
        print("  target writes:%7u" % d_memap.n_client_writes)
        print("  MEM-AP reads: %7u" % d_memap.memap.n_reads)
        print("  MEM-AP writes:%7u" % d_memap.memap.n_writes)
    # Clear up all devices, e.g. unclaim and relock
    for cs in cssys:
        cs.close()
