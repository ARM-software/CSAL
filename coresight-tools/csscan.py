#!/usr/bin/python

"""
Scan the ROM table and report on CoreSight devices.
Also do ATB topology detection.

We report three levels of status:
  - the "hard wired" configuration selected at SoC design time
  - the "programming" configuration, e.g. address comparator settings
  - the actual status, e.g. busy/ready bits, values of counters etc.

To do:
  - CPU affinity and debug/PMU/ETM/CTI grouping
  - latest CoreSight architecture (mostly done)
  - ETMv3.x/PTF
  - SoC600: TMC, CATU
  - power requestors

Copyright (C) ARM Ltd. 2018.  All rights reserved.

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

import os, sys, struct, time, json

# We provide our own implementation of the mmap module which gives us
# more control over access to volatile registers.
import iommap as mmap


o_max_devices = 9999999
o_top_only = False
o_verbose = 0
o_show_programming = False
o_show_all_status = False
o_show_integration = False
o_show_authstatus = False
o_show_sample = False        # Destructive sampling
o_exclusions = []


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
# The CoreSight architecture defines
#   DEVARCH[15:0]:ARCHID  DEVARCH[19:16]:revision
# Conventionally Arm uses
#   DEVARCH[11:0]:architecture  DEVARCH[15:12]:major-rev  DEVARCH[19:16]:minor-rev

ARM_ARCHID_ETM      = 0x4a13
ARM_ARCHID_CTI      = 0x1a14
ARM_ARCHID_PMU      = 0x2a16
ARM_ARCHID_STM      = 0x0a63
ARM_ARCHID_ELA      = 0x0a75
ARM_ARCHID_ROM      = 0x0af7

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


class Device:
    """
    A single CoreSight device mapped by a ROM table (including ROM tables themselves).    
    """

    def __init__(self, cs, addr):
        self.we_unlocked = False
        self.m = None
        self.cs = cs
        assert (addr & 0xfff) == 0, "Device must be located on 4K boundary: 0x%x" % addr
        self.base_address = addr
        self.affine_core = None      # Link to the Device object for the core debug block
        self.map_is_write = False
        self.map()
        self.CIDR = (self.byte(0xFFC)<<24) | (self.byte(0xFF8)<<16) | (self.byte(0xFF4)<<8) | self.byte(0xFF0)
        self.PIDR = (self.byte(0xFD0) << 32) | (self.byte(0xFEC) << 24) | (self.byte(0xFE8) << 16) | (self.byte(0xFE4) << 8) | self.byte(0xFE0)
        self.jedec_designer = (((self.PIDR>>32)&15) << 7) | ((self.PIDR >> 12) & 0x3f)
        # The part number is selected by the component designer.
        self.part_number = self.PIDR & 0xfff
        self.devtype = None
        self.devarch = None
        self.is_checking = (o_verbose >= 1)
        if self.is_coresight():            
            arch = self.read32(0xFBC)
            if (arch & 0x00100000) != 0:
                self.devarch = arch
            self.devtype = self.read32(0xFCC)

    def map(self, write=False):
        # The mmap() base address must be a multiple of the OS page size.
        # But CoreSight devices might be on a smaller granularity.
        # E.g. devices might be at 4K boundaries but the OS is using 64K pages.
        # So we need to adjust the mmap address and size to page granularity.
        # This might mean we end up mapping the same page-sized range several
        # times for different 4K devices located within it.
        if self.m is None:
            self.mmap_offset = self.base_address % self.cs.page_size
            mmap_address = self.base_address - self.mmap_offset
            self.m = self.cs.map(mmap_address, write=write)

    def unmap(self):
        if self.m is not None:
            self.cs.unmap(self.m)
            self.m = None

    def write_enable(self):
        if not self.map_is_write:
            self.unmap()
            self.map(write=True)
            self.map_is_write = True

    def __str__(self):
        s = "%s @0x%x" % (self.cs_device_type_name(), self.base_address)
        if self.is_affine_to_core():
            s += " (core)"
        return s

    def __del__(self):
        if self.we_unlocked and self.cs.restore_locks:
            self.lock()
        self.unmap()

    def read32(self, off):
        """
        Read a device register. The register may be volatile, so we should take
        care to only read it once.
        """
        self.map()
        if o_verbose >= 2:
            print("  0x%x[%03x] R4" % (self.base_address, off), end="")
        off += self.mmap_offset
        raw = self.m[off:off+4]
        x = struct.unpack("I", raw)[0]
        if o_verbose >= 2:
            print("  = 0x%08x" % x)
        return x

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
        s = struct.pack("I", value)
        off += self.mmap_offset
        self.m[off:off+4] = s
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
        if o_verbose >= 2:
            print("  0x%x[%03x] W8 := 0x%016x" % (self.base_address, off, value))
        s = struct.pack("Q", value)
        off += self.mmap_offset
        self.m[off:off+8] = s

    def read32x2(self, hi, lo):
        # CoreSight (APB-connected) devices are generally 32-bit wide,
        # and 64-bit values are read as a pair of registers.
        # We assume that we're not dealing with volatile data (e.g. counters)
        # where special action is needed to return a consistent result.
        return (self.read32(hi) << 32) | self.read32(lo)

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

    def byte(self, off):
        self.map()
        if o_verbose >= 3:
            print("  0x%x[%03x] R1" % (self.base_address, off))
        off += self.mmap_offset
        x = ord(self.m[off:off+1])
        if o_verbose >= 3:
            print("  = 0x%02x" % x)
        return x

    def is_arm_part_number(self, n=None):
        return self.jedec_designer == JEDEC_ARM and (n is None or self.part_number == n)

    def arm_part_number(self):
        if self.jedec_designer == JEDEC_ARM:
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
        else:
            desc = "UNKNOWN (devtype = %s)" % (devtype)
        return desc

    def atb_in_ports(self):
        if self.is_funnel():
            return self.read32(0xFC8) & 15    # read DEVID
        elif self.coresight_device_type()[0] in [1,2]:
            return 1
        else:
            return 0

    def atb_out_ports(self):
        if self.is_replicator():
            return 2
        elif self.coresight_device_type()[0] in [2,3]:
            return 1
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
        return self.affine_core is not None

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
        return (self.read32(0xFB4) & 0x02) == 0

    def unlock(self):
        self.write_enable()
        if not self.is_unlocked():
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


class CSROM:
    """
    Container for the overall ROM table scan.
    Owns the mechanism by which we access physical memory - e.g. a
    mapping on to /dev/mem. Individual device mappings are owned by the
    device objects.
    """

    def __init__(self):
        self.fd = None
        self.page_size = os.sysconf("SC_PAGE_SIZE")
        try:
            # This may fail because not present or access-restricted.
            self.fd = open("/dev/mem", "r+b")
        except:
            try:
                self.fd = open("/dev/csmem", "r+b")
            except:
                #print("Can't access /dev/mem or /dev/csmem - are you running as superuser?")
                raise
        self.fno = self.fd.fileno()
        self.device_by_base_address = {}
        self.n_mappings = 0
        self.restore_locks = True 

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
        """
        try:
            if write:
                prot = (mmap.PROT_READ|mmap.PROT_WRITE)
            else:
                prot = mmap.PROT_READ
            m = mmap.mmap(self.fno, self.page_size, mmap.MAP_SHARED, prot, offset=addr)
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

    def device_at(self, addr, unlock=True):
        assert addr in self.device_by_base_address, "missing device at 0x%x" % addr
        d = self.device_by_base_address[addr]
        if unlock:
            d.unlock()
        return d

    def create_device_at(self, addr, rom_table_entry=None):
        assert not addr in self.device_by_base_address, "device at 0x%x already collected" % addr
        d = Device(self, addr)
        d.rom_table_entry = rom_table_entry
        self.device_by_base_address[addr] = d
        return d

    def list_table(self, td, include_empty=False, recurse=True):
        """
        Iterate (perhaps recursively) over a ROM Table, returning
        table entries which contain device objects.

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
                d = self.create_device_at(e.device_address(), rom_table_entry=e)
                e.device = d
                # Fix up device affinity - in the absence of anywhere better.
                # We could either do this using DEVAFF or heuristically.
                if d.is_core_debug():
                    d.affine_core = d      # affine to itself
                    d.affine_devices = {}
                    cpus_in_this_table.append(d)
                elif d.is_coresight_device_type(6,1):
                    # PMU: allocate to the first CPU that hasn't yet got a PMU
                    for c in cpus_in_this_table:
                        if "PMU" not in c.affine_devices:
                            d.affine_core = c
                            c.affine_devices["PMU"] = d
                            break
                elif d.is_coresight_device_type(3,1):
                    # ETM: allocate to the first CPU that hasn't yet got an ETM
                    for c in cpus_in_this_table:
                        if "ETM" not in c.affine_devices:
                            d.affine_core = c
                            c.affine_devices["ETM"] = d
                            break
                elif d.is_coresight_device_type(4,1):
                    # CTI: allocate to the first CPU that hasn't yet got a CTI
                    # If not using DEVAFF, it should be at -64K offset from the CTI
                    for c in cpus_in_this_table:
                        if "CTI" not in c.affine_devices and c.base_address == (d.base_address - 0x10000):
                            d.affine_core = c
                            c.affine_devices["CTI"] = d
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

    def show_coresight_device(self, d):
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

        if d.architecture() is None:
            archdesc = "" 
        elif d.is_arm_architecture():
            archid = d.architecture()
            archpart = archid & 0xfff
            archrev = (d.devarch >> 16) & 15
            if archid in arm_archids:
                archdesc = "Arm %s rev%u" % (arm_archids[archid], archrev)
            elif archpart in arm_archparts:
                archdesc = "?Arm %s rev%u.%u" % (arm_archparts[archpart], (archid >> 12), archrev)
            else:
                archdesc = "?Arm:0x%04x rev %u" % (archid, archrev)
        else:
            archdesc = "?ARCH:0x%x:0x%x" % (d.architect(), d.architecture())

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
            # PMU doesn't have a register of its own to indicate power state - you have to
            # find the affine core.
            if not d.is_affine_to_core():
                core_powered_off = True
            else:
                edprsr = d.affine_core.read32(0x314)
                core_powered_off = ((edprsr & 0x1) == 0)
            if not core_powered_off:
                config = d.read32(0xE00)
                n_counters = config & 0xff
                if o_verbose:
                    print(" config:0x%08x" % (config), end="")
                print(" counters:%u" % (n_counters), end="")
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
        elif d.is_arm_architecture(ARM_ARCHID_ETM):
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
                n_resource_selectors = bits(etmid4,16,4)*2
                n_address_comparator_pairs = bits(etmid4,0,4)
                n_pe_comparators = bits(etmid4,12,4)
                n_single_shot = bits(etmid4,20,4)
                n_events = bits(etmid0,10,2)+1
                n_counters = bits(etmid5,28,3)
                n_seqstates = bits(etmid5,25,3)
                n_extin = bits(etmid5,0,9)
                n_extinsel = bits(etmid5,9,3)
                if eminor >= 3:
                    if bits(etmid4,16,4) == 0:
                        n_events = 0       
                print(" events:%u resources:%u addrcomp:%u ssc:%u pecomp:%u counters:%u seqstates:%u extin:%u extinsel:%u" % (n_events, n_resource_selectors, n_address_comparator_pairs, n_single_shot, n_pe_comparators, n_counters, n_seqstates, n_extin, n_extinsel), end="")
                if bit(etmid5,31):
                    print(" reduced-function-counter", end="")
        elif d.is_arm_architecture(ARM_ARCHID_STM):
            # CoreSight STM
            n_ports = devid & 0x1ffff
            print(" ports:%u" % n_ports, end="")
        elif d.is_arm_architecture(ARM_ARCHID_ELA):
            print(" devid:0x%08x" % devid, end="")
        elif d.is_cti():
            # CoreSight CTI (SoC400) or CoreSight CTI (SoC600) or core CTI
            # n.b. SoC600 CTI is fixed at 4 channels
            print(" channels:%u triggers:%u" % (((devid>>16)&0xf), ((devid>>8)&0xff)), end="")
        elif d.is_arm_part_number(0x908):
            # CoreSight trace funnel (SoC400)
            in_ports = devid & 15
            print(" in-ports:%u" % in_ports, end="")
            if (devid & 0xf0) == 3:
                print(" priority-scheme")
        elif d.is_arm_part_number(0x909):
            # CoreSight trace replicator (SoC400)
            out_ports = devid & 15
            print(" out-ports:%u" % out_ports, end="")
            if (devid & 0xf0) == 3:
                print(" priority-scheme")
        elif d.is_arm_part_number(0x912):
            # CoreSight TPIU
            print(" TPIU", end="")
        elif d.is_arm_part_number(0x907):
            # CoreSight ETB
            print(" ETB size:%u" % (d.read32(0x004)*4), end="")
        elif d.is_arm_part_number(0x961):
            # CoreSight TMC (SoC400 generation)
            configtype = (devid >> 6) & 3
            print(" TMC:%s" % ["ETB","ETR","ETF","?3"][configtype], end="")
            if configtype != 1:
                print(" size:%u" % (d.read32(0x004)*4), end="")   # for ETB/ETF this is fixed, for ETR it's the buffer size
            memwidth = (devid >> 8) & 7
            print(" memwidth:%u" % (8<<memwidth), end="")
            if configtype == 1:
                wbdepth = (devid >> 11) & 7
                print(" wb:%u" % (1<<wbdepth), end="")

        # dynamic information, but generic for all CoreSight devices
        if d.is_unlocked():
            print(" unlocked", end="")
        if not core_powered_off:
            claimed = d.read32(0xFA4)
            if claimed:
                print(" claimed:0x%x" % claimed, end="")
        if (d.read32(0xF00) & 1) != 0:
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
            # Core debug interface
            pass
        elif d.is_arm_architecture(ARM_ARCHID_PMU):
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
        elif d.is_arm_architecture(ARM_ARCHID_ETM):
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
        elif d.is_arm_part_number(0x907) or d.is_arm_part_number(0x961):
            # CoreSight SoC400 ETB or TMC trace buffer.
            # Trace buffer management is complicated by the variety of design-time
            # and programming-time configuration choices:
            #   1. Product: integration-time product selection, from e.g.
            #     - Arm CoreSight SoC-400 ETB (0x907)
            #     - Arm CoreSight TMC (0x961)
            #     - Arm CoreSight SoC-600 TMC
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
            print("  mode: %s" % ["circular buffer","software FIFO","hardware FIFO","?3"][mode])
            if is_ETR:
                axi_control = d.read32(0x110)
                print("  AXI control: 0x%08x" % axi_control)
                scatter_gather = bit(axi_control,7)
                etr_memory = d.read64(0x118)    # DBALO, DBAHI
                if not scatter_gather:
                    # base address of trace buffer in system memory
                    print("  buffer address: 0x%x" % etr_memory)
                    print("  buffer size: 0x%x" % (d.read32(0x004)*4))
                else:
                    # address of first page table entry in linked list
                    print("  scatter-gather table: 0x%x" % etr_memory)
                    # ideally we'd read the scatter-gather table from physical memory,
                    # to show where the ETR was actually writing the data
            ffcr = d.read32(0x304)
            ffcr_map = {0:"formatting",1:"format-triggers",4:"FOnFlIn",5:"flush-on-trigger",6:"FlushMan",12:"stop-on-flush",13:"stop-on-trigger"}
            print("  flush control: %s" % bits_set(ffcr,ffcr_map))
            # from here, report current status
            TraceCaptEn = bit(d.read32(0x020), 0)
            status = d.read32(0x00C)
            if not is_TMC:
                print("  status: %s" % bits_set(status,{0:"Full",1:"Triggered",2:"AcqComp",3:"FtEmpty"}))
                print("  state: %s" % ["disabled","enabled"][TraceCaptEn])
            else:
                print("  status: %s" % bits_set(status,{0:"Full",1:"Triggered",2:"TMCready",3:"FtEmpty",4:"Empty",5:"MemErr"}))
                TMCReady = bit(status,2)
                if not TraceCaptEn:
                    if not TMCReady:
                        tmcstate = "Disabling (CTL=0x%08x, STS=0x%08x, FFCR=0x%08x, FFSR=0x%08x, RRP=0x%08x, RWP=0x%08x)" % (d.read32(0x020), status, ffcr, d.read32(0x300), d.read32(0x014), d.read32(0x018))
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
                print("  state: %s" % tmcstate)
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
            print("  trigger inputs:  %s" % (binstr(d.read32(0x130),n_trigs)))
            print("  trigger outputs: %s" % (binstr(d.read32(0x134),n_trigs)))
            print("  channel inputs:  %s" % (binstr(d.read32(0x138),n_channels)))
            print("  channel outputs: %s" % (binstr(d.read32(0x13C),n_channels)))
        elif d.is_arm_part_number(0x908):
            # CoreSight funnel
            ctrl = d.read32(0x000)
            print("  ports enabled: %s" % (binstr((ctrl & 0xff),in_ports)))
            print("  hold time: %u" % bits(ctrl,8,4))
            if bit(d.read32(0xEF0), 1):
                print("  downstream requested flush")
            integration_regs = [0xEF0, 0xEF4, 0xEF8]
        elif d.is_arm_part_number(0x909):
            # CoreSight replicator
            for rep_port in [0,1]:
                rep_filter = d.read32(0x000 + rep_port*4)
                print("  id filter port %u: 0x%x" % (rep_port, rep_filter), end="")
                if rep_filter == 0:
                    print(" (all IDs enabled)", end="")
                print()
            integration_regs = [0xEF8]
        else:
            # unknown device
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


    def show_device(self, d):
        """
        Show device details on a single line.
        """
        rev = (d.PIDR >> 20) & 15       # PIDR2.REVISION
        patch = (d.PIDR >> 28) & 15     # PIDR3.REVAND
        print("@0x%x " % (d.base_address), end=" ")
        # Note that Arm CoreSight SoC uses PIDR2.REVISION to count successive
        # major/minor releases of each block. The overall release of CoreSight SoC
        # can only be deduced from the combination of block releases seen.
        # For example SoC-400 r3p1 has funnel rev r1p0 indicated by REVISION=2,
        # while SoC-400 r3p2 has funnel rev r1p1 indicated by REVISION=3.
        print("  0x%03x 0x%03x r%u.%u  " % (d.jedec_designer, d.part_number, rev, patch), end="")
        if (d.CIDR & 0xffff0fff) != 0xb105000d:
            print("unexpected CIDR: 0x%08x" % d.CIDR)
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
            self.show_coresight_device(d)
        elif d.device_class() == 0xF:
            # might be worth reading DEVARCH even though Class 0xF doesn't guarantee to have it (and it might not be readable)
            print("generic PrimeCell peripheral: DEVARCH=0x%08x DEVAFF=0x%08x" % (d.read32(0xFBC), d.read32(0xFA8)))
            # might be Arm RAS architecture
            if False and d.read32(0xFBC) == 0x47700a00:
                print("  0xE80: %08x" % d.read32(0xE80))
                print("  0xFC8: %08x" % d.read32(0xFC8))
                for a in range(0,0x030,8):
                    print("  0x%03x: %08x" % (a, d.read32(a)))
        else: 
            print("class:%u" % (d.device_class()))


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
        reg = 0xEF8
        mask = 0x01
        if d.is_replicator():
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
        else:
            reg = 0xEF8
        d.write32(reg, flag*mask, check=False)
    def set_ATREADYS(d, n, flag):
        if d.is_funnel():
            enable_funnel_input(d, n)
        if d.is_replicator():
            reg = 0xEFC
            mask = 0x10
        else:
            reg = 0xEF0
            mask = 0x01
        d.write32(reg, flag*mask, check=False)
    def get_ATVALIDS(d, n):
        if d.is_funnel():
            enable_funnel_input(d, n)
        mask = 0x01
        if d.is_replicator():
            mask = 0x08
        return (d.read32(0xEF8) & mask) != 0
    for d in atb_devices:
        d.unlock()
        d.set_integration_mode(True)
        def clear_integration_regs(d):
            d.write32(0xEF0, 0, check=False)
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
        c.show_device(dm)        
        for mp in range(0, dm.atb_out_ports()):            
            set_ATVALIDM(dm, mp, 1)
            for ds in atb_devices:
                if ds == dm:
                    continue
                for sp in range(0, ds.atb_in_ports()):
                    if get_ATVALIDS(ds, sp):
                        def jport(d, p):
                            return [("0x%x" % d.base_address), p]
                        ld = {"type": "ATB", "from": jport(dm, mp), "to": jport(ds, sp)}
                        topo["links"].append(ld)
                        print("  %u->%u  " % (mp, sp), end="")
                        c.show_device(ds)
                        set_ATREADYS(ds, sp, 1)
                        set_ATVALIDM(dm, mp, 0)
                        set_ATVALIDM(dm, mp, 1) # ready for next time
                        break
                if ds.is_funnel():
                    d.clr32(0x000, 0xFF)
            set_ATVALIDM(dm, mp, 0)
    # Finally, put the devices back into production mode.
    for d in atb_devices:
        d.set_integration_mode(False)
        d.lock()
    # At this point, the system isn't guaranteed to be in a usable
    # (mission-mode) state. In practice, it often works.
    print("ATB topology detection complete.")


def topology_detection_cti(devices, topo):
    """
    CTI topology detection.
    For each device, assert its outputs and search other devices for corresponding inputs.

    With DynamIQ it appears the relationship between a core and its CTI is not discoverable
    via topology detection. Instead the relationship is fixed and documented in the DSU TRM:

    DSU per-core CTI inputs:
      0: cross-halt
      1: PMU overflow
      2: profile sampl
      4-7: ETM trace output
      8-9: ELA trigger output
    DSU per-core CTI outputs:
      0: debug request
      1: restart
      2: GIC generic CTI interrupt
      4-7: ETM external input
      8-9: ELA trigger input
    """
    def pin_out(d):
        if d.is_arm_part_number(0x907) or d.is_arm_part_number(0x961):
            yield ("ACQCOMP", 0xEE0, 0)
            yield ("FULL", 0xEE0, 1)
        elif d.is_coresight_device_type(3,1):
            for i in range(0, 4):
                yield ("ETMEXTOUT%u" % i, 0xEDC, i+8)
        elif d.is_arm_architecture(ARM_ARCHID_STM):
            yield ("TRIGOUTSPTE", 0xEE8, 0)
            yield ("TRIGOUTSW", 0xEE8, 1)
            yield ("TRIGOUTHETE", 0xEE8, 2)
            yield ("ASYNCOUT", 0xEE8, 3)
        elif d.is_cti() and not d.is_affine_to_core():
            # Testing core-affine CTIs currently disabled to avoid halting our own core
            n_triggers = ((d.read32(0xFC8)>>8)&0xff)
            for i in range(0, n_triggers):
                yield ("TRIGOUT%u" % i, 0xEE8, i)
        else:
            pass
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
        elif d.is_cti():
            n_triggers = ((d.read32(0xFC8)>>8)&0xff)
            for i in range(0, n_triggers):
                yield ("TRIGIN%u" % i, 0xEF8, i, 0xEE0)
        else:
            pass
    def has_triggers(d):
        return d.is_cti() or len(list(pin_out(d))) > 0 or len(list(pin_in(d))) > 0
    print("\nCTI topology detection")
    devices = [d for d in devices if has_triggers(d)]
    # Put all devices into integration mode, and do the master preamble
    for d in devices:
        c.show_device(d)
        d.unlock()
        d.set_integration_mode(True)
        for (name, reg, b) in pin_out(d):
            d.clr32(reg, 1<<b)
    # Slave preamble, and check if any input pins are already asserted...
    for ds in devices:
        for (sname, sreg, sb, inack) in pin_in(ds):
            if inack is not None:
                d.clr32(inack, 1<<sb)
            if bit(ds.read32(sreg), sb):
                print("%s %s already asserted" % (ds, sname))
    out_map = {}
    in_map = {}
    print("CTI outputs:")
    for dm in devices:
        if len(list(pin_out(dm))):
            print("  %s" % dm)
        for (mname, mreg, mb) in pin_out(dm):
            dm.set32(mreg, 1<<mb)
            mkey = (dm, mname)
            for ds in devices:
                for (sname, sreg, sb, inack) in pin_in(ds):
                    if bit(ds.read32(sreg), sb):
                        print("    %s -> %s %s" % (mname, ds, sname))
                        skey = (ds, sname)
                        if mkey in out_map:
                            print("       multiple outputs!")
                        if skey in in_map:
                            (da, aname) = in_map[skey]
                            print("       multiple inputs: already connected to %s %s" % (da, aname))
                        out_map[mkey] = skey
                        in_map[skey] = mkey
                        if inack is not None:
                            ds.set32(inack, 1<<sb)
                            ds.clr32(inack, 1<<sb)
            dm.clr32(mreg, 1<<mb)
            if mkey not in out_map:
                print("    %s not connected" % (mname))
    print("CTI inputs:")
    for ds in devices:
        if len(list(pin_in(ds))):
            print("  %s" % ds)
        for (sname, sreg, sb, inack) in pin_in(ds):
            skey = (ds, sname)
            if skey in in_map:
                (dm, mname) = in_map[skey]
                print("    %s <- %s %s" % (sname, dm, mname))
            else:
                print("    %s not connected" % (sname))
    for d in devices:
        d.set_integration_mode(False)
        d.lock()
    print("CTI topology detection complete.")


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
        assert e.device is not None or e.device_address() in o_exclusions
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


if __name__ == "__main__":
    # we don't use argparse because it's not available on Python 2.6
    def help():
        print("%s [--exclude=<addr>] [--status] <addr>" % sys.argv[0])
        print("  --exclude=<addr>     don't access device at this address")
        print("  --status             show device status as well as configuration")
        print("  --limit=<n>          stop scan after n devices")
        print("  --topology           detect ATB topology")
        print("  --enable-timestamps  enable global CoreSight timestamps")
        print("  -v/--verbose         increase verbosity level")
        sys.exit(1)
    c = None
    done = False
    o_detect_topology = False
    o_detect_topology_cti = False
    o_enable_timestamps = False
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
        elif arg == "--authstatus":
            o_show_authstatus = True
        elif arg.startswith("--limit="):
            o_max_devices = int(arg[8:])
        elif arg == "--top-only":
            o_top_only = True
        else:
            table_addr = int(arg, 16)
            if c is None:
                try:
                    c = CSROM()
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

