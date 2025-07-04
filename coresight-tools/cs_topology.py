#!/usr/bin/python

"""
Manage a CoreSight configuration

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


from __future__ import print_function

import sys, os, json


# CoreSight Device Type indicates the generic function of the device.
# It does not indicate the specific programming model of the device.
# Defined in CoreSight Architecture, under DEVTYPE.
# This is only a rough guide. For example, a TMC configured as a router
# is (1,2), "buffer", not either of the codes listed as "router".
CS_DEVTYPE_MISC = (0,0)
CS_DEVTYPE_PORT = (1,1)
CS_DEVTYPE_BUFFER = (1,2)
CS_DEVTYPE_ROUTER = (1,3)        # "Basic trace router"
CS_DEVTYPE_FUNNEL = (2,1)        # "Trace Funnel, Router"
CS_DEVTYPE_REPLICATOR = (2,2)    # "Filter" - includes replicators whether filtering or not
CS_DEVTYPE_FIFO = (2,3)          # "FIFO, Large Buffer"
CS_DEVTYPE_TRACE_CORE = (3,1)
CS_DEVTYPE_TRACE_BUS = (3,4)
CS_DEVTYPE_TRACE_SW = (3,6)
CS_DEVTYPE_CTI = (4,1)
CS_DEVTYPE_POWER = (4,3)
CS_DEVTYPE_CORE = (5,1)
CS_DEVTYPE_ELA = (5,7)
CS_DEVTYPE_PMU_CORE = (6,1)

CS_DEVTYPE_TIMESTAMP = (0,1)        # Not defined by CoreSight Architecture


devtype_str = {
    CS_DEVTYPE_PORT:       "port",
    CS_DEVTYPE_BUFFER:     "buffer",
    CS_DEVTYPE_ROUTER:     "router",
    CS_DEVTYPE_FUNNEL:     "funnel",
    CS_DEVTYPE_REPLICATOR: "replicator",
    CS_DEVTYPE_FIFO:       "fifo",
    CS_DEVTYPE_TRACE_CORE: "core-trace",
    CS_DEVTYPE_TRACE_BUS:  "bus-trace",
    CS_DEVTYPE_TRACE_SW:   "sw-trace",
    CS_DEVTYPE_CTI:        "CTI",
    CS_DEVTYPE_POWER:      "power-req",
    CS_DEVTYPE_CORE:       "core",
    CS_DEVTYPE_PMU_CORE:   "core-pmu",
    CS_DEVTYPE_ELA:        "ELA",
    CS_DEVTYPE_TIMESTAMP:  "timestamp"
}


# Link type enumerators defined by this module
CS_LINK_ATB = 1
CS_LINK_CTI = 2
CS_LINK_CORE_TRACE = 3

link_type_str = {
    CS_LINK_ATB: "ATB",
    CS_LINK_CTI: "CTI",
    CS_LINK_CORE_TRACE: "core-trace"
}

link_types = [CS_LINK_ATB, CS_LINK_CTI, CS_LINK_CORE_TRACE]


# Link ends
CS_LINK_MASTER = (1,"a")
CS_LINK_SLAVE = (1,3)

def other_end(e):
    if e == CS_LINK_MASTER:
        return CS_LINK_SLAVE
    elif e == CS_LINK_SLAVE:
        return CS_LINK_MASTER
    else:
        assert False


# A given device will have one or more addresses, depending on where (which DAP) it's being accesse from.
# DAP_CORE refers to addresses as seen by the application cores.
DAP_CORE = ""


class Device:

    """
    A CoreSight device.
    """

    def __init__(self, platform, device_type, is_hidden=False, name=None, type_name=None, mem_address=None, dap_name=DAP_CORE):
        """
        Create a device.
          - device_type should be a major/minor pair, e.g. CS_DEVTYPE_FIFO.
          - name is free for user use and should be a unique name for
            this device instance within the platform, e.g. "ETB#1".
          - type_name is free for user use and should be a descriptive name
            for the device type: especially useful for cores
        """
        self.platform = platform
        self.is_hidden = is_hidden
        assert (not is_hidden) or (device_type in [CS_DEVTYPE_FUNNEL, CS_DEVTYPE_REPLICATOR])
        if name is not None:
            self.set_name(name)
        else:
            self.name = None
        self.type_name = type_name
        self.part_vendor = None
        self.part_number = None     # e.g. 0x906
        self.cpu_number = None      # CPU (PE) number within the system, e.g. as seen by Linux
        self.affine_cpu = None      # a CS_DEVTYPE_CORE Device object we are affine to
        self.type = device_type
        if device_type == CS_DEVTYPE_CORE:
            self.affine_cpu = self
            self.affine_devices = []
        elif device_type == CS_DEVTYPE_TRACE_SW:
            self.stimulus_base_address = None
            self.stimulus_size = None
        elif device_type == CS_DEVTYPE_TRACE_CORE:
            self.etm_architecture = None
        self.mem_address = None     # Ideally, memory address as seen by the core (DAP-relative address may differ)
        # Input and output links can be of various types: ATB, CTI etc.
        # The device may also have configured ports that do not have links.
        self.outlinks = []
        self.inlinks = []
        platform.devices.append(self)
        if mem_address is not None:
            self.set_mem_address(mem_address, dap_name=dap_name)
        if platform.trace_creation:
            print("  created %s%s" % (str(self), [""," (hidden)"][is_hidden]))
            platform.check()
        self.sysfs_path = None      # Device path in Linux sysfs or equivalent

    def type_str(self):
        if self.type in devtype_str:
            return devtype_str[self.type]
        else:
            return str(self.type)

    def __str__(self):
        """
        Generate a string representation for the device, including its name (if known)
        and base address. This could unfortunately duplicate the address, if the naming
        convention includes the address, e.g.
           etm2@0x80000
        but
           etm@0x0080000@0x80000
        So we try to be clever and only append the base address if it's not already
        in the name.
        """
        s = ""
        if self.name is not None:
            s = self.name
        else:
            s += "<%s>" % self.type_str()
        if self.is_memory_mapped():
            if self.name is not None and '@' in self.name:
                pass
            else:
                s += "@" + self.address_str()
        return s

    def links(self, type, end=None):
        if end is None or end == CS_LINK_SLAVE:
            for ln in self.inlinks:
                if ln.linktype == type:
                    yield ln
        if end is None or end == CS_LINK_MASTER:
            for ln in self.outlinks:
                if ln.linktype == type:
                    yield ln

    def link(self, type, end, port=0):
        """
        Get the other end of an existing link
        """
        assert type in link_types, "unexpected link type: %s" % type
        assert end in [CS_LINK_SLAVE, CS_LINK_MASTER], "unexpected link end: %s (expected CS_LINK_SLAVE or CS_LINK_MASTER)" % end
        for ln in self.links(type, end):
            if ln.port(end) == port:
                return ln
        return None

    def get_path_to(self, td, type=CS_LINK_ATB):
        """
        Get a path (a list of links) to another device, or None if no path.
        """
        if td == self:
            return Path()
        for ln in self.outlinks:
            p = ln.slave.get_path_to(td, type=type)
            if p is not None:
                return p.prepend(ln)
        return None

    def is_replicator(self):
        return self.type == CS_DEVTYPE_REPLICATOR

    def is_funnel(self):
        return self.type == CS_DEVTYPE_FUNNEL

    def is_affine_to_cpu(self):
        return self.cpu_number is not None or self.affine_cpu is not None

    def set_affine_cpu(self, cpu_dev):
        """
        Set the affine CPU device. This is used when you already have a
        device object for the device.
        """
        if self.affine_cpu != cpu_dev:
            assert self.affine_cpu is None, "set_affine_cpu() called twice with different devices"
            assert cpu_dev.type == CS_DEVTYPE_CORE, "set_affine_cpu needs a core device: %s" % cpu_dev
            self.affine_cpu = cpu_dev
            cpu_dev.affine_devices.append(self)
            if self.cpu_number is None:
                self.cpu_number = cpu_dev.cpu_number

    def set_cpu_number(self, n):
        self.cpu_number = n
        if n > self.platform.max_cpu_number:
            self.platform.max_cpu_number = n
        if self.type == CS_DEVTYPE_CORE:
            # Core cpu number is now known, so update all its affine devices
            # to get the same CPU number.
            for d in self.affine_devices:
                assert d.affine_cpu == self
                d.cpu_number = n
            # Some devices may already have got a CPU number, but because the core
            # has only just got its own number, they're not tied together.
            # Do that now.
            for d in self.platform.devices:
                if d.cpu_number == n and d.affine_cpu is not self:
                    d.set_affine_cpu(self)
        elif self.affine_cpu is None:
            cpu_dev = self.platform.device_by_cpu(n)
            if cpu_dev is not None:
                self.set_affine_cpu(cpu_dev)

    def set_arm_part_number(self, pid):
        assert pid <= 0xfff, "expected 3 hex digit part number: 0x%x" % pid
        self.part_vendor = 'A'
        self.part_number = pid

    def set_name(self, name):
        self.name = name
        if name in self.platform.devices_by_name:
            assert False, "%s: duplicate device name '%s'" % (self.platform, name)
        self.platform.devices_by_name[name] = self

    def set_mem_address(self, maddr, dap_name=DAP_CORE):
        """
        Set the address of this device, also registering it in the Platform's
        address mapping and checking for multiple devices at the same address.
        """
        self.mem_address = maddr
        self.dap_name = dap_name
        addr = self.address()
        if addr is not None:
            while addr in self.platform.devices_by_address:
                # we should only ever see this when enumerating devices by JTAG
                # and when the devices differ in AP index
                print("%s: warning: address %s has multiple devices %s and %s" % (self.platform.source_file, self.address_str(), self.platform.devices_by_address[addr].name, self.name))
                # TBD this is a hack
                (d, a) = addr
                addr = (d, a+1)
            self.platform.devices_by_address[addr] = self

    def address(self):
        if self.mem_address is not None:
            return (self.dap_name, self.mem_address)
        else:
            return None

    def is_memory_mapped(self):
        return self.address() is not None

    def address_str(self):
        if self.address() is not None:
            (dapname, addr) = self.address()
            if dapname:
                return "%s:0x%x" % (dapname, addr)
            else:
                return "0x%x" % (addr)
        elif self.dap_name:
            return "%s:<no address>" % (self.dap_name)
        else:
            return "<no address>"


class Link:

    """
    Link is the class of objects that represent point-to-point links
    between CoreSight components, e.g.
      ATB
      cross-trigger
      core-to-ETM
    Note that CoreSight has the concept of a "trace link" which is
    a device such as a funnel or ETF. In our object model, that is a
    Device, not a Link.
    """

    def __init__(self, master, slave, linktype, master_port=0, slave_port=0):
        assert isinstance(master, Device)
        assert isinstance(slave, Device)
        assert master.platform == slave.platform
        platform = master.platform
        assert master != slave
        assert linktype in link_types
        if linktype == CS_LINK_CORE_TRACE:
            assert master.type == CS_DEVTYPE_CORE
            # Normally a core would have a trace interface to an ETM, but with
            # the Cortex-M MTB, a core can output trace directly into a buffer.
            assert slave.type in [CS_DEVTYPE_TRACE_CORE, CS_DEVTYPE_BUFFER]
        elif linktype == CS_LINK_CTI:
            assert master.type not in [CS_DEVTYPE_FUNNEL, CS_DEVTYPE_REPLICATOR]
            assert slave.type not in [CS_DEVTYPE_FUNNEL, CS_DEVTYPE_REPLICATOR]
        elif linktype == CS_LINK_ATB:
            pass
        self.linktype = linktype
        self.master = master        # input to this link
        self.slave = slave          # output from this link
        self.master_port = master_port
        self.slave_port = slave_port
        if platform.trace_creation:
            print("    creating link: %s" % str(self))
            platform.check()
        if linktype == CS_LINK_ATB:
            # Check if the slave already has any inputs on this port (and is not hidden)
            sl = slave.link(linktype, CS_LINK_SLAVE, slave_port)
            if sl is not None:
                if not platform.auto_split:
                    print("** %s.m%s -> %s.s%s: slave already ATB-connected from %s" % (master, master_port, slave, slave_port, sl.master))
                    assert False
                # check if there's already a hidden funnel on this slave port
                if sl.master.type == CS_DEVTYPE_FUNNEL and sl.master.is_hidden:
                    pd = sl.master
                    # this new link will now go to the slave port on the existing hidden funnel
                else:
                    # introduce a hidden funnel for the multiple inputs to this slave port
                    pd = Device(platform, CS_DEVTYPE_FUNNEL, is_hidden=True, name=("<hidden-funnel:%s.s%u>" % (str(slave), slave_port)))
                    # the slave port's single link is now the hidden link from the funnel.
                    # But first remove the existing link, to avoid recursion
                    # the previous master's link to the slave port now needs to be repointed
                    # to the hidden funnel
                    assert sl in slave.inlinks
                    slave.inlinks.remove(sl)
                    sl.slave = pd
                    sl.slave_port = None
                    pd.inlinks.append(sl)
                    # create the hidden link from the hidden funnel to the shared slave port
                    Link(pd, slave, linktype, master_port=0, slave_port=slave_port)
                self.slave = pd
                self.slave_port = None
            # do the same for master port
            ml = master.link(linktype, CS_LINK_MASTER, master_port)
            if ml is not None:
                if not platform.auto_split:
                    print("** %s.m%s -> %s.s%s: master already ATB-connected to %s" % (master, master_port, slave, slave_port, ml.slave))
                    assert False
                if ml.slave.type == CS_DEVTYPE_REPLICATOR and ml.slave.is_hidden:
                    pd = ml.slave
                else:
                    # introduce a hidden replicator for the multiple outputs from this master port
                    pd = Device(platform, CS_DEVTYPE_REPLICATOR, is_hidden=True, name=("<hidden-replicator:%s.m%u>" % (str(master), master_port)))
                    # the master port's single link is now the hidden link to the replicator
                    # the existing link from the master is now one of the replicator outputs
                    assert ml in master.outlinks
                    master.outlinks.remove(ml)
                    ml.master = pd
                    ml.master_port = None
                    pd.outlinks.append(ml)
                    # create the hidden link from the shared master port to the hidden replicator
                    Link(master, pd, linktype, master_port=master_port, slave_port=0)
                self.master = pd
                self.master_port = None
        self.master.outlinks.append(self)
        self.slave.inlinks.append(self)
        platform.links.append(self)
        if platform.trace_creation:
            platform.check()
            print("    link created: %s" % str(self))

    def __str__(self):
        s = str(self.master)
        if self.master_port is not None:
            s += ".%u" % self.master_port
        s += " --(%s)--> " % link_type_str[self.linktype]
        if self.slave_port is not None:
            s += "%u." % self.slave_port
        s += str(self.slave)
        return s

    def device(self, end):
        assert end in [CS_LINK_SLAVE, CS_LINK_MASTER]
        if end == CS_LINK_SLAVE:
            return self.slave
        else:
            return self.master

    def port(self, end):
        assert end in [CS_LINK_SLAVE, CS_LINK_MASTER]
        if end == CS_LINK_SLAVE:
            return self.slave_port
        else:
            return self.master_port

    def device_end(self, d):
        if d == self.master:
            return CS_LINK_MASTER
        elif d == self.slave:
            return CS_LINK_SLAVE
        else:
            return None

    def link_port(self, d):
        if d == self.master:
            return self.master_port
        elif d == self.slave:
            return self.slave_port
        else:
            return None

    def other(self, d):
        # Given a device, return the device at the other end
        assert d == self.master or d == self.slave
        if d == self.master:
            od = self.slave
        else:
            od = self.master
        assert od != d
        return od


class Path:
    """
    A collection of links. Usually of the same type.
    """
    def __init__(self, links=[]):
        self.links = [ln for ln in links]

    def len(self):
        return len(self.links)

    def append(self, ln):
        """
        Update the path in place by adding another link.
        """
        assert (not self.links) or self.links[-1].slave == ln.master, "%s append %s" % (self, ln)
        self.links.append(ln)
        return self

    def __add__(self, ln):
        """
        Create a new path from an old one with a new link appended.
        """
        return Path(self.links).append(ln)

    def prepend(self, ln):
        assert (not self.links) or ln.slave == self.links[0].master, "%s prepend %s" % (ln, self)
        self.links.insert(0, ln)
        return self

    def devices(self, hidden=True):
        assert self.links
        for (i, ln) in enumerate(self.links):
            if i == 0 or not ln.master.is_hidden:
                yield ln.master
        yield self.links[-1].slave

    def first_device(self):
        return self.links[0].master

    def last_device(self):
        return self.links[-1].slave

    def str(self, typed=True, hidden=True):
        if not self.links:
            return "[]"
        ln0 = self.links[0]
        s = str(ln0.master)
        for (i, ln) in enumerate(self.links):
            if ln.master_port is not None:
                s += ".%u" % ln.master_port
            s += " "
            if typed:
                s += "--(%s)" % link_type_str[ln.linktype]
            s += "--> "
            if hidden or not ln.slave.is_hidden or (i == len(self.links)-1):
                if ln.slave_port is not None:
                    s += "%u." % ln.slave_port
                s += str(ln.slave)
        return s

    def __str__(self):
        return str(self, typed=True)


class Platform:
    """
    A collection of linked CoreSight devices.
    """

    def __init__(self, name=None, source_file=None, auto_split=False):
        self.trace_creation = False
        self.name = name
        self.source_file = source_file    # diagnostic use only - need not exist
        self.auto_split = auto_split
        self.devices = []
        self.devices_by_address = {}
        self.devices_by_name = {}
        self.links = []              # all links
        self.max_cpu_number = 0

    def name_str(self):
        if self.name is not None:
            s = self.name
        elif self.source_file is not None:
            s = self.source_file
        else:
            s = "<CoreSight>"
        return s

    def __str__(self):
        s = "%s: %u devices, %u links" % (self.name_str(), len(self.devices), len(self.links))
        return s

    def device_by_address(self, addr):
        """
        Look up a device by an address - a combination of a DAP and an offset.
        """
        assert isinstance(addr, tuple)
        if addr in self.devices_by_address:
            return self.devices_by_address[addr]
        else:
            return None

    def device_by_name(self, name):
        """
        Look up a device by the name that we have given it.
        """
        if name in self.devices_by_name:
            return self.devices_by_name[name]
        else:
            return None

    def device_by_cpu(self, cpu, type=CS_DEVTYPE_CORE):
        """
        Look up a device (of a given type) by affine CPU number.
        """
        for d in self.devices:
            if d.cpu_number == cpu and d.type == type:
                return d
        return None

    def create_device(self, type, **kwargs):
        d = Device(self, type, **kwargs)
        return d

    def add_unmapped_topology(self):
        """
        Topology may have been created with apparent 1-to-N or N-to-1 ATB connections.
        Introduce unmapped funnels and replicators as required, to ensure that ATB
        connections are always 1-1. This is done at the port level. So for example
        if port 0 on a funnel has two incoming ATB links, we need to create another
        (non-programmable) funnel in front of it to funnel those two links.
        (The input port numbers on that funnel are meaningless.)

        This is now fixed up immediately when links are created.
        """
        pass

    def __iter__(self):
        """
        Iterate over all devices, ordered by address.
        Unmapped devices are listed last.
        """
        for daddr in sorted(self.devices_by_address):
            yield self.device_by_address(daddr)
        for d in self.devices:
            if not d.is_memory_mapped():
                yield d

    def check(self):
        """
        Run various consistency checks over the topology representation,
        checking that devices and links are properly connected.
        We expect this to always succeed, by construction,
        regardless of whether the topology representation is
        correct or compliant as regards CoreSight.

        For a CoreSight architecture compliance check, see check_topology().
        """
        all_devices = list(self)
        assert len(self.devices) == len(all_devices)
        for ln in self.links:
            assert ln.master in self.devices
            assert ln.slave in self.devices
            assert ln in ln.master.outlinks
            assert ln in ln.slave.inlinks
        for d in self:
            for ln in d.inlinks:
                assert ln.slave == d
            for ln in d.outlinks:
                assert ln.master == d
            if d.mem_address is not None:
                assert d.address() in self.devices_by_address
        return self

    def check_topology(self):
        return check_topology(self)

    def show(self):
        """
        Print a simple textual list of devices.
        """
        print("%s: %u devices, %u links" % (self.name, len(self.devices_by_address), len(self.links)))
        #return
        print("Platform: %s" % self.name)
        # List devices
        for d in self:
            if d.name is not None:
                name = d.name
            else:
                name = None
            print("%20s  " % d.address_str(), end="")
            print("  %20s" % name, end="")
            print("  %12s" % (d.type_str()), end="")
            if d.is_affine_to_cpu():
                if d.cpu_number is not None:
                    print(" %4u" % d.cpu_number, end="")
                if d.affine_cpu is not None:
                    print(" %4s" % str(d.affine_cpu), end="")
            else:
                print("     ", end="")
            if d.is_hidden:
                print(" hidden", end="")
            if d.sysfs_path is not None:
                print("  %s" % d.sysfs_path, end="")
            print()
            if False:
                for cfk in d.config:
                    print("    %s: %s" % (cfk, d.config[cfk]))
        print("Links:")
        for ln in self.links:
            print("  %s" % str(ln))
        print("CPUs:")
        for c in range(0, self.max_cpu_number+1):
            cd = self.device_by_cpu(c, type=CS_DEVTYPE_TRACE_CORE)
            if cd is None:
                continue
            print("  CPU #%u:" % c)
            for sink in self.devices:
                if sink.type in [CS_DEVTYPE_PORT, CS_DEVTYPE_FIFO, CS_DEVTYPE_BUFFER, CS_DEVTYPE_ROUTER]:
                    p = cd.get_path_to(sink)
                    print("    %s: %s" % (sink, p))


def load(fn):
    """
    Load a CoreSight topology description from a JSON file, using our own lightweight format.
    """
    f = open(fn)
    jp = json.load(f)
    p = Platform(auto_split=True)
    def jaddr(s):
        try:
            addr = int(s, 16)
        except:
            print("invalid device address: %s" % s)
            raise
        return addr
    for jd in jp["devices"]:
        d = Device(p, tuple(jd["type"]))
        d.set_mem_address(jaddr(jd["address"]))
        if "architecture" in jd:
            arch = jd["architecture"]
            if arch[0] == "ETM":
                d.etm_architecture = int(arch[1])
        if "ram_size" in jd:
            d.ram_size = jd["ram_size"]
    for jl in jp["links"]:
        def jport(p, port):
            if isinstance(port, list):
                (fa, fp) = tuple(port)
            else:
                (fa, fp) = (port, 0)
            fa = jaddr(fa)
            fd = p.device_by_address((DAP_CORE, fa))
            if fd is None:
                p.show()
            assert fd is not None, "missing device at address 0x%x" % fa
            return (fd, fp)
        (fd, fp) = jport(p, jl["from"])
        (td, tp) = jport(p, jl["to"])
        if jl["type"] == "ATB":
            Link(fd, td, CS_LINK_ATB, master_port=fp, slave_port=tp)
    f.close()
    return p


def link_can_be_disabled(ln):
    """
    Check if an ATB link can be disabled dynamically.
    """
    if ln.master.is_replicator() and not ln.master.is_hidden:
        return True
    if ln.slave.is_funnel() and not ln.slave.is_hidden:
        return True
    return False


def path_can_be_disabled(p):
    """
    Check if path can be disabled dynamically.
    """
    for ln in p.links:
        if link_can_be_disabled(ln):
            return ln
    return None


class TopologyChecker:
    """
    Check that topology is compliant with CoreSight architectural constraints.
    Basically there can't be multiple paths between any two devices
    (and by implication, no cycles).

    There are at least three possible interpretations of the architectural requirement:

     - there cannot be multiple paths statically, i.e. there must be no
       possible way of programming links such that trace could go from
       a source to a sink by two different routes

     - there may be multiple paths statically, as long as all paths can
       independently be enabled, such that other paths can be disabled,
       so that trace does not reach the same sink by two different paths.

     - there may be multiple paths statically as long as there is some
       way of programming all links so that trace does not reach the same
       sink by two different paths.

    Note that considered as an undirected graph, there may be cycles, e.g. the
    configuration where two replicators and two funnels are used as a crossbar
    switch to connect two sources and two sinks, is valid.

    Method: for all devices, explore all paths forward, looking to see if we
    reach the same node two ways. Complexity-wise, this is not optimal.
    """
    def __init__(self, S, strict=False, max_issues=10):
        self.S = S
        self.strict = strict
        self.max_issues = max_issues
        self.check()

    class MaxIssues(Exception):
        pass

    def check(self):
        # Check the whole topology.
        self.n_issues = 0
        try:
            # Iterate through all possible starting trace sources.
            # Note that a CPU with data trace must be considered as
            # two trace sources.
            for d in self.S.devices:
                if False and d.is_hidden:
                    continue
                if not d.is_replicator():
                    continue
                self.seen = {}
                self.seen_non_disabled = {}
                self.explore(d, Path())
            return self.n_issues
        except self.MaxIssues:
            print("%s: ... further issues will be ignored" % self.S.name_str())
            return self.max_issues + 1

    def report(self, d, p1, p2):
        """
        Report that a device is reachable by two paths, at least one
        of which cannot be dynamically disabled.
        """
        self.n_issues += 1
        print()
        print("%s: [%u] %s seen from two paths:" % (self.S.name_str(), self.n_issues, d))
        while len(p1.links) >= 2 and len(p2.links) >= 2 and p1.links[0] == p2.links[0] and p1.links[1] == p2.links[1]:
            p1.links.pop(0)
            p2.links.pop(0)
        print("  %s" % p1.str(typed=False, hidden=False), end="")
        if not path_can_be_disabled(p1):
            print(" (always enabled)", end="")
        print()
        print("  %s" % p2.str(typed=False, hidden=False), end="")
        if not path_can_be_disabled(p2):
            print(" (always enabled)", end="")
        print()
        if self.n_issues >= self.max_issues:
            raise self.MaxIssues

    def explore(self, d, path):
        nd = not path_can_be_disabled(path)
        if not d.is_hidden:
            if d in self.seen and (self.strict or not nd):
                self.report(d, self.seen[d], path)
                return
            elif d in self.seen_non_disabled:
                self.report(d, self.seen_non_disabled[d], path)
                return
        self.seen[d] = path
        if nd:
            self.seen_non_disabled[d] = path
        for x in d.outlinks:
            assert x.master == d
            if x.linktype == CS_LINK_ATB:
                self.explore(x.slave, path + x)


def check_topology(S):
    checker = TopologyChecker(S)
    return checker.check()


def test():
    """
    Check that hidden funnels and replicators are introduced as necessary
    """
    print("Running self-tests...")
    p = Platform(auto_split=True)
    dm1 = Device(p, CS_DEVTYPE_TRACE_CORE, name="m1")
    dm2 = p.create_device(CS_DEVTYPE_TRACE_CORE, name="m2")
    dm3 = Device(p, CS_DEVTYPE_TRACE_CORE, name="m3")
    dstm = Device(p, CS_DEVTYPE_TRACE_SW, name="stm")
    df1 = Device(p, CS_DEVTYPE_FIFO, name="fifo1")
    ds1 = Device(p, CS_DEVTYPE_PORT, name="port")
    ds2 = Device(p, CS_DEVTYPE_BUFFER, name="buffer")
    Link(dstm, df1, CS_LINK_ATB, slave_port=2)
    Link(dm1, df1, CS_LINK_ATB, slave_port=1)
    Link(dm2, df1, CS_LINK_ATB, slave_port=1)   # Cause a hidden funnel to be created
    Link(dm3, df1, CS_LINK_ATB, slave_port=1)   # Use the same hidden funnel
    Link(df1, ds1, CS_LINK_ATB)
    Link(df1, ds2, CS_LINK_ATB)                 # Cause a hidden replicator
    assert df1.link(CS_LINK_ATB, CS_LINK_SLAVE, port=0) is None
    assert df1.link(CS_LINK_ATB, CS_LINK_SLAVE, port=1).master.is_hidden
    assert not df1.link(CS_LINK_ATB, CS_LINK_SLAVE, port=2).master.is_hidden
    assert df1.link(CS_LINK_ATB, CS_LINK_MASTER, port=0).slave.is_hidden
    # this will need a hidden funnel on ps2.0
    Link(df1, ds2, CS_LINK_ATB)
    p.show()
    p.check()
    print("Self-tests completed.")


if __name__ == "__main__":
    done = False
    for arg in sys.argv[1:]:
        if arg.startswith("-"):
            print("unrecognized option: %s" % arg)
        elif arg.endswith(".json"):
            p = load(arg)
            p.show()
        else:
            print("unrecognized command-line argument: %s" % arg)
        done = True
    if not done:
        test()
