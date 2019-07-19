#!/usr/bin/python

"""
Print a Linux device tree fragment for a CoreSight topology.

TBD:
 - ensure we have the correct Linux compatibility strings.
   This might mean adding support for DEVARCH to cs_topology.
"""

from __future__ import print_function

import cs_topology as CS
import sys


"""
Only a subset of CoreSight devices go into the device tree.
For example, CS_DEVTYPE_CTI is excluded.

(Perhaps it would be better to have a list of excluded device types?)
"""
selected_devtypes = [
    CS.CS_DEVTYPE_TRACE_CORE,
    CS.CS_DEVTYPE_TRACE_SW,
    CS.CS_DEVTYPE_FUNNEL,
    CS.CS_DEVTYPE_REPLICATOR,
    CS.CS_DEVTYPE_FIFO,
    CS.CS_DEVTYPE_BUFFER,
    CS.CS_DEVTYPE_ROUTER
]


devtype_strings = {
    CS.CS_DEVTYPE_CORE: "cpu-debug",
    CS.CS_DEVTYPE_TRACE_CORE: "etm",
    CS.CS_DEVTYPE_TRACE_SW: "stm",
    CS.CS_DEVTYPE_BUFFER: "etb",
    CS.CS_DEVTYPE_FIFO: "etf",
    CS.CS_DEVTYPE_FUNNEL: "funnel",
    CS.CS_DEVTYPE_REPLICATOR: "replicator",
    CS.CS_DEVTYPE_ROUTER: "tmc",
    CS.CS_DEVTYPE_PORT: "tpiu"
}


o_diag_ports = False


class DTWriter:
    """
    Manage the writing of a CoreSight topology description as a Linux device tree fragment.
    """
    def __init__(self, platform):
        platform.check()     
        self.platform = platform
        # initialize some parameters that the user can override before writing
        self.prefix = "\t\t"
        self.style = 2         # 1 is original port style, 2 is new one Suzuki Poulose introduced 2018
        self.clocks = ["DBGCLK"]
        self.clock_names = ["dbgclk"]        
        # initialize structures that are going to be used when we generate the DT
        # and that the user can override
        self.dev_cpu_number = {}
        # devices with the same DT name get separate names for their port endpoints.
        self.dev_name_for_port = {}     # dev -> string
        self.port_name_used = {}        # string -> dev
        n_core = 0
        for dev in platform:
            if dev.cpu_number is not None:
                self.dev_cpu_number[dev] = dev.cpu_number
            elif dev.type == CS.CS_DEVTYPE_CORE:                
                self.dev_cpu_number[dev] = n_core
                n_core += 1
            # give each device a unique name for endpoint purposes
            # For example, if there's just one "stm" it will be called "stm".
            # If there are two, they will be "stm1" and "stm2".
            endpoint_dev_name = self.dt_name(dev)
            if endpoint_dev_name not in self.port_name_used:
                # first occurrence of this dev name gets it verbatim,
                # and it will later be updated to avoid a clash
                self.port_name_used[endpoint_dev_name] = [dev]
            else:
                # this is the second or subsequent device with this name
                if len(self.port_name_used[endpoint_dev_name]) == 1:
                    # first device for this name is no longer the only one - update its name
                    first_dev = self.port_name_used[endpoint_dev_name][0]
                    self.dev_name_for_port[first_dev] = ("%s1" % endpoint_dev_name)
                self.port_name_used[endpoint_dev_name].append(dev)
                endpoint_dev_name += ("%u" % len(self.port_name_used[endpoint_dev_name]))
            self.dev_name_for_port[dev] = endpoint_dev_name

    def device_in_dt(self, d):
        return d.type in selected_devtypes

    def devices(self):
        for d in self.platform:
            if self.device_in_dt(d):
                yield d

    def cpu_number(self, d):
        assert d in self.dev_cpu_number, "trying to get CPU number from %s" % str(d)
        return self.dev_cpu_number[d]

    def dt_name(self, d):
        """
        Construct a name for this device.
        """
        if d.type == CS.CS_DEVTYPE_CORE:
            return "cpu%u" % self.cpu_number(d)
        elif d.type in devtype_strings:
            return devtype_strings[d.type]
        else:
            return "unknown_%u_%u" % (d.type[0], d.type[1])

    def dt_compat_name(self, d):
        """
        Return the device type as indicated in the compatibility string:
          compatible = "arm,coresight-etm4x", "arm,primecell";
        This tells the kernel what driver to bind it to.
        """
        if d.type == CS.CS_DEVTYPE_TRACE_CORE:
            # Linux's ETM driver currently needs subarchitecture version
            if d.etm_architecture is not None:
                if d.etm_architecture <= 2:
                    return "etm%ux" % (d.etm_architecture + 1)
                elif d.etm_architecture == 3:
                    return "ptm"
                else:
                    return "etm%ux" % (d.etm_architecture)
            else:
                return "etm"
        elif d.type in devtype_strings:
            return devtype_strings[d.type]
        else:
            return "unknown_%u_%u" % (d.type[0], d.type[1])

    def dt_type_name(self, d):
        return self.dt_name(d)

    def dt_port_id(self, p, end):
        # p is a Link. is_input is the end of the link as seen from the
        # device point of view - i.e. True for the far (slave) end of the link.
        assert isinstance(p, CS.Link)
        d = p.device(end)
        if True:
            all_devices = list(self.platform)
            assert d in all_devices
        global dt_out_ports, dt_in_ports
        try:
            namen = self.dev_name_for_port[d]
        except:
            print("can't find %s" % d)
            for x in self.dev_name_for_port:
                print("  %s: %s" % (str(x), self.dev_name_for_port[x]))
                if x == d:
                    print("     !!!!")
            assert False
        pid = "%s_%s_port" % (namen, ["out","in"][end==CS.CS_LINK_SLAVE])
        pno = p.link_port(d)
        if pno is not None:
            pid += "%u" % pno
        return pid

    def print_port(self, d, p, pfx):
        if o_diag_ports:
            print("%s/* %s */" % (pfx, p))
        de = p.device_end(d)
        assert de is not None, "link %s doesn't connect %s" % (str(p), str(d))
        other_d = p.other(d)
        print("%s%s: endpoint {" % (pfx, self.dt_port_id(p, de)))
        if self.style == 1 and de == CS.CS_LINK_SLAVE:
            print("%s\tslave-mode;" % pfx)
        print("%s\tremote-endpoint = <&%s>;" % (pfx, self.dt_port_id(p, CS.other_end(de))))
        print("%s};" % pfx)

    def addr_reg_string(self, addr, size):
        if self.addr64:
            return "<%#x %#x 0 %#x>" % (addr >> 32, addr & 0xffffffff, size)
        else:
            return "<%#x %#x>" % (addr, size)

    def write(self):
        print("/*")
        print(" * Device Tree source fragment (for guidance only)")
        if self.platform.source_file is not None:
            print(" *")
            print(" * derived from %s" % self.platform.source_file)
        print(" */")
        print("")
        print("/* auto-generated */")     
        def plural(n):
            if n > 1:
                return "s"
            else:
                return ""
        def link_in_dt(p):
            return p.linktype == CS.CS_LINK_ATB 
        def filter_ports(pl):
            return filter(link_in_dt, pl)
        dt_in_ports = {}
        dt_out_ports = {}
        for d in self.devices():
            dt_in_ports[d] = filter_ports(d.inlinks)
            dt_out_ports[d] = filter_ports(d.outlinks)
        # See if we're going to be using 64-bit addresses
        self.addr64 = False
        for d in self.devices():
            if d.is_memory_mapped() and d.mem_address > 0xffffffff:
                self.addr64 = True
                break
        for d in self.devices():
            print()
            if d.is_memory_mapped():
                print("%s%s@0,%08lx {" % (self.prefix, self.dt_name(d), d.mem_address))
            else:
                print("%s%s {" % (self.prefix, self.dt_name(d)))
            compat = "\"arm,coresight-%s\"" % self.dt_compat_name(d)
            if d.is_memory_mapped():
                compat += ", \"arm,primecell\""
            print("%s\tcompatible = %s;" % (self.prefix, compat))
            if d.is_memory_mapped():
                print("%s\treg = %s" % (self.prefix, self.addr_reg_string(d.mem_address, 0x1000)), end="")                
                if self.dt_type_name(d) == "stm":
                    # Currently the STM driver requires a stimulus base address.
                    sb = d.stimulus_base_address
                    size = 0x1000000
                    if sb is None:
                        sb = 0x0BAD0BAD
                    print(", %s;" % (self.addr_reg_string(sb, size)))
                    print("%s\treg-names = \"stm-base\", \"stm-stimulus-base\"" % self.prefix, end="")
                print(";")
            else:
                print("%s\t/* device is not memory-mapped */", self.prefix)
            if self.clocks or self.clock_names:
                print()
                if self.clocks:
                    print("%s\tclocks = %s;" % (self.prefix, ", ".join([("<&%s>" % s) for s in self.clocks])))
                if self.clock_names:
                    print("%s\tclock_names = %s;" % (self.prefix, ", ".join([("\"%s\"" % s) for s in self.clock_names])))
            # In the device tree, a CPU-related device (including the 'core debug' device)
            # is linked to the device tree's CPU node.
            if d.cpu_number is not None:
                print()
                print("%s\tcpu = <&CPU%u>;" % (self.prefix, d.cpu_number))
            # should now remove the ports that DT doesn't describe
            in_ports = filter_ports(d.inlinks)
            out_ports = filter_ports(d.outlinks)
            ports = in_ports + out_ports
            o_diag_ports = False 
            if ports:
                print()
                if o_diag_ports:
                    for ln in ports:
                        print("%s\t/* %s */" % (self.prefix, ln))
                if self.style == 1:
                    print("%s\tport%s {" % (self.prefix, plural(len(ports))))
                if self.style == 1 and len(ports) == 1:
                    self.print_port(d, ports[0], self.prefix + "\t\t")
                else:
                    # Port numbers on multiport devices have a single 32-bit 'address'.
                    if self.style == 1:
                        print("%s\t\t#address-cells = <1>;" % self.prefix)
                        print("%s\t\t#size-cells = <0>;" % self.prefix)
                    i = 0
                    for (pn, p) in enumerate(ports):
                        is_input = (p.slave == d)
                        first = False
                        if pn == 0 and is_input:
                            if self.style == 1:
                                print("%s\t\t/* %s input port%s */" % (self.prefix, self.dt_name(d), plural(len(in_ports))))                        
                            else:
                                print("%s\tin-ports {" % (self.prefix))
                            first = True
                        elif pn == len(in_ports):
                            if self.style == 1:
                                print("%s\t\t/* %s output port%s */" % (self.prefix, self.dt_name(d), plural(len(out_ports))))
                            else:
                                print("%s\tout-ports {" % (self.prefix))
                            i = 0
                            first = True
                        if first and self.style >= 2:
                            print("%s\t\t#address-cells = <1>;" % self.prefix)
                            print("%s\t\t#size-cells = <0>;" % self.prefix)
                        print("%s\t\tport@%u {" % (self.prefix, pn))
                        print("%s\t\t\treg = <%u>;" % (self.prefix, p.link_port(d)))
                        self.print_port(d, p, self.prefix + "\t\t\t")
                        print("%s\t\t};" % self.prefix)
                        i += 1
                print("%s\t};" % self.prefix)
            print("%s};" % self.prefix)


def gen_dts(p, file=None):
    """
    Write a DTS fragment to standard output or a file.
    """
    if file is None:
        file = sys.stdout
    oo = None
    if file != sys.stdout:
        oo = sys.stdout
        sys.stdout = file
    # Currently our writer only writes to sys.stdout.
    dtw = DTWriter(p)
    dtw.write()
    if oo is not None:
        sys.stdout = oo


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        p = CS.load(arg)
        gen_dts(p)
 
