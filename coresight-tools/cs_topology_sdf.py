#!/usr/bin/python

"""
Read a CoreSight configuration from an SDF file.

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


import sys
import os


from xml.dom import minidom, Node

import cs_topology


o_verbose = 0


sdf_map = {
    "CSETM":           cs_topology.CS_DEVTYPE_TRACE_CORE,
    "CSPTM":           cs_topology.CS_DEVTYPE_TRACE_CORE,
    "ETE":             cs_topology.CS_DEVTYPE_TRACE_CORE,
    "CSATBReplicator": cs_topology.CS_DEVTYPE_REPLICATOR,
    "CSTFunnel":       cs_topology.CS_DEVTYPE_FUNNEL,
    "CSTPIU":          cs_topology.CS_DEVTYPE_PORT,
    "CSETF":           cs_topology.CS_DEVTYPE_FIFO,
    "CSETB":           cs_topology.CS_DEVTYPE_BUFFER,
    "CSSTM":           cs_topology.CS_DEVTYPE_TRACE_SW,
    "CSITM":           cs_topology.CS_DEVTYPE_TRACE_SW,
    "CSELA":           cs_topology.CS_DEVTYPE_ELA,
    "CSELA600":        cs_topology.CS_DEVTYPE_ELA,
    "CSPMU":           cs_topology.CS_DEVTYPE_PMU_CORE,
    "CSCTI":           cs_topology.CS_DEVTYPE_CTI,
    "CSGPR":           cs_topology.CS_DEVTYPE_POWER,
    "Timestamp Generator": cs_topology.CS_DEVTYPE_TIMESTAMP,
    "Timestamp Generator (SoC-600)": cs_topology.CS_DEVTYPE_TIMESTAMP,
    "CMNDTCTraceSource": cs_topology.CS_DEVTYPE_CMN_DTC,
}


sdf_map_link = {
    "ATB":             cs_topology.CS_LINK_ATB,
    "CoreTrace":       cs_topology.CS_LINK_CORE_TRACE,
}


def parent_with_tag(e, tag):
    while e is not None:
        if e.nodeType == Node.ELEMENT_NODE and e.tagName == tag:
            break
        e = e.parentNode
    return e


class SDFDeviceInfo:
    """
    Represent an SDF device element as a Python object, for convenience.
    """
    def __init__(self, xd):
        self.xd = xd
        self.type = xd.attributes["type"].value
        self.name = xd.attributes["name"].value
        self.base_address = None
        self.ap_index = None
        self.dp_memspace = False
        self.cti_base_address = None         # for CPUs only
        self.lock_enable = True              # evidently the default
        xdap = parent_with_tag(xd, "dap")
        self.dap = xdap.attributes["name"].value if xdap else None
        for xci in xd.getElementsByTagName("config_item"):
            cname = xci.attributes["name"].value
            cvalue = xci.firstChild.nodeValue
            if cname == "CORESIGHT_BASE_ADDRESS":
                if self.base_address is None:
                    self.base_address = 0
                self.base_address |= int(cvalue, 16)
            elif cname == "CORESIGHT_BASE_ADDRESS_MSW":
                if self.base_address is None:
                    self.base_address = 0
                self.base_address |= (int(cvalue, 16) << 32)
            elif cname == "CORESIGHT_AP_INDEX":
                # For a device, the index of the AP by which the device is accessed.
                # CORESIGHT_BASE_ADDRESS indicates the device offset.
                # For an AP, the index of the AP itself. CORESIGHT_AP_ADDRESS
                # indicates the address of the AP.
                assert self.ap_index is None
                self.ap_index = int(cvalue, 0)
            elif cname == "CTI_CORESIGHT_BASE_ADDRESS":
                # The device type will be a CPU product name
                self.cti_base_address = int(cvalue, 16)
            elif cname == "CORESIGHT_AP_ADDRESS":
                assert self.base_address is None
                assert self.type == "CSMEMAP"
                self.base_address = int(cvalue, 16)
            elif cname == "CORESIGHT_LOCK_ENABLE":
                # usually "False" here
                self.lock_enable = bool(cvalue)
            elif cname == "CORESIGHT_DP_MEMSPACE":
                self.dp_memspace = bool(cvalue)
            elif cname == "ROM_ENTRY_OFFSET":
                pass
            elif cname in ["GPR_BASE_ADDRESS", "GPR_BASE_ADDRESS_MSW"]:
                pass
            elif cname in ["ICACHE_MAINTENANCE_MODE", "DCACHE_MAINTENANCE_MODE"]:
                # CPU device
                pass
            else:
                print("%s:%s: unexpected config_item: %s" % (self.type, self.name, cname))
        self.info = {}
        xdis = xd.getElementsByTagName("device_info_item")
        for xdi in xdis:
            iname = xdi.attributes["name"].value
            try:
                self.info[iname] = xdi.firstChild.nodeValue
            except Exception:
                pass


class SDFLinkInfo:
    """
    Represent an SDF topology link element as a Python object, for convenience.
    """
    def __init__(self, xl):
        self.type = xl.attributes["type"].value
        self.master = xl.attributes["master"].value
        self.slave = xl.attributes["slave"].value
        try:
            self.master_interface = int(xl.attributes["master_interface"].value)
        except Exception:
            self.master_interface = 0
        try:
            self.slave_interface = int(xl.attributes["slave_interface"].value)
        except Exception:
            self.slave_interface = 0


class SDF:
    """
    Convenience class for dealing with an SDF XML file. This is not intended to be used
    outside this module - instead we build a representation-neutral Platform object.
    """
    def __init__(self, fn):
        with open(fn, "r") as f:
            s = f.read()
        self.xdoc = minidom.parseString(s)
        self.xdevices = self.xdoc.getElementsByTagName("device")
        self.xlinks = self.xdoc.getElementsByTagName("topology_link")
        self.device_by_name = {}

    def devices(self):
        for xd in self.xdevices:
            yield SDFDeviceInfo(xd)

    def links(self, type=None):
        for xl in self.xlinks:
            li = SDFLinkInfo(xl)
            if type is None or type == li.type:
                yield li


def sdf_device_type_probably_cpu(dt):
    """
    In SDF, each CPU (core) object has a sui generis device type,
    e.g. "Cortex-R52". There appears to be no other indication that
    the device is a CPU, e.g. if it's a third party core with a
    vendor originated name.
    """
    if dt.startswith("Cortex-"):
        return True
    if dt.startswith("Neoverse "):
        return True
    return False


def load(fn):
    """
    Given an ArmDS SDF configuration file, build a Platform representation.
    """
    S = SDF(fn)
    p = cs_topology.Platform(auto_split=True, source_file=os.path.basename(fn))
    atb_master_names = {}
    if False and len(list(S.links("ATB"))) == 0:
        print("%s: no ATB topology" % fn, file=sys.stderr)
        return None
    for li in S.links():
        if li.type == "CoreTrace":
            p.create_device(cs_topology.CS_DEVTYPE_CORE, name=li.master)
        elif li.type == "ATB":
            atb_master_names[li.master] = True
    for di in S.devices():
        ctype = None
        #print(di.info, file=sys.stderr)
        if di.type in sdf_map:
            ctype = sdf_map[di.type]
        elif di.type == "CSTMC":
            if "CONFIG_TYPE" not in di.info:
                print("%s: TMC %s expected CONFIG_TYPE" % (fn, di.name), file=sys.stderr)
                tmc_type = None
            else:
                tmc_type = di.info["CONFIG_TYPE"]
            # newer SDFs also have TMC_DEVICE_TYPE indicating TRACE_LINK and TRACE_SINK
            if tmc_type == "ETF":
                if not di.name in atb_master_names:
                    print("%s: '%s' reported as %s %s but not mastering ATB - missing topology?" % (fn, di.name, di.type, tmc_type), file=sys.stderr)
                ctype = cs_topology.CS_DEVTYPE_FIFO
            elif tmc_type == "ETB":
                if di.name in atb_master_names:
                    # This really is bogus TMC type detection
                    print("%s: '%s' reported as %s %s but is ATB master: assuming ETF" % (fn, di.name, di.type, tmc_type), file=sys.stderr)
                    ctype = cs_topology.CS_DEVTYPE_FIFO
                else:
                    ctype = cs_topology.CS_DEVTYPE_BUFFER
            elif tmc_type == "ETR":
                assert (not di.name in atb_master_names)
                ctype = cs_topology.CS_DEVTYPE_ROUTER
            else:
                print("%s: '%s' has unknown TMC config type '%s'" % (fn, di.name, tmc_type), file=sys.stderr)
        elif di.type in ["CSMEMAP", "CSDWT", "CSFPB", "CATU"]:
            continue
        elif sdf_device_type_probably_cpu(di.type):
            d = p.device_by_name(di.name)
            if d is None:
                print("%s: '%s' looks like a core, but not in CoreTrace list" % (fn, di.name), file=sys.stderr)
                ctype = cs_topology.CS_DEVTYPE_CORE
            pass
        else:
            print("%s: '%s' has unknown type '%s'" % (fn, di.name, di.type), file=sys.stderr)
            continue
        if (di.ap_index is None) != di.dp_memspace:
            print("%s: '%s': expect exactly one of DAP index and DP_MEMSPACE" % (fn, di.name), file=sys.stderr)
        # Check if device already exists - might have already been created from CoreTrace
        d = p.device_by_name(di.name)
        dap_name = str(di.ap_index) if di.ap_index else "DP" if di.dp_memspace else "?"
        if di.dap is not None:
            dap_name = di.dap + ":" + dap_name
        if d is None:
            d = p.create_device(ctype, name=di.name, mem_address=di.base_address, dap_name=dap_name)
        else:
            d.set_mem_address(mem_address=di.base_address, dap_name=dap_name)
        if o_verbose:
            print("%s: %s" % (di.type, di.info), file=sys.stderr)
        if "RAM_SIZE_BYTES" in di.info:
            d.ram_size_bytes = int(di.info["RAM_SIZE_BYTES"])
        if "JEP_ID" in di.info:
            # The vendor id e.g. 0x43B for Arm
            d.part_vendor = int(di.info["JEP_ID"], 16)
        if "PERIPHERAL_ID" in di.info:
            # The peripheral id, usually 3 digits, e.g. 0x9EB for a CSSoC-600 funnel
            d.part_number = int(di.info["PERIPHERAL_ID"], 16)
        if "VERSION" in di.info:
            d.version_string = di.info["VERSION"]
        if di.type == "CSTFunnel":
            if "PORT_COUNT" in di.info:
                d.port_count = int(di.info["PORT_COUNT"])
        if di.type == "CSTPIU":
            if "SUPPORTED_PORT_SIZES" in di.info:
                d.port_sizes = di.info["SUPPORTED_PORT_SIZES"]
        if ctype == cs_topology.CS_DEVTYPE_ROUTER:
            if "MEM_WIDTH" in di.info:
                d.mem_width_bits = int(di.info["MEM_WIDTH"])
            if "CATU_DEVICE_NAME" in di.info:
                d.catu_device_name = di.info["CATU_DEVICE_NAME"]
    for li in S.links():
        if not li.type in sdf_map_link:
            continue
        if p.device_by_name(li.master) is not None and p.device_by_name(li.slave) is not None:
            cs_topology.Link(p.device_by_name(li.master), p.device_by_name(li.slave), sdf_map_link[li.type], master_port=li.master_interface, slave_port=li.slave_interface)
        else:
            print("%s: %s topology connects unhandled devices: '%s' -> '%s'" % (fn, li.type, li.master, li.slave), file=sys.stderr)
    return p.check()


def main(argv):
    """
    Basic command-line functionality. Use 'cstopo' for conversions etc.
    """
    import argparse
    parser = argparse.ArgumentParser(description="read SDF system description files (Arm DS)")
    parser.add_argument("--print", action="store_true", help="print topology")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    parser.add_argument("files", type=str, nargs="+", help="SDF files to open")
    opts = parser.parse_args(argv)
    o_verbose = opts.verbose
    for fn in opts.files:
        S = load(fn)
        cs_topology.check_topology(S)
        if opts.print:
            S.show()


if __name__ == "__main__":
    main(sys.argv[1:])
