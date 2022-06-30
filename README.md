CoreSight Access Library        {#mainpage}
========================

The __CoreSight Access Library__ (CSAL) provides an API which enables user code to interact directly with CoreSight devices on a target.
This allows, for example, program execution trace to be captured in a production system without the need to 
have an external debugger connected.  The saved trace can be retrieved later and loaded into a debugger for analysis. CSAL can be run on application core or a management core.

The library supports a number of different CoreSight components,
and has configurations for several target SoCs and boards as described in the
[demos `readme`](@ref demos) file described below.
  
You can modify the library and demos to support other CoreSight components and/or boards.  An example Linux application 
(`tracedemo`) that exercises the library is provided.  As it runs, `tracedemo` creates several files on the target, 
including the captured trace. Ready-made example capture files are provided that can be loaded into a debugger.

CoreSight Component Support
---------------------------

The following trace components are supported by the library:

- ETMv3.x: used in Cortex A5, A7 cores; Cortex R4, R5 cores.
- PTMv1.x: used in Cortex A9, A15, A17 cores.
- ETMv4.x: Used in Cortex R7 and later R-profile cores.
  Used in **V8 Architecture** Cores - Cortex A and Neoverse cores.
- CoreSight ITM.
- CoreSight STM.
- CoreSight ETB.
- CoreSight TMC in buffer mode.
- CoreSight CTI.
- Global Timestamp Generator.
- CoreSight MEM-AP.
- CoreSight ELA.

The library also supports access to the v7 Arch or v8 Arch debug sampling registers,
allowing non intrusive sampling of PC, VMID and ContextID on a running core.

Optional support is provided for intrusive halting mode debug support of v7 Arch debug cores.

Normally, components are accessed in the local memory space.
The library also supports accessing components through a MEM-AP device.

In addition, it provides several ways to get access to physical memory:
- directly, suitable for a bare-metal system
- as a Linux userspace device driver, by memory-mapping /dev/mem
- using Linux kernel features (this is experimental)
- through a simple OS-hosted network daemon (devmemd, provided in the package), for development

Installation
------------

CSAL is supplied as a git repository on github - git@github.com:ARM-software/CSAL.git

`./source` : Contains all the CSAL library source .c files.

`./include`: Contains the CSAL library API header include files.

`./demos`  : Contains the source and build files for the demonstration programs.

`./build`  : The main library build `Makefile`. Change to this directory to build the library.

`./python` : Build and source files to make a python module to interface to the library. (unmaintained)

`./experimental` : Unmaintained and unsupported additional demos.

`./doxygen-cfg.txt` : File to generate CSAL API documentation using __doxygen__.

`./README.md` : This readme text file - which is also processed by __doxygen__.

`./makefile`  : master makefile - `make help` for list of targets.

`./coresight-tools` : Self-contained Python tools for CoreSight topology discovery.

`./devmemd`   : a simple network daemon to forward memory accesses, for testing during development.


Documentation
-------------

API Documentation is provided inline in the source header files, which use the __doxygen__ standard mark-up.
Run `doxygen` on the `./doxygen-cfg.txt` file located in the library main directory.

    doxygen ./doxygen-cfg.txt

This will produce the documentation in the `./doc/html` directory. The doxygen configuration also includes
the `readme*.md` files as part of the documentation.

Usage
-----

__Building the Library and Demos__:

Run `make` from the root of the installation. This will build the standard version of the library,
and deliver the library into the `./lib/<arch>/rel` directory. The demonstration programs will be
built and linked to the library, delivered into the `./bin/<arch>/rel` directory. 

To use the library in a program include the file `csaccess.h` from the `./include` directory and
link to the built library. 

See [`./build/readme_buildlib.md`](@ref buildlib) for further information on building the library.

See [`./demos/readme_demos.md`](@ref demos) for further information on running the demos.

__Simple usage__:

Each CoreSight component that you need to access (trace unit, funnel, sink etc.)
should be registered with CSAL by calling `cs_device_register`:
see the "CoreSight component and topology registration" section of the API.
You will need to know the physical address of the component.
This may be obtained from a vendor datasheet, or sometimes it is discoverable
from an on-chip ROM table. See `coresight-tools/discovery.md` for more details.
Connections between devices should also be registered with CSAL.

__Accessing components via a MEM-AP__:

On some SoCs, components are accessed indirectly, via a MEM-AP component,
which acts as a gateway into a separate address space.
CSAL supports indirect access via MEM-AP when built with the `CSAL_MEMAP` option.
The MEM-AP device, and any other directly accessible devices, should first
be registered in the usual way,
then `cs_set_default_memap()` should be called to register the MEM-AP as the
owner for new devices.
Subsequent device registrations take place in the address space of the MEM-AP,
and the CSAL API functions can then act on the devices as normal.

Note that access via a MEM-AP makes it especially important to avoid conflicts
between multiple debug agents, to avoid race conditions on the MEM-AP's
transfer registers.
Each MEM-AP component provides two independent transfer areas, the second being at offset 0x1000.
One can be used by an external debugger while the other is used by CSAL.
CSAL will check the settings of MEM-AP's CLAIM register, to check if it is in use
by an external debugger, and will then set the claim bit indicating self-hosted use.
However, note that some external debuggers do not check or set the CLAIM bits.
When using a MEM-AP,
we recommend finding out which half of the MEM-AP is used by the
debugger and using the other half.

__Multithreading__:

CSAL's global state is not thread-safe in general.
However, once components are registered, it should generally be safe to use them
concurrently from different threads as long as two threads are
not writing to (or causing side-effects in) the same component at the same time.
For example, one thread could program a trace unit while another is
monitoring a trace sink and a third is sampling from a PMU,
all via the CSAL APIs.

When components are accessed indirectly via a shared MEM-AP,
access from different threads will attempt to update the MEM-AP.
It will generally be necessary to use some form of locking
so that updates to the MEM-AP's transfer address register and use of its
data transfer registers are within a critical section.
This has not currently been implemented in CSAL.

__Using the Library in Python__:

This experimental code is not built by default.
The ./python directory contains source and makefiles to generate a python module to allow
use of the library. 

See [`./build/readme_python.md`](@ref python) for further information.

------------------------------------

Version and Modification Information
====================================

Version 1.000
-------------

Initial Library Release.

Version 2.000
-------------

Updates to APIs:-
- Added in `cs_library_version()` to management API.
- Added `cs_device_write_masked()`, `cs_device_wait()` and `cs_device_set_wait_repeats()` to the 
  register access API.
- Added `cs_cti_set_active_channel()`, `cs_cti_clear_active_channel()` and `cs_cti_clear_all_active_channels()`
  to the Cross Trigger Low level API.
- Added `cs_trace_enable_cycle_accurate()` to Trace Source API. 
- _Functionality change:_ Function `cs_trace_enable_timestamps()` altered - this will no longer enable cycle accurate 
  tracing at the same time as timestamps are enabled.
- Added in support for ETMv4. New ETMv4 structures added with ETMv4 supported in common API calls.
- Generic ETM programming calls added - `cs_etm_config_init_ex()`, `cs_etm_config_get_ex()` and `cs_etm_config_put_ex()`. 
  These calls can be passed structures to any architecture ETM. 
- Added in support for V8 Architecture debug sampling. 
- _API change_: Function `cs_etm_static_config_init()` deprecated. Not useful in external API.
  
General changes:-
- Source file and directory re-structuring for improved maintenance.
- Examples extended for additional board support. 


Version 2.001
-------------

Updates to APIs:-
- STM support updated. Swstim API enhanced to differentiate between ITM / STM common fns and STM only.
  STM now has dedicated write function targeting extended stim ports.
- _API change_: Function `cs_stm_enable_trigger()` changed to `cs_trace_swstim_enable_trigger()`.
  Function `cs_trace_get_sw_stim_count()` changed to `cs_trace_swstim_get_port_count()`.
- _Functionality change:_ `cs_trace_enable()` on a STM or ITM device will no longer automatically
  enable all stimulus ports and set the sync frequency. These operations must now be done using
  specific API calls. This is to prevent the enable function from over-writing and user set configuration.  
- CoreSight Access Utility library created. This provides the board registration and detection framework
  previously built into the demo code. Also contains the trace extraction and snapshot creation code 
  to allow trace to be imported into DS-5 - format used compatible with DS-5 5.21.  Separation of this code 
  into an auxiliary library allows easier use in custom implementations. 
  Demo build modified to use this aux library. Know board configurations moved into separate file.
- Juno (v8 board) configuration added to known boards in the demos area.


Version 2.002
-------------
Updates to APIs:-
- CoreSight Timestamp (TS) Generator API added.
- `cs_trace_enable_timestamps()` updated to enable TS generation if passed a TS generator type object.
- Updated topology detection to recognise an Embedded Logic Analyser type component.
- Updated documentation for running Juno examples an shipping scripts to set up the platform.

Version 2.3
-------------
- Transfer to github project
- makefile updates for x-compile and master makefile in project root dir.
- moved some code to 'experimental' directory - demos that are not maintained / supported. 

Version 3.0
-----------
- Added support for CoreSight SoC-600 components
- Added support for MEM-AP
- The API now uses types 'uint32_t' and 'uint64_t' for types representing target registers
- Minor portability and languge conformance improvements
- Added support for network connection (devmemd) - a development aid, not intended for production

Version 3.1
-----------
- Added support for CoreSight ELA


------------------------------------

Licence Information
===================

*Copyright (C) ARM Limited, 2014-2021. All rights reserved.*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:
 
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
