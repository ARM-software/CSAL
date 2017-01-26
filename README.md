CoreSight Access Library        {#mainpage}
========================

The __CoreSight Access Library__ provides an API which enables user code to interact directly with CoreSight trace devices on your target.  
This allows, for example, program execution trace to be captured in a production system without the need to 
have an external debugger connected.  The saved trace can be retrieved later and loaded into DS-5 debugger for analysis.  

The library supports a number of different CoreSight components on several target boards as described in the 
[demos `readme`](@ref demos) file described below. 
  
You can modify the library and demos to support other CoreSight components and/or boards.  An example Linux application 
(`tracedemo`) that exercises the library is provided.  As it runs, `tracedemo` creates several files on the target, 
including the captured trace. Ready-made example capture files are provided that can be loaded into DS-5 debugger.

CoreSight Trace Component Support
---------------------------------

The following trace components are supported by the library:-

- ETMv3.x: used in Cortex A5, A7 cores; Cortex R4, R5 cores.
- PTMv1.x: used in Cortex A9, A15, A17 cores.
- ETMv4.x: Used in Cortex R7 cores.
  Used in **V8 Architecture** Cores - Cortex A57 and A53.
- CoreSight ITM.
- CoreSight STM.
- CoreSight ETB.
- CoreSight TMC in buffer mode.
- CoreSight CTI.
- Global Timestamp Generator.

The library also supports access to the v7 Arch or v8 Arch debug sampling registers,
allowing non intrusive sampling of PC, VMID and ContextID on a running core.

Optional support is provided for intrusive halting mode debug support of v7 Arch debug cores.

Installation
------------

Library supplied as a git repository on github - git@github.com:ARM-software/CSAL.git

`./source` : Contains all the library source .c files.

`./include`: Contains the library API header include files.

`./demos`  : Contains the source and build files for the demonstration programs.

`./build`  : The main library build `Makefile`. Change to this directory to build the library.

`./python` : Build and source files to make a python module to interface to the library. (unmaintained)

`./experimental` : Unmaintained and unsupported additional demos.

`./doxygen-cfg.txt` : File to generate API documentation using __doxygen__.

`./README.md` : This readme text file - which is also processed by __doxygen__.

`./makefile`  : master makefile - `make help` for list of targets.


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

------------------------------------

Licence Information
===================

*Copyright (C) ARM Limited, 2014. All rights reserved.*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:
 
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
