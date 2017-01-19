/*!
  \file     cs_util_create_snapshot.h
  \brief    CS Access Utility Library - Create trace snapshot files for DS-5 import.
   
  
  \copyright   Copyright (C) ARM Limited, 2015-2016. All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#ifndef CS_UTIL_CREATE_SNAPSHOT_H
#define CS_UTIL_CREATE_SNAPSHOT_H

#include "csregistration.h"
/** @defgroup cs_lib_snapshot Extract Trace and Create DS-5 Snapshots
    @ingroup cs_lib_utils

    These functions use the devices_t and board structures used in the registration framework, 
    to create a snapshot for import into DS-5. 

    Usage:
    - i)  create the relevant board and devices structures - `setup_board()`.
    - ii) configure the devices ready for trace capture.
    - iii) call `set_kernel_trace_dump_range()` to set the memory area for trace.
    - iv) call `do_dump_config()` to create the snapshot data files.
    - v) Run the trace capture session.
    - vi) call `do_fetch_trace()` to extract the capture trace.

    The snapshot is now ready for import into DS-5.

    @{*/

/*!
 * Set start and and addresses for kernel memory dump.
 * Used when dumping config in `do_dump_config()`
 *
 * @param start : Start Address.
 * @param end : End Address.
 *
 */
void set_kernel_trace_dump_range(unsigned long start, unsigned long end);

/*!
 * Dump kernel memory to a file.
 *
 * @param fn : Output file name.
 * @param start : Start address in kernel virtual memory.
 * @param end : End address in kernel virtual memory.
 */
int dump_kernel_memory(char const *fn, unsigned long start,
		       unsigned long end);

/*!
 * Create the set of snapshot configuration files based on the supplied board structure and
 * devices structure. Creates a set of .ini files and initial memory dumps for import into DS-5
 *
 * Snapshot items for SWSTIM devices (ITM/STM) is optional.
 *
 * @param *board : pointer to the hardware board structure.
 * @param *devices : pointer to the devices configured on the board.
 * @param do_dump_swstim : set none-zero to create SWSTIM snapshot items
 *
 */
void do_dump_config(const struct board *board,
		    const struct cs_devices_t *devices,
		    int do_dump_swstim);

/*!
 * Fetches trace from configured sinks and saves to files required for the snapshot configuration 
 * dumped above.
 *
 * @param *devices : pointer to the devices configured on the board.
 * @param do_dump_swstim : set none-zero to create SWSTIM trace data files.
 *
 */
void do_fetch_trace(const struct cs_devices_t *devices,
		    int do_dump_swstim);

/** @}*/
#endif				/* CS_UTIL_CREATE_SNAPSHOT_H */
