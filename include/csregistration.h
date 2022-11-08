/*! 
  \file     csregistration.h
  \brief    CS Access Utility Library - CoreSight board registration functions
   
  Provides an abstract interface to registering boards with the library (for multiple demos)

  \copyright  Copyright (C) ARM Limited, 2013. All rights reserved.

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

#ifdef __cplusplus
extern "C" {
#endif
#ifndef CS_REGISTRATION_H
#define CS_REGISTRATION_H

#include "csaccess.h"
/** @defgroup cs_lib_reg CoreSight Library Board Registration framework
    @ingroup cs_lib_utils

    Creates and registers a CS library configuration for a given board, using CS Access Libary API calls.

    The devices registered here may later be used to extract trace and create snapshots for DS-5.

    This provides a framework for users to implement board specific registration.
    @{*/

#ifndef LIB_CSREG_MAX_TRACE_SINKS
/** Default define to set the number of trace sinks in the devices_t structure.   

    This value can be set in the build environment to build a library suitable for larger 
    devices with more trace sinks.    
*/
#define LIB_CSREG_MAX_TRACE_SINKS 8
#endif

#ifndef LIB_CSREG_MAX_TRACE_ALT_SRC
/** Default define to set the number of none-core trace sources in the devices_t structure.   

    This value can be set in the build environment to build a library suitable for larger 
    devices with more none-core trace sources.    
*/
#define LIB_CSREG_MAX_TRACE_ALT_SRC 8
#endif

/*! Board devices structure.

  Will contain all the registered trace devices once the board detect process is complete. 
  Used to configure the trace system, create snapshots and extract trace data later.

  Board specific `do_registration` must set this correctly for the board.
*/
struct cs_devices_t {
    unsigned int cpu_id[LIB_MAX_CPU_DEVICES]; /**< CoreSight Core IDs for each of the cores in the system */
    cs_device_t ptm[LIB_MAX_CPU_DEVICES]; /**< Trace source device (ETM/PTM) associated with each core */
    cs_device_t itm;   /**< SWSTIM source on the system (ITM or STM). */
    cs_device_t etb;   /**< ETB style trace buffer (ETB/ETF) for the cores and optionally SWSTIM source. */
    cs_device_t itm_etb;  /**< if non-NULL, alternate ETB for the SWSTIM source if not captured in main ETB. */
    cs_device_t trace_sinks[LIB_CSREG_MAX_TRACE_SINKS];	  /**< Additional sinks (for later library expansion) */
    cs_device_t trace_alt_srcs[LIB_CSREG_MAX_TRACE_ALT_SRC];  /**< Additional none-cores sources (for later library expansion) */
};

/*! Board detect and registration structure. */
struct board {
    /*!
     * Board specific CS Access library registration function.
     * This function is required to create the appropriate devices and fill in the
     * devices structure.
     *
     * @param *devices : pointer to a devices structure to be filled in.
     *
     * @return int  : 0 if successful registration.
     */
    int (*do_registration) (struct cs_devices_t * devices);
							  /**< pointer to board specific registration function */
    int n_cpu;	  /**< number of CPUs on the board. */
    const char *hardware; /**< Name of the hardware - to be matched to a read from `/proc/cpuinfo` */
};

/*!
 * This function initialise the CS access library, try to detect the board hardware in use, based on a supplied list of boards.
 * and return a pointer to the detected board and fill in the devices structure based on a call to the 
 * `do_registration()` function in the board structure. Finally the registration process will be completed
 * with a call to cs_registration_complete().
 *
 * - **Linux systems** : uses the internal `do_probe_board()` function to match the board name 
 *                       from `/proc/cpuinfo` to an entry in `board_list->hardware`. Once a match 
 *                       is found the CPU IDs are filled in from the same location. The boards'
 *                       `do_registration()` is then called.    
 *
 * - **Baremetal**    : This does not use `do_probe_board()` functionality. The `board` pointer is
 *                      set to the first element in `board_list`. The `do_registration()` is then 
 *                      called on this board.
 *
 * @param **board : location of a board structure pointer to be filled if valid board detected
 * @param *devices : location of devices structure to be filled if valid board detected.
 * @param *board_list : array of board structures - used to detect current board.
 *
 * @return int  : 0 if successfully detected board and registered devices.
 */
int setup_board(const struct board **board, struct cs_devices_t *devices,
		const struct board *board_list);

/*! Array of CoreSight CPU IDs ordered by core index. 
    
  On linux systems the index numbers are the core number order defined in `/proc/cpuinfo`,
  and set up in the local `do_probe_board()` function.

  These are transferred into the `cs_devices_t` structure `cpu_id[]` array during the 
  call to `do_registration()` for the specific board.

  On Baremetal implementations, or where the `/proc/cpuinfo` does not have sufficent information,
  then the `do_registration()` must fill in appropriate values in the `devices.cpu_id[]` array.
*/
extern unsigned int cpu_id[LIB_MAX_CPU_DEVICES];

/*! Flag to indicate the registration code should print out verbose messages.
  0 = no verbose messages, defaults to 1 = verbose messages.
*/
extern int registration_verbose;


/*!
 * Selects named board from the board list and uses this to configure the library.
 * Does do the probe hardware that setup_board uses. Returns error if the board name does not 
 * match a hardware name in the board_list. 
 * 
 * Use to force configuration of named board if hardware probe cannot correctly detect the board.
 *
 * @param *board_name : Name of board to configure.
 * @param **board : location of a board structure pointer to be filled if valid board detected
 * @param *devices : location of devices structure to be filled if valid board detected.
 * @param *board_list : array of board structures - used to detect current board.
 *
 * @return int  :  0 if successfully selected board and registered devices.
 */
int setup_named_board(const char *board_name, const struct board **board,
		      struct cs_devices_t *devices,
		      const struct board *board_list);

/** @}*/

#endif
#ifdef __cplusplus
}
#endif
