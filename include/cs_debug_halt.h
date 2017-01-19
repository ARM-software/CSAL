/*!
 * \file       cs_debug_halt.h
 * \brief      CS Access API - access core intrusive debug registers.
 *
 *             Define 'USING_V7_DBG_HALT' to enable these features in the library API headers.
 *             Link to library built with the features enabled.
 * 
 * \copyright  Copyright (C) ARM Limited, 2014. All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _included_cs_debug_halt_h
#define _included_cs_debug_halt_h


/* opt out of the halt mode debug by default. */
#ifdef USING_V7_DBG_HALT

/**
   \defgroup debug_v7_halt Intrusive halt mode debug interface to v7 debug architecture CPU

   * This interface is not present on the standard implementation of the library. 
   * Added for board hardware bring up testing only.
   @{
*/

#define CS_DEBUG_CANCEL_BUS_REQUESTS  0x01   /**< Cancel any outstanding bus requests */

/**
 *  Put a CPU into halted debug state.
 *  If you do this to the current CPU, you should ensure that some other
 *  mechanism (e.g. other CPU, cross-trigger, external debug) is able to
 *  restart the CPU if for some reason this process terminates or deadlocks.
 *  Note that if the halted CPU currently holds an OS lock, there is a chance
 *  that the current process may deadlock if it needs OS interaction while
 *  the other process is halted.  In general, activity between halting
 *  and restarting the other CPU should be kept to a minimum.
 *
 *  \param  flags   Flags e.g. CS_DEBUG_CANCEL_BUS_REQUESTS
 */
int cs_debug_halt(cs_device_t, unsigned int flags);


/**
 *  Debug method-of-entry
 */
typedef enum cs_debug_moe {
    CS_DEBUG_MOE_REQUEST = 0,
    CS_DEBUG_MOE_BREAKPOINT = 1,
    CS_DEBUG_MOE_ASYNC_WATCHPOINT = 2,
    CS_DEBUG_MOE_BKPT_INSTRUCTION = 3,
    CS_DEBUG_MOE_EXTERNAL = 4,
    CS_DEBUG_MOE_VECTOR_CATCH = 5,
    CS_DEBUG_MOE_OS_UNLOCK_CATCH = 8,
    CS_DEBUG_MOE_SYNC_WATCHPOINT = 10
} cs_debug_moe_t;

/**
 *  Check if a CPU is in halted-debug state, and optionally
 *  get the reason for entry (see Table C11-22).
 *
 *  \param dev      device descriptor for CPU
 *  \param reason   pointer to receive method-of-entry code
 */
int cs_debug_is_halted(cs_device_t dev, cs_debug_moe_t * reason);

/**
 *  Attempt to check if a CPU is currently executing instructions.
 *  We do this by clearing a flag that is set by instruction execution
 *  and then by checking the flag a bit later.
 *
 *  The CPU may report as inactive if
 *    - it is in halted debug state
 *    - it is at a WFI
 *    - it is stalled on a very long-latency instruction
 */
int cs_debug_cpu_is_active(cs_device_t);


/**
 *  Execute an instruction on a halted CPU.
 *  
 *  \param  dev   device descriptor for CPU
 *  \param  inst  the ARM instruction to be executed
 */
int cs_debug_exec(cs_device_t dev, unsigned int inst);


#define CS_SYSREG_APSR  0x0000	  /**< System register selector: Application PSR */
#define CS_SYSREG_SPSR  0x0001	  /**< System register selector: Saved PSR */
/**
 *  Read a system register on a halted CPU.
 *
 *  \param dev    device descriptor for CPU
 *  \param reg    System register to read (e.g. CS_SYSREG_APSR)
 *  \param pvalue Pointer to receive system register value
 */
int cs_debug_read_sysreg(cs_device_t dev, unsigned int reg,
			 unsigned int *pvalue);


/**
 *  Read memory from the core's perspective, on a halted CPU.
 *
 *  \param dev    device descriptor for CPU
 *  \param addr   address to read data from
 *  \param pdata  pointer to receive data
 *  \param size   size of data to read, in bytes
 */
int cs_debug_read_memory(cs_device_t dev, cs_virtaddr_t addr, void *pdata,
			 unsigned int size);


/**
 *  Restart a CPU from halted debug state.
 *
 *  \param dev    device descriptor for CPU
 */
int cs_debug_restart(cs_device_t dev);


/**
 *  Read a snapshot of the processor's integer registers.
 *
 *  \param dev    device descriptor for CPU
 *  \param mask   mask of registers to read (bit 0 for R0 etc.)
 *  \param regs   area to read registers to - results are not packed
 */
int cs_debug_read_registers(cs_device_t dev, unsigned int mask,
			    unsigned int *regs);


/** @} */

#endif				/*  USING_V7_DBG_HALT */

#endif				/* _included_cs_debug_halt_h */

/* end of  cs_debug_halt.h */
