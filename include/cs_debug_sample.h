/*!
 * \file       cs_debug_sample.h
 * \brief      CS Access API - access core debug sampling registers
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

#ifndef _included_cs_debug_sample_h
#define _included_cs_debug_sample_h

/**
   \defgroup debug Access to Debug Sampling Registers.

   Non - intrusive interface to sampling debug architecture on CPU
   Samples PC plus VMID and CONTEXTID if present from a running core via the debug registers. 

   @{
*/

/**
 *  Sample the program counter on a running CPU. Routine will detect architecture v7 or 
 *  architecture v8 core and sample appropriately. If the library is built for 64bit 
 *  virtual addresses (cs_virtaddr_t) then a 64 bit address will be returned if a v8 64 bit
 *  core is being sampled.
 *
 *  Optionally, CONTEXTID and VMID can be sampled, synchronously with the PC.
 * 
 *  \param dev   device to sample - must be the debug registers on a core.
 *  \param pc    pointer to receive PC virtual address sample. Bit 0 set indicates Thumb state.
 *  \param cid   pointer to receive CONTEXTID sample
 *  \param vmid  pointer to receive VMID sample
 *  @return 0 if valid sample was obtained. -1 if sampling is not possible at present time.
 */
int cs_debug_get_pc_sample(cs_device_t dev, cs_virtaddr_t * pc,
			   unsigned int *cid, unsigned int *vmid);


/** @} */


/* opt out of the halt mode debug by default. */
#ifdef USING_V7_DBG_HALT

#include "cs_debug_halt.h"

#endif				/*  USING_V7_DBG_HALT */


#endif				/* _included_cs_debug_sample_h */

/* end of  cs_debug_sample.h */
