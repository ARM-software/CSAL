/*!
 * \file       cs_pmu.h
 * \brief      CS Access API - access core PMU registers
 *
 * \copyright  Copyright (C) ARM Limited, 2014-2016. All rights reserved.
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

#ifndef _included_cs_pmu_h
#define _included_cs_pmu_h

/**
   \defgroup pmu PMU

   Memory-mapped access to CPU PMUs.

   Access via this interface may conflict with other PMU usage,
   e.g. via the Linux perf subsystem or external profilers.

   @{
*/


typedef unsigned int cs_pmu_mask_t;   /**< Mask of counters, including cycle counter */
#define CS_PMU_MASK_CYCLES ((cs_pmu_mask_t)0x80000000)	 /**< Mask bit for cycle counter */

/**
   Get the number of counters (exclusive of the cycle counter)
   supported by a CPU PMU.
*/
int cs_pmu_n_counters(cs_device_t);

/**
   Read CPU PMU event counts (under mask) and/or the cycle counter.
   The cycle-counter bit (0x80000000 / CS_PMU_MASK_CYCLES) is ignored if in the mask.
   Note that the event counts are read into a packed array, starting from the
   lowest numbered selected counter.

   Any overflow bits in selected counters will be reset.
   This allows you to maintain (in your own code) higher order bits
   of a counter, and use the overflow bits to increment them,
   as long as you take samples reasonably frequently (i.e. several times a second).
*/
int cs_pmu_get_counts(cs_device_t, cs_pmu_mask_t mask,
		      unsigned int *cycles, unsigned int *counts,
		      cs_pmu_mask_t * overflow);


/**
 *  Structure for more general programming/reading of the CPU PMU.
 *
 *  The structure is versioned to allow legacy code to statically link
 *  against newer versions of the API.
 */
typedef struct cs_pmu {
    unsigned int version;    /**< Version field - for future expansion */
    unsigned int div64:1;    /**< Cycle counter divide-by-64 */
    unsigned int cycles;     /**< Cycle counter */
    cs_pmu_mask_t overflow;  /**< Overflow flags for event counters and cycle counter */
    cs_pmu_mask_t mask;	     /**< Mask of counts/events to program/read */
    unsigned int counts[31];	 /**< Event counts */
    unsigned int eventtypes[31]; /**< Event types */
} cs_pmu_t;

#define CS_PMU_VERSION_1   0x01	   /**< Version 1 of the structure */


#define CS_PMU_CYCLES      0x01	   /**< Select the cycle counter */
#define CS_PMU_OVERFLOW    0x02	   /**< Select the overflow flags */
#define CS_PMU_COUNTS      0x04	   /**< Select the event counts */
#define CS_PMU_EVENTTYPES  0x08	   /**< Select the event types */
#define CS_PMU_DIV64       0x10	   /**< Select the divide-by-64 flag */
#define CS_PMU_ENABLE      0x20	   /**< Enable the PMU when done */
#define CS_PMU_DISABLE     0x40	   /**< Disable the PMU when done (or temporarily) */

/**
 * Read status from a CPU PMU, under control of the flags word.
 * The state of the PMU can be controlled during and after the readout,
 * as follows:
 *   
 *  Before    During     After
 *  ------    -----      -----
 *  any       disabled   disabled      CS_PMU_DISABLE
 *  any       disabled   enabled       CS_PMU_DISABLE|CS_PMU_ENABLE
 *  any       same       same          (default)
 *
 * \param  flags   Flags e.g. CS_PMU_CYCLES|CS_PMU_ENABLE
 * \param  status  PMU status data to be read from the PMU
 */
int cs_pmu_read_status(cs_device_t, unsigned int flags, cs_pmu_t * status);

/**
 *  Write status to a CPU PMU, under control of the flags word.
 *
 * \param  flags   Flags e.g. CS_PMU_CYCLES, CS_PMU_ENABLE
 * \param  status  PMU status data to be written to the PMU
 */
int cs_pmu_write_status(cs_device_t, unsigned int flags,
			cs_pmu_t const *status);

/**
 *  Control whether the CPU PMU event bus is exported to ETM etc.
 *  Does not affect interrupt generation.
 *
 * \param  enable  Indicate whether to enable or disable export.
 */
int cs_pmu_bus_export(cs_device_t, int enable);

/**
 *  Reset a CPU PMU.  Valid flags are CYCLES, OVERFLOW, COUNTS, ENABLE, DISABLE.
 *
 * \param  flags   Flags e.g. CS_PMU_CYCLES, CS_PMU_ENABLE
 */
int cs_pmu_reset(cs_device_t, unsigned int flags);


/**
 *  Test if a PMU is enabled.
 */
int cs_pmu_is_enabled(cs_device_t);

/** @} */



#endif				/* _included_cs_pmu_h */

/* end of  cs_pmu.h */
