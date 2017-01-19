/*!
 * \file       cs_types.h
 * \brief      CS Access API - type declarations for API
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

#ifndef _included_cs_types_h
#define _included_cs_types_h

#if defined(__KERNEL__) || defined(MODULE)
#define UNIX_KERNEL 1	     /**< defined if running in kernel (currently experimental) */
#endif				/* __KERNELi__ */

#if !defined(UNIX_USERSPACE) && !defined(UNIX_KERNEL) && !defined(BAREMETAL)
#define UNIX_USERSPACE 1     /**< defined if running as a userspace device driver */
#endif				/* UNIX_USERSPACE */

/** \defgroup cslib_types Global API Type definitions 
 * 
 *  General types used within the CoreSight Access library API.
 *
 * @{
 */


/** \brief Handle to CoreSight component */
typedef void *cs_device_t;

/** \brief For functions that return a device descriptor, CS_ERRDESC indicates an invalid device */
#define CS_ERRDESC ((void *)0)


/** \brief Physical address 
    Defines the size type for a physical address. 
    If library compiled with <tt>\b LPAE</tt> defined then this value will be large
    enough for the 40 bit LPAE extension addresses.
    See \ref buildlib "Building the Library" for information on building the library.
*/
#ifdef LPAE
typedef unsigned long long cs_physaddr_t;
/** printf format to match cs_physaddr_t */
#define CS_PHYSFMT "010llX"    /**< printf format for physical address */
#ifdef UNIX_USERSPACE
#define _FILE_OFFSET_BITS 64
#endif
#else				/* !LPAE */
typedef unsigned long cs_physaddr_t;
#define CS_PHYSFMT "08lX"      /**< printf format for physical address */
#endif				/* LPAE */

/** @brief Virtual address
 *  Defines size type for the virtual addresses - as used in the PC sampling code, and ETM address comparator
 *  programming.  
 *  Uses the <tt>stdint.h</tt> types to explicitly define the virtual address length to enable us to 
 *  compile for a v8 AARCH32 application, but "see" the 64 bit address samples in the core debug registers.
 *  Compile library with <tt>\b CS_VA64BIT </tt> defined to enable 64 bit virtual address sizes.
 *  See \ref buildlib "Building the Library" for information on building the library.
 */
#include <stdint.h>

#ifdef CS_VA64BIT
typedef uint64_t cs_virtaddr_t;
#define CS_VAFMT "010llX"    /**< printf format for virtual address */
#else
typedef uint32_t cs_virtaddr_t;
#define CS_VAFMT "08lX"	     /**< printf format for virtual address */
#endif

/*! @name Device classes
 *
 *  These class definitions are used within the library to determine the function of 
 *  individual devices. Some devices can have multiple associated classes.
 *  e.g. an ETM will have CS_DEVCLASS_SOURCE and CS_DEVCLASS_CPU as it is a trace source
 *       associated with a CPU.
 * @{
 */

#define CS_DEVCLASS_SOURCE     0x001  /**< Trace source */
#define CS_DEVCLASS_SINK       0x002  /**< Trace sink */
#define CS_DEVCLASS_DEBUG      0x004  /**< CPU debug interface */
#define CS_DEVCLASS_PMU        0x008  /**< CPU PMU interface */
#define CS_DEVCLASS_CTI        0x010  /**< Cross-trigger interface (CTI) */
#define CS_DEVCLASS_LINK       0x020  /**< Trace link (funnel, ETF, replicator) */
#define CS_DEVCLASS_CPU        0x040  /**< CPU */
#define CS_DEVCLASS_TIMESTAMP  0x080  /**< Timestamp generator */
#define CS_DEVCLASS_BUFFER     0x100  /**< Trace buffer */
#define CS_DEVCLASS_PORT       0x200  /**< External trace port (TPIU) */
#define CS_DEVCLASS_SWSTIM     0x400  /**< Software trace (ITM, STM) */
#define CS_DEVCLASS_ELA        0x800  /**< Logic Analyzer (Stygian, ELA-500) */
#define CS_DEVCLASS_TRIGSRC   0x1000  /**< Generates triggers only, not trace */


/** @} */

/** \brief CPU index, from zero.  
    The choice of index is determined by the caller. */
typedef int cs_cpu_t;

#define CS_CPU_UNKNOWN ((cs_cpu_t)(-1))	 /**< Device is affine to an unknown CPU */
#define CS_NO_CPU      ((cs_cpu_t)(-2))	 /**< Device is not affine to a CPU */

/** \brief Trace source identifier on the ATB trace bus.
    Valid values are 1..119.  Source ids should be unique within a
    connected trace topology - i.e. the set of all trace sources
    that can send trace to a single trace buffer or port.
    It is recommended that source ids are unique across the whole system.
*/
typedef int cs_atid_t;

/** \brief Power domain id for the device.
 * Identifies which power domain a component is in.  There is assumed
 * to be some hierarchical nesting of power domains.
 */
typedef unsigned int cs_power_domain_t;

/** \brief Device Type
 * 
 * Identifies the type of device.  The type corresponds to the
 * programmer's view - i.e. the register-based programming model
 * exposed by the device.

 * Currently all kinds of ETMs are treated as the same device type
 * even though there are separate architecture documents.
 */
typedef enum {
    DEV_UNKNOWN,  /**< Unknown device */
    DEV_ETM,	  /**< ETM (v3 or v4), or PTM */
    DEV_ITM,	  /**< ITM - Software trace stimulus */
    DEV_STM,	  /**< STM - Software trace stimulus */
    DEV_FUNNEL,	  /**< Trace Funnel */
    DEV_REPLICATOR,   /**< Trace Replicator */
    DEV_ETF,	  /**< Embedded Trace FIFO - Trace memory controller in ETF mode. */
    DEV_ETB,	  /**< Embedded Trace Buffer - legacy trace buffer or TMC in ETB/ETR */
    DEV_TPIU,	  /**< Trace Port Interface - external interface to trace system */
    DEV_SWO,	  /**< Serial Wire Output */
    DEV_CTI,	  /**< Cross Trigger Interface*/
    DEV_CPU_DEBUG,    /**< Core Debug registers */
    DEV_CPU_PMU,      /**< Core PMU registers */
    DEV_TS,	      /**< Timestamp generator */
    DEV_ELA,	      /**< Embedded logic analyzer */
    DEV_MAX	      /**< End of type list */
} cs_devtype_t;


/** Enum type defining the bit operations for the cs_device_wait() function */
typedef enum {
    CS_REG_WAITBITS_ALL_1 = 1,/**< operation value for cs_device_wait() : wait for all bits in mask to go high */
    CS_REG_WAITBITS_ANY_1,  /**< operation value for cs_device_wait() : wait for any bit in mask to go high  */
    CS_REG_WAITBITS_ALL_0, /**< operation value for cs_device_wait() : wait for all bits in mask to go low */
    CS_REG_WAITBITS_ANY_0, /**< operation value for cs_device_wait() : wait for any bit in mask to go low  */
    CS_REG_WAITBITS_PTTRN, /**< operation value for cs_device_wait() : wait for bits to match pattern (both high and low bits) */
    CS_REG_WAITBITS_END	/**< End marker. Not a valid operation. */
} cs_reg_waitbits_op_t;


/** Default define to set the size of a number of fixed device tables in the library.
    
    This will determine the size of certain library elements that have fixed size arrays.
    e.g. arrays of CPUs, CTIs etc. 

    This value can be set in the build environment to build a library suitable for larger 
    devices with multiple core clusters.

    
*/
#ifndef LIB_MAX_CPU_DEVICES
#define LIB_MAX_CPU_DEVICES 32
#endif


/** @} */

#endif				/* _included_cs_types_h */

/* end of  cs_types.h */
