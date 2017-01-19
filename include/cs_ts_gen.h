/*!
 * \file       cs_ts_gen.h
 * \brief      CS Access API - program CS Timestamp Generator
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

#ifndef _included_cs_ts_gen_h
#define _included_cs_ts_gen_h

#include "cs_types.h"

/** 
 * @defgroup ts_gen Timestamp Generator.
 *
 *  @brief  Configuration and use of the CoreSight Timestamp generator component.
 *
@{
*/

/** @defgroup ts_ty Timestamp Generator Types 
    @ingroup ts_gen

    @brief Types used in the API for the CoreSight Timestamp Generator.

@{*/

/** 
 * @brief TS generator access type.
 *  
 * timestamp generators have two possible access interfaces, one read-only and one read-write for 
 * configuration and control. 
 * 
 * Generators in a CoreSight system must implement the read-write interface, but this API can 
 * be connected to a system generator that has the read-only access.
 * 
 */
typedef enum {
    TSGEN_INTERFACE_CTRL,     /**< interface is the control interface - used for both CS and secure control of system generic time. */
    TSGEN_INTERFACE_RO	      /**< interface is the read-only access interface - used if generator using system generic time. */
} cs_ts_gen_interface_t;


/** 
 * @brief Timestamp Generator configuration.
 *
 */
typedef struct cs_ts_gen_config {
    cs_ts_gen_interface_t if_type; /**< marks this API object as attached to a read-write or read-only interface */
} cs_ts_gen_config_t;

/** @}*/

/** @defgroup ts_api Timestamp Generator API.
    @ingroup ts_gen

    @brief API to control and read a CoreSight timestamp generator.

    Simplest implementation will enable the generator to ensure timestamps appear in 
    all the enabled CoreSight trace sources. Use cs_tsgen_enable() or cs_trace_enable_timestamps()
    on the device to do this.

    This cs library object can be used to monitor a TS generator where only the Read Only interface
    is possible - e.g. a system timestamp generator outside the CoreSight trace system.
@{*/

/*!
 * @brief Read the current 64 bit value from the TS generator. 
 * 
 * Will over-sample to ensure that a wrap of the lower
 * 32 bits does not lead to an incorrect value and the appearance 
 * of the value going backwards
 *
 * @param dev : A CS TS generator device.
 * @param value : pointer to location to return the current value.
 *
 * @return uint64_t  : 0 for success, -1 if device is not a TS gen, or value pointer is NULL
 */
int cs_tsgen_readvalue(cs_device_t dev, uint64_t * value);

/*!
 *  @brief Set the TS generator timestamp value.
 * 
 *
 * @param dev : TS generator device.
 * @param value : Timestamp value to set.
 *
 * @return int  : 0 for success, -1 if not a TS gen, or is RO type.
 */
int cs_tsgen_set_value(cs_device_t dev, uint64_t value);

/*!
 *  @brief Enable or disable the TS generator.
 * 
 * Note: the function cs_trace_enable_timestamps() will also enable a TS gen.
 *
 * @param dev : TS generator device.
 * @param enable : 0 to disable, none 0 to enable.
 *
 * @return int  : 0 for success, -1 if not a TS gen, or is RO type.
 */
int cs_tsgen_enable(cs_device_t dev, int enable);

/*!
 *  @brief Set or clear the halt on debug control bit.
 *
 * @param dev : TS generator device.
 * @param dbg_halt : 0 or 1 value for the halt on debug control bit.
 *
 * @return int  : 0 for success, error value if not a TS gen, RO type.
 */
int cs_tsgen_set_dbg_halt(cs_device_t dev, int dbg_halt);

/*!
 *  @brief Check for debug halt.
 *
 * Check the status register to determine if the TS generator
 * is halted in debug.
 *
 * @param dev :  TS generator device.
 *
 * @return int  : 1 if halted, 0 if running, or not TS gen / RO device.
 */
int cs_tsgen_status_is_dbg_halted(cs_device_t dev);

/*!
 *  @brief Set the frequency ID register value on the TS generator 
 *
 * @param dev :  TS generator device.
 * @param freq : Freq ID value to set.
 *
 * @return int  :  0 for success, -1 if not a TS gen, or RO type.
 */
int cs_tsgen_set_freq_id(cs_device_t dev, uint32_t freq);

/*!
 *  @brief Get the frequency ID register value on the TS generator 
 *
 * @param dev : TS generator device.
 * @param *freq : Return Freq ID value
 *
 * @return int  : 0 for success, -1 if not a TS gen or RO type.
 */
int cs_tsgen_get_freq_id(cs_device_t dev, uint32_t * freq);

/*!
 *   @brief Mark libray object attached to RO interface.
 *
 * Marks this device object as being attached to a system 
 * timestamp generator, with only the RO interface accessible at
 * the registered component base address.
 *
 * The cs_tsgen_readvalue() will work correctly using the RO
 * interface offsets. All other API fns will return an error.
 *
 * @param dev : device to be marked as RO TS gen.
 *
 * @return int : 0 for success, -1 if not a TS generator.
 */
int cs_tsgen_config_as_ro(cs_device_t dev);

/** @}*/

/** @}*/

#endif				/* _included_cs_ts_gen_h */
