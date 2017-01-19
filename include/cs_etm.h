/*!
 * \file       cs_etm.h
 * \brief      CS Access API - ETM/PTM programming
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

#ifndef _included_cs_etm_h
#define _included_cs_etm_h

#include "cs_etm_types.h"
#include "cs_etmv4_types.h"

/**
   \defgroup etm_ptm Programming API for ETMs and PTM.
   @ingroup etm_api

   API calls used in programming ETM v3.x, ETM v4.x or PTM v1.x.

   @{
*/

/** @name ETMv3 and PTM API
    @{
*/

/** @brief Initialize an ETMv3/PTM configuration structure.
 
    Data zeroed, request flags for counters/comparators set to 
    access all.

    @param etm_config Pointer to ETMv3 configuration structure.
     
*/
int cs_etm_config_init(struct cs_etm_config *etm_config);

/** @brief Read the configuration.
    Read the configuration from the ETMv3 device hardware.

    @param dev Hardware device to access.
    @param etm_config Pointer to ETMv3 configuration structure.
 
*/
int cs_etm_config_get(cs_device_t dev, struct cs_etm_config *etm_config);

/** @brief Write the configuration.
    Write the configuration to the ETMv3 device hardware.

    @param dev Hardware device to access.
    @param etm_config Pointer to ETMv3 configuration structure.
 
*/
int cs_etm_config_put(cs_device_t dev, struct cs_etm_config *etm_config);

#ifndef UNIX_KERNEL
/** Print an ETMv3/PTM configuration. (not available in the UNIX_KERNEL build) */
int cs_etm_config_print(struct cs_etm_config *);
#endif

/** @} */


/** @name Generic ETM configuration API
 
    Opaque pointers used to allow for different configuration structures
    across ETM architectures. Appropriate sturcture and hardware access according to 
    the version of the ETM architecture.
    @{
*/

/** @brief Initialize an ETM configuration structure.
 
    Data zeroed, request flags for counters/comparators set to 
    access all.

    @param dev Hardware device to access.
    @param etm_config Pointer to an appropriate ETM configuration structure.
     
*/
int cs_etm_config_init_ex(cs_device_t dev, void *etm_config);

/** @brief Read the configuration.
    Read the configuration from the ETM device hardware.

    @param dev Hardware device to access.
    @param etm_config Pointer to an appropriate ETM configuration structure.
 
*/
int cs_etm_config_get_ex(cs_device_t dev, void *etm_config);

/** @brief Write the configuration.
    Write the configuration to the ETM device hardware.

    @param dev Hardware device to access.
    @param etm_config Pointer to an appropriate ETM configuration structure.
 
*/
int cs_etm_config_put_ex(cs_device_t dev, void *etm_config);

#ifndef UNIX_KERNEL
/** @brief Print an ETM configuration. 

    (not available in the UNIX_KERNEL build) 

    @param dev Hardware device to access.
    @param etm_config Pointer to an appropriate ETM configuration structure.
*/
int cs_etm_config_print_ex(cs_device_t dev, void *etm_config);
#endif

/** @} */


/** @name Common ETM API
    @{*/

/** Put an ETM into a "clean" state.  This is not necessarily a "reset"
 * state as an ETM reset does not initialize the registers.
 * On exit from cs_etm_clean():
 *   Counters will be zeroed and incrementing NEVER.
 *   Sequencer will be in state 0 with all transitions NEVER.
 *   External outputs will all be NEVER.
 *   Trace ID will be retained at the current value.
 */
int cs_etm_clean(cs_device_t dev);

/** Enable programming mode for an ETM */
int cs_etm_enable_programming(cs_device_t dev);

/** Disable programming mode for an ETM */
int cs_etm_disable_programming(cs_device_t dev);

/** Get version of ETM **/
int cs_etm_get_version(cs_device_t dev);

/**@}*/

/** @name ETM API Deprecated
    @{*/

/** Initialize an ETM configuration structure. 
 *  DEPRECATED: Do not use.
 */
int cs_etm_static_config_init(struct cs_etm_static_config *);

/**@}*/

/** @} */



#endif				/* _included_cs_etm_h */

/* end of  cs_etm.h */
