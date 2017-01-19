/*!
 * \file       cs_etm_v4.h
 * \brief      Internal header for ETMv4 implementation functions.
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

#ifndef _included_cs_etm_v4_h
#define _included_cs_etm_v4_h

#include "cs_access_cmnfns.h"
#include "cs_etmv4_types.h"

int _cs_etm_v4_static_config_init(struct cs_device *d);
int _cs_etm_v4_config_init(struct cs_device *d, cs_etmv4_config_t * c);
int _cs_etm_v4_config_get(struct cs_device *d, cs_etmv4_config_t * c);
int _cs_etm_v4_config_put(struct cs_device *d, cs_etmv4_config_t * c);
int _cs_etm_v4_clean(struct cs_device *d);
int _cs_etm_v4_disable_programming(struct cs_device *d);
int _cs_etm_v4_enable_programming(struct cs_device *d);

#ifndef UNIX_KERNEL
int _cs_etm_v4_config_print(struct cs_device *d, cs_etmv4_config_t * c);
#endif

#endif				/* _included_cs_etm_v4_h */

/* end of  cs_etm_v4.h */
