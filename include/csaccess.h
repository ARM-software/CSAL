/*!
 * \file       csaccess.h
 * \brief      CoreSight Access Library API : On target library for programming CoreSight infrastructure.
 *
 * \copyright  Copyright (C) ARM Limited, 2013. All rights reserved.
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

#ifndef _included_csaccess_h
#define _included_csaccess_h

/* Include headers for the various components */
#include "cs_types.h"	       /**< define of the general API types */
#include "cs_init_manage.h"    /**< Library initialisation and management */
#include "cs_topology.h"       /**< rom table and topology generation and iteration */
#include "cs_reg_access.h"     /**< generic coresight component register access */
#include "cs_trace_source.h"   /**< Generic trace source programming */
#include "cs_etm.h"	       /**< ETM and PTM specific trace source programming */
#include "cs_sw_stim.h"	       /**< SW stimulus - ITM, STM - trace ports */
#include "cs_trace_sink.h"     /**< Generic trace sinks and buffers programming */
#include "cs_cti_ect.h"	       /**< handle CTI and ECT programming */
#include "cs_debug_sample.h"   /**< access core debug registers - PC sampling  */
#include "cs_pmu.h"	       /**< access core PMU registers - event sampling */
#include "cs_ts_gen.h"	       /**< access CS timestamp generator */

#endif				/* included */

/* end of csaccess.h */
