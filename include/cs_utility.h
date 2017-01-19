/*!
   \file    cs_utility.h   
   \brief   CS Access Utility Library - Auxiliary functions using CS Access API
   
   Set of auxiliary functions that are used by demo code but re-useable in 
   user applications. The functions cover board detection and libary registration,
   and extraction of trace data and creation of a snapshot for DS-5.

  
   \copyright  Copyright (C) ARM Limited, 2015. All rights reserved.

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

#ifndef CS_UTILITY_H
#define CS_UTILITY_H

/** @defgroup cs_lib_utils CoreSight Access Library auxiliary functionality.

   Set of auxiliary functions that are used by demo code but re-useable in 
   user applications. The functions cover board detection and libary registration,
   and extraction of trace data and creation of a snapshot for DS-5.

   Provided as an addtional library to the main CoreSight Access library.

@{*/


#include "csregistration.h"
#include "cs_trace_metadata.h"
#include "cs_util_create_snapshot.h"

/** @}*/
#endif				/*CS_UTILITY_H */
