/*!
 * \file       cs_init_manage.h
 * \brief      CS Access API - Library Initialisation and Management.
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

#ifdef __cplusplus
extern "C" {
#endif
#ifndef _included_cs_init_manage_h
#define _included_cs_init_manage_h

#ifdef __STDC_HOSTED__
#include <stdio.h>
#endif

/**
 * \defgroup init Library Management.
 * Library initialisation and management functions
 * @{
 */

/** Initialize the library and start registration */
int cs_init(void);

/** Set the default for diagnostic tracing messages from the API
 *  \param n   set to 1 to produce diagnostic messages
 */
int cs_diag_set(int n);

/** Write diagnostic output the same way the library does.
 */
void cs_diagf(char const *, ...);

#ifdef __STDC_HOSTED__
/** Set the output file for diagnostics. */
int cs_diag_set_fd(FILE *fd);
#endif


/** Lock all components (devices) */
int cs_shutdown(void);


/**
   Release internal claims on all trace devices, e.g. by unsetting the
   internal claim bit.  This allows free use and reprogramming by an
   external debugger.
*/
int cs_release(void);


/** Return the number of programming errors detected so far. */
unsigned int cs_error_count(void);


/** Make all current configuration take effect */
int cs_checkpoint(void);


/** return the version number for the library 
 *  version number in form 0xMMNN:
 *  MM - major version number.
 *  NN - minor version number.
 *
 */
unsigned short cs_library_version();


/** @} */

#endif				/* _included_cs_init_manage_h */

/* end of  cs_init_manage.h */
#ifdef __cplusplus
}
#endif
