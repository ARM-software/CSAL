/*!
 * \file       cs_trace_metadata.h
 * \brief      CS Access Utility Library - Examples : functions to extract component meta-data for post run analysis
 *
 *   Uses CS Access API calls to extract the data required for post run analysis of trace data collected 
 *   in the demo programs 
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

#ifndef _included_cs_trace_metadata_h
#define _included_cs_trace_metadata_h

/** \defgroup tracemeta Extract trace metadata for post run analysis
 * @ingroup cs_lib_utils
 *  Get the meta-data for the trace source components registered in the system.
 * @{
 */


#define CS_METADATA_INI  1   /**< Metadata format #1: .INI file */

/** Get system-wide trace metadata in textual format
 *
 *  \param mtype    Data format e.g. CS_METADATA_INI
 *  \param dev      Device descriptor
 *  \param trace_id Trace index
 *  \param buf      Output buffer
 *  \param size     Size of output buffer - allow 200 bytes per trace source
 *  \param name_buf Buffer to receive name of trace device
 *  \param name_buf_size Size of name buffer
 *  \return         Number of bytes written, or needed
 */
int cs_get_trace_metadata(int mtype, cs_device_t dev, int trace_id,
			  char *buf, unsigned int size, char *name_buf,
			  unsigned int name_buf_size);


/** @} */


#endif /*_included_cs_trace_metadata_h*/

/* end of file cs_trace_metadata.h */
