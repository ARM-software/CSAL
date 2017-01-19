/*!
 * \file       cs_trace_source.h
 * \brief      CS Access API - generic functionality relating to trace sources
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

#ifndef _included_cs_trace_source_h
#define _included_cs_trace_source_h

/** \defgroup tracesource Generic device programming API for trace sources
 *  Provides enable/disable, timestamp and trace ID fucntionality
 * @{
 */

/** Set the trace source id for a component */
int cs_set_trace_source_id(cs_device_t dev, cs_atid_t id);

/** Get the current trace source id for a component */
cs_atid_t cs_get_trace_source_id(cs_device_t dev);

/** Enable a trace source to generate trace */
int cs_trace_enable(cs_device_t dev);

/** Check if trace source is enabled */
int cs_trace_is_enabled(cs_device_t dev);

/** Disable a trace source */
int cs_trace_disable(cs_device_t dev);

/** Enable or disable timestamping on a trace source.
    Enable generation on a TS generator.
*/
int cs_trace_enable_timestamps(cs_device_t dev, int enable);

/** Enable or disable cycle accurate tracing on a trace source */
int cs_trace_enable_cycle_accurate(cs_device_t dev, int enable);

/**
 *  Configure ID filtering on a programmable replicator
 *  \param dev      Replicator
 *  \param port     Output port, 0 or 1
 *  \param filter   Filter, bit 0 for ids 0..15, bit 1 for ids 16..31 etc.
 *  \note           Set a 1 bit in the filter to discard trace for the
 *                  selected ids.
 */
int cs_replicator_set_filter(cs_device_t dev, unsigned int port,
			     unsigned int filter);

/**
   Get the current global timestamp from the system timestamp generator, if available.
*/
int cs_get_global_timestamp(unsigned long long *ts);

/** @} */



#endif				/* _included_cs_trace_source_h */

/* end of  cs_trace_source.h */
