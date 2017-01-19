/*!
 * \file       cs_trace_sink.h
 * \brief      CS Access API - functionality relating to trace sinks and buffers
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

#ifndef _included_cs_trace_sink_h
#define _included_cs_trace_sink_h

/** \defgroup tracesink Generic device programming API for trace sinks and buffers
 * Provides enable / disable, along with triggers and trace extraction for generic buffers.
 *
 * Supports standard ETB, TMC in ETB mode, TMC in ETF mode - programmed as Circular buffer.
 * @{
 */

/** Check if sink is enabled */
int cs_sink_is_enabled(cs_device_t dev);

/**
   Enable a trace sink
*/
int cs_sink_enable(cs_device_t dev);

/**
   Disable a trace sink to stop it generating back-pressure
*/
int cs_sink_disable(cs_device_t dev);

/** Disable all TPIUs in the system */
int cs_disable_tpiu(void);


/** Get buffer RAM size in bytes, for a trace buffer */
int cs_get_buffer_size_bytes(cs_device_t dev);

/** Set buffer trigger counter
 *  This stops the trace capture a defined time after the trigger event has been seen.
 *
 *  \param dev    Device descriptor
 *  \param bytes  Number of bytes of trace to be written to the buffer following the trigger event.
 *
 * Set to a large value to capture trace after the event.
 * Set to a small value to capture trace before the event.
 * Set to half the size of the trace RAM to capture trace around the event.
 */
int cs_set_buffer_trigger_counter(cs_device_t dev, unsigned int bytes);

/** Check whether the buffer has wrapped since being initialized */
int cs_buffer_has_wrapped(cs_device_t dev);

/** Get number of bytes that have not yet been destructively read from the buffer */
int cs_get_buffer_unread_bytes(cs_device_t dev);

/** Retrieve trace data from a buffer device, destructively */
int cs_get_trace_data(cs_device_t dev, void *buf, unsigned int size);

/** Empty a trace buffer by resetting the write and read pointers.
 *  After this call, cs_get_buffer_unread_bytes() will return zero
 *  and cs_buffer_has_wrapped() will return false.
 *  Emptying the buffer does not overwrite its contents,
 *  for that see cs_clear_trace_buffer().
 */
int cs_empty_trace_buffer(cs_device_t dev);

/** Clear the contents of a trace buffer device by overwriting it
 *  with a given data word.  Then set the trace buffer to empty
 *  as for cs_empty_trace_buffer().
 *
 *  \param dev   The buffer device (e.g. ETB)
 *  \param data  Data to write in - e.g. 0, 0xCDCDCDCD etc.
 */
int cs_clear_trace_buffer(cs_device_t dev, unsigned int data);  

/** Insert trace data into a buffer device.
 *  This is provided mainly for testing purposes.
 *  If the data being written is the size of the buffer, or greater,
 *  the buffer will be marked as having wrapped.
 *
 *  \param dev   The buffer device
 *  \param buf   Trace data to write into the buffer
 *  \param size  Size of the data, in bytes
 */
int cs_insert_trace_data(cs_device_t dev, void const *buf, unsigned int size);


/** @} */

#endif /* _included_cs_trace_sink_h */

/* end of  cs_trace_sink.h */
