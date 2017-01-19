/*
High-resolution timestamps

Copyright (C) ARM Ltd. 2016.  All rights reserved.

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

/*
This file provides a consistent but efficient way of handling
nanosecond-resolution timestamps as scalars.

It allows application code to avoid dealing with 'struct timespec'.
*/

#ifndef __included_tns_h
#define __included_tns_h

/*
Nanoseconds since the epoch (1 Jan 1970).
*/
typedef unsigned long long ns_epoch_t;

/*
Nanoseconds as a delta.
*/
typedef signed long long ns_delta_t;

/*
Calculate the delta between two times - from the first one to the second one.
*/
static inline
ns_delta_t tns_delta(ns_epoch_t a, ns_epoch_t b)
{
    return (signed long long)b - (signed long long)a;
}

/*
Initialize any timestamp conversion factors.
*/
void tns_init(void);

/*
Get the current time.
*/
ns_epoch_t tns_now(void);

/*
Get an epoch-based timestamp from the local_clock() / CLOCK_MONOTONIC_RAW
timestamp used in perf timestamps.
*/
ns_epoch_t tns_from_perf(unsigned long long t);

#endif /* included */

