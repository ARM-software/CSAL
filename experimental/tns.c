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

#include "tns.h"

#include <time.h>


static ns_epoch_t boot_time;


static unsigned long long timespec_ns(struct timespec const *a)
{
    return a->tv_nsec + a->tv_sec*1000000000ULL;
}


ns_epoch_t tns_now(void)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    return timespec_ns(&now);    
}


void tns_init(void)
{
    struct timespec now_mono, now_real;
    /* now - epoch */
    clock_gettime(CLOCK_REALTIME, &now_real);
    /* now - boot */
    clock_gettime(CLOCK_MONOTONIC_RAW, &now_mono);
    /* boot - epoch */
    boot_time = tns_delta(timespec_ns(&now_mono), timespec_ns(&now_real));
}


ns_epoch_t tns_from_perf(unsigned long long t)
{
    if (!boot_time) {
        tns_init();
    }
    return t + boot_time;
}

