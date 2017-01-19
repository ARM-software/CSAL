/*
CoreSight topology printing 

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

#ifndef __include_cs_topology_print
#define __include_cs_topology_print

typedef enum {
   CS_TOP_STDC,    /* Standard C */
   CS_TOP_DTS,     /* Linux device tree source fragment */
   CS_TOP_DOT,     /* Dot graph */
   CS_TOP_MAX
} cs_topology_format_t;

#include <stdio.h>

int cs_print_topology(FILE *, cs_topology_format_t);

#endif /* included */

