/*!
 * \file       cs_map_local.h
 * \brief      CS Access Library - internal functions to map local memory
 *
 * \copyright  Copyright (C) ARM Limited, 2014-2016. All rights reserved.
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

#ifndef _included_cs_map_local_h
#define _included_cs_map_local_h

#include "cs_types.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void *io_map(cs_physaddr_t addr, unsigned int size, int writable);
extern void io_unmap(void volatile *addr, unsigned int size);
extern int _cs_map(struct cs_device *d, int writable);
extern void _cs_unmap(struct cs_device *d);

#ifdef __cplusplus
}
#endif

#endif /* included */
