/*!
 * \file       cs_stub_devmemd.h
 * \brief      Stub API for accessing device via devmemd for testing
 *
 * \copyright  Copyright (C) ARM Limited, 2021. All rights reserved.
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

#ifndef _included_cs_stub_devmemd_h
#define _included_cs_stub_devmemd_h

#include <stdint.h>

extern void devmemd_init();

extern uint32_t devmemd_read32(unsigned long addr);
extern uint64_t devmemd_read64(unsigned long addr);

extern void devmemd_write32(unsigned long addr, uint32_t data);
extern void devmemd_write64(unsigned long addr, uint64_t data);

extern void devmemd_close();

#endif /* included */
