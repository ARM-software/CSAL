/*!
 * \file       cs_memap.h
 * \brief      CS Access API - access a MEM-AP device and its address space
 *
 * Only basic features of MEM-AP are provided, primarily aimed at when
 * we need to access other CoreSight devices via a MEM-AP.
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

#ifdef __cplusplus
extern "C" {
#endif
#ifndef _included_cs_memap_h
#define _included_cs_memap_h

/**
   \defgroup memap MEM-AP

   Memory-mapped access to MEM-AP devices. This API group provides direct
   access to MEM-AP features and to the memory space beyond the MEM-AP.
   For efficiency, the CSAL object maintains a cached copy of the current
   value of the MEM-AP's Transfer Address Register.

   To register CSAL devices under a MEM-AP, build CSAL with the CSAL_MEMAP
   option and use the @ref cs_set_default_memap API.

   @{
*/


#include <stdint.h>

/**
 * Read a 32-bit word from a location in a MEM-AP's target address space
 * This may update the MEM-AP's TAR and CSAL's locally cached copy.
 *
 * \param device  the MEM-AP device to read through
 * \param addr    the physical address, in MEM-AP space, to read from
 */
uint32_t cs_memap_read32(cs_device_t device, cs_physaddr_t addr);

/**
 * Write a 32-bit word to memory location, via a MEM-AP.
 * This may update the MEM-AP's TAR and CSAL's locally cached copy.
 *
 * \param device  the MEM-AP device to write through
 * \param addr    the physical address, in MEM-AP space, to write to
 * \param data    the 32-bit data to be written
 */
void cs_memap_write32(cs_device_t device, cs_physaddr_t addr, uint32_t data);

/**
 * Read a 64-bit value from a location in a MEM-AP's target address space
 * This may update the MEM-AP's TAR and CSAL's locally cached copy.
 *
 * \param device  the MEM-AP device to read through
 * \param addr    the physical address, in MEM-AP space, to read from
 */
uint64_t cs_memap_read64(cs_device_t device, cs_physaddr_t addr);

/**
 * Write a 64-bit value to memory location, via a MEM-AP.
 * This may update the MEM-AP's TAR and CSAL's locally cached copy.
 *
 * \param device  the MEM-AP device to write through
 * \param addr    the physical address, in MEM-AP space, to write to
 * \param data    the 64-bit data to be written
 */
void cs_memap_write64(cs_device_t device, cs_physaddr_t addr, uint64_t data);


/**
 * Check if the MEM-AP has logged a transfer error, and optionally reset the error.
 *
 * \param device  the MEM-AP device to check
 * \param reset   a flag indicating if a detected error should be reset
 * \result        non-zero if the MEM-AP had logged an error
 */
int cs_memap_check_error(cs_device_t device, int reset);


/**
 * Write the MEM-AP's Transfer Address Register directly.
 *
 * \param device  the MEM-AP device
 * \param addr    the address in the MEM-AP's address space
 */
void cs_memap_write_TAR(cs_device_t device, cs_physaddr_t addr);

/**
 * Read the MEM-AP's Transfer Address Register directly.
 *
 * \param device  the MEM-AP device
 * \result        the TAR's value, an address in the MEM-AP's address space
 */
cs_physaddr_t cs_memap_read_TAR(cs_device_t device);


/**
 * Invalidate the cached copy of the Transfer Address Register.
 *
 * \param device  the MEM-AP device
 */
void cs_memap_invalidate_TAR(cs_device_t device);

/** @} */

#endif /* _included_cs_memap_h */

/* end of cs_memap.h */
#ifdef __cplusplus
}
#endif
