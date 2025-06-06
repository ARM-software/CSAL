/*!
 * \file       cs_reg_access.h
 * \brief      CS Access API - Generic CoreSight register access.
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
#ifndef _included_cs_reg_access_h
#define _included_cs_reg_access_h

/** \defgroup registerlevel Register-level device programming API
 *
 *  Set of API calls to operate on individual device registers.
 *  Registers can be access as complete reads and writes, or individual
 *  bits can be accessed, while leaving other bits unchanged.
 * @{
 */

/** Physical address for device.  
 *  This will be zero for a non-mapped replicator.
 *
 *  For a device accessed via a MEM-AP, it will be the address behind the MEM-AP.
 *
 *   \param dev     device descriptor
 *   \return Physical address for the device.
 *   
 */
cs_physaddr_t cs_device_address(cs_device_t dev);

/** Return the 3-hex-digit CoreSight part number for a device,
 *  e.g. 0x95F for a Cortex-A15 PTM.
 *  It should not normally be necessary to test this part number.
 *   \param dev     device descriptor
 *   \return Value of the CoreSight part number
 */
unsigned short cs_device_part_number(cs_device_t dev);

/** Read a value from a device register 
  *   \param dev     device descriptor
  *   \param offset  register address offset, in bytes
  *   \return        Value in the register.
*/
uint32_t cs_device_read(cs_device_t dev, unsigned int offset);

/** Read a 64-bit value from a pair of device registers
  *   \param dev     device descriptor
  *   \param hioff   register offset for high word
  *   \param looff   register offset for low word
  *   \return        value in the register pair
*/
uint64_t cs_device_read32x2(cs_device_t dev, unsigned int hioff, unsigned int looff);

/** Read a 64-bit value from a 64-bit device register
  *   \param dev     device descriptor
  *   \param offset  offset for the 64-bit register
  *   \return        value in the 64-bit register
*/
uint64_t cs_device_read64(cs_device_t dev, unsigned int off);

/** Write a value to a device register.
  *
  * This should be used for normal configuration registers that are expected to
  * read back the value written.
  *
  *   \param dev     device descriptor
  *   \param offset  register address offset, in bytes
  *   \param data    value to write to the register.
  */
int cs_device_write(cs_device_t dev, unsigned int offset, uint32_t data);

/** Write a value to a 64-bit device register.
  *
  *   \param dev     device descriptor
  *   \param offset  register offset, in bytes
  *   \param data    64-bit value to write to the register
  */
int cs_device_write64(cs_device_t dev, unsigned int offset, uint64_t data);

/** Write a value to a device register.
  *
  * This should be used for write-only registers that do not read back the value written.
  *
  *   \param dev     device descriptor
  *   \param offset  register address offset, in bytes
  *   \param data    value to write to the register.
  */
int cs_device_write_only(cs_device_t dev, unsigned int offset, uint32_t data);

/** Write a value to a device register using a bitmask. 
  *
  * Uses a read-modify-write operation. The value written is masked 
  * with the bitmask - only the bits set in the mask are changed in the written
  * value.
  *
  *   \param dev     device descriptor
  *   \param offset  register address offset, in bytes
  *   \param data    value to write to the register.
  *   \param bitmask bits to write - a '1' bit in the mask will write the bit from the data value.
  */
int cs_device_write_masked(cs_device_t dev, unsigned int offset,
			   uint32_t data, uint32_t bitmask);

/**
 *   Set bit(s) in a device register, using a read-modify-write operation.
 *
 *   \param dev     device descriptor
 *   \param offset  register offset, in bytes
 *   \param bits    bits to set - a '1' bit in the mask will set the bit.
 */
int cs_device_set(cs_device_t dev, unsigned int offset, uint32_t bits);

/**
 *   Clear bit(s) in a device register, using a read-modify-write operation.
 *
 *   \param dev     device descriptor
 *   \param offset  register offset, in bytes
 *   \param bits    bits to clear - a '1' bit in the mask will clear the bit.
 */
int cs_device_clear(cs_device_t dev, unsigned int offset, uint32_t bits);

/**
 *   Wait for bit(s) in a device register, to achieve a given state.
 *   Wait function defined by the enum values in #cs_reg_waitbits_op_t.
 *   Value of register on match (or last failed match value) can be returned if 
 *   <tt> \b p_last_val </tt> pointer is set to a valid location to store the value.
 *
 *   \param dev     device descriptor
 *   \param offset  register address offset within the device, in bytes.
 *   \param bit_mask bit(s) to wait on - bits set to 1 in the mask will be used.
 *   \param operation test operations to use. See the CS_REG_WAITBITS_* enum values.
 *   \param pattern bit pattern to wait for in masked bits. Only used if CS_REGWAIT_BITS_PTTRN used as operation.
 *   \param p_last_val pointer to storage for the last read value of the register.
 * 
 */
int cs_device_wait(cs_device_t dev, unsigned int offset,
		   uint32_t bit_mask, cs_reg_waitbits_op_t operation,
		   uint32_t pattern, uint32_t *p_last_val);


/**
 *   Device data barrier.
 *
 *   This is needed when a device register write must complete
 *   (i.e. be observed by the device) before an access to normal memory.
 */
void cs_device_data_barrier(cs_device_t dev);

/**
 *   Device instruction barrier.
 *
 *   This is needed when a device register write must complete before
 *   any further local code execution. A situation where this might be needed
 *   is when programming the current core's ETM prior to executing code that
 *   must be traced. It should not normally be necessary.
 */
void cs_device_instruction_barrier(cs_device_t dev);


/**
 *   Number of repeat register checks the library will do when waiting on bits to
 *   change in a register. 
 * 
 *   This applies to both the explicit cs_device_wait calls, and implicit library 
 *   functionality such as ETM programming that requires waiting on bits.
 *
 *   Library default is 32.
 *
 *   \param n_wait_repeat_count  number of times a register will be checked for bit value
 */
void cs_device_set_wait_repeats(int n_wait_repeat_count);


/**
 *   Set a flag in our device object to print all register accesses.
 *   Return -1 if the library was not built with this feature enabled.
 *   Default device tracing state is as set by cs_diag_set(), or disabled.
 *   Note that ths is an internal library feature and unrelated to hardware tracing.
 *
 *   \param dev        device descriptor
 *   \param tracing    set to 1 to trace register writes
 */
int cs_device_diag_set(cs_device_t dev, int tracing);


/**
 *   Print out a summary of the device.
 */
void cs_device_diag_summary(cs_device_t dev);


/**
 *   Unlock a device. Not normally necessary - library does it automatically.
 *   May be necessary if another agent has locked the device.
 *
 *   \param dev     device descriptor
 */
int cs_device_unlock(cs_device_t dev);


/**
 *   Lock a device. May be done as a precaution after programming.
 *
 *   \param dev     device descriptor
 */
int cs_device_lock(cs_device_t dev);


/**
 *   Check if a device is powered, if possible.
 *
 *   \param dev     device descriptor
 */
int cs_device_is_powered(cs_device_t dev);
#define CS_POWER_UNKNOWN  -1
#define CS_POWER_OFF       0
#define CS_POWER_ON        1


/** @} */

#endif				/* _included_cs_reg_access_h */

#ifdef __cplusplus
}
#endif
/* end of  cs_reg_access.h */
