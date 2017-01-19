/*!
 * \file       cs_sw_stim.h
 * \brief      CS Access API - software stimulus trace ports
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

#ifndef _included_cs_sw_stim_h
#define _included_cs_sw_stim_h

#include "cs_stm_types.h"

/**
\defgroup sw_stim Software Stimulus Ports

Configuration and use of software stimulus trace ports - ITM and STM

@{
*/

/** @defgroup swstim_api Programming API for STM and ITM
@ingroup sw_stim

Basic API functions are common and can be used with both ITM or STM.
Advanced functions with `_stm_` in the name are for the stm device only.

Initialising for use.
---------------------

The following code will initialise and ITM `dev` for basic use, with all ports 
enabled for operation:-

    cs_trace_swstim_enable_all_ports(dev);
    cs_trace_swstim_set_sync_repeat(dev,32);
    cs_trace_enable(dev);

A similar sequence can be used to initialise the STM. However, if the STM has extended ports
then an additional step is needed to configure at least one master.

    int master_index = 0;
    cs_physaddr_t mast_addr = 0x70000000;
    cs_stm_config_master(dev, master_index, mast_addr);
    cs_stm_select_master(dev,master_index);
    cs_trace_swstim_enable_all_ports(dev);
    cs_trace_swstim_set_sync_repeat(dev,32);
    cs_trace_enable(dev);

@{*/

/*!
 * Return the number of software stimulus ports implemented
 *
 * @param dev : ITM or STM trace device
 *
 * @return int  : number of ports implemented
 */
int cs_trace_swstim_get_port_count(cs_device_t dev);

/** Generate a software trace message on a given port
 * 
 *  This is a generic operation that can target either ITM or STM.
 *
 *  - **ITM** : implements the stimulus port registers - index is in the range 0 to 
 *     num_ports_implemented - 1. For the ITM the number of ports is usually 32.
 *  
 *  - **STM** : the ports used will depend on the features implemented in the STM.
 *     - if extended ports are implemented, then the write will be an `I_DMTS` type,
 *       on the currently configured master using the supplied port index. Index range is `0` to 
 *       `num_ports_implemented - 1`. Number of ports can be up to 65536 for the STM.
 *     - if there are no extended stimulus ports then the STM basic stimulus ports will be used.
 *       There are up to 32 basic stimulus ports on the STM, index in range 0 - 31.
 *  
 *
 *  \param dev    the software trace device (ITM or STM)
 *  \param port   the stimulus port index - must be in valid range for the device
 *  \param value  the stimulus message value (payload)
 */
int cs_trace_stimulus(cs_device_t dev, unsigned int port,
		      unsigned int value);

/*!
 * Enable triggers on stimulus port write.
 * 
 * - **ITM** : Bits 0-31 set trigger on write for ports 0-31 repsectively. 
 * - **STM** : Bits 0-31 set trigger on write for ports 0-31, and any further groups above 
 *             port 31 in the same order (32-63, 64-95 etc).
 *
 * @param dev : STM or ITM device to use.
 * @param mask : bit mask for ports to change
 * @param value : bit values for ports to change.
 *
 * @return int  : 0 for success.
 */
int cs_trace_swstim_enable_trigger(cs_device_t dev, unsigned int mask,
				   unsigned int value);

/*!
 * Enable all SW stimulus ports on the device.
 * - **ITM** : sets all 32 bits in the enable register.
 * - **STM** : sets all 32 bits in the enable register and switches off the port select register
 *             and master select registers, enabling all ports for all masters.
 *
 * @param dev : STM or ITM device to use.
 *
 * @return int  : 0 for success.
 */
int cs_trace_swstim_enable_all_ports(cs_device_t dev);

/*!
 * Set the Sync packet frequency count.
 *  
 * This sets the frequncy that SYNC packets appear in the trace stream.
 * - **ITM** : Value written to `ITMSYNCCTRL` register.
 * - **STM** : Value written to `STMSYNCR[11:0]`. `STMSYNCR[12]` (MODE) set to 0.
 *
 * @param dev : STM or ITM device to use.
 * @param value : Value of counter.
 *
 * @return int  : 0 for success.
 */
int cs_trace_swstim_set_sync_repeat(cs_device_t dev, unsigned int value);

/** Define STM master address.
 *
 *  This function defines the address for a given master and maps that memory
 *  into the application space, to enable ports to be written.
 *
 *  A STM master is a 16MB large memory address space providing
 *  up to 65536 stimulus ports, 256 bytes each. STM architecture
 *  supports more than one groups like this, each group being
 *  a single master aligned to a 16MB boundary.
 *
 *  The software view of the masters in a system and the relationship to master IDs
 *  in STPv2 is implementation dependent. For example on the ARM Juno development board,
 *  all cores see a single master at the same address, but the master ID mapped into 
 *  STPv2 is different depending on the core used and the security state of the access.
 *
 *  \param dev          STM device
 *  \param master       STM master index
 *  \param port_0_addr  Physical address of the first stimulus port for this master.
 *                      (this will be implementation dependent and on the AXI bus).
 *
 *  \return             Zero on success, error code otherwise
 */
int cs_stm_config_master(cs_device_t dev, unsigned int master,
			 cs_physaddr_t port_0_addr);
/*!
 * Select STM master to be used in cs_trace_stimulus() or cs_stm_ext_write()
 *
 * @param dev : STM device
 * @param master : STM master index
 *
 * @return int  : 0 for success, error code if master not configured.
 */
int cs_stm_select_master(cs_device_t dev, unsigned int master);



/*!
 * Write data to the STM extended stimulus port. 
 *
 * The current master is used for the memory base address, with the port index and 
 * operation type defining the offset within that master.
 *
 * Large writes are broken into multiple writes of the size of the fundamental 
 * data size for the implemented STM. 
 *
 * Writes use the supplied transaction type. None data writes will ignore any input data
 * and write 0 to the port.
 * 
 * 
 * @param dev    : STM to use.
 * @param port   : Extended stimulus port to use.
 * @param *value : pointer to write data
 * @param length : length of data to write.
 * @param trans_type : Transaction type.
 *
 * @return int  : 0 for successful operation.
*/
int cs_stm_ext_write(cs_device_t dev, const unsigned int port,
		     const unsigned char *value, const int length,
		     const int trans_type);

/*!
 * Reads a set of configuration registers from the STM. 
 * Registers accessed controlled by the config_op_flags parameter in the stm_config_t
 * structure. Use for advanced configuration of the STM device.
 *
 * @param dev : STM device
 * @param *dyn_config : configuration structure for data read from device.
 *
 * @return int  : 0 for successful operation.
 */
int cs_stm_config_get(cs_device_t dev, stm_config_t * dyn_config);

/*!
 * Writes a set of configuration registers to the STM. 
 * Registers accessed controlled by the config_op_flags parameter in the stm_config_t
 * structure. Use for advanced configuration of the STM device.
 *
 * @param dev : STM device
 * @param *dyn_config : configuration structure for data written to device.
 *
 * @return int  : 0 for successful operation.
 */
int cs_stm_config_put(cs_device_t dev, stm_config_t * dyn_config);

/** @} */

/** @}*/

#endif				/* _included_cs_sw_stim_h */

/* end of  cs_sw_stim.h */
