/*!
 * \file       cs_topology.h
 * \brief      CS Access API - ROM table and topology functions
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

#ifndef _included_cs_topology_h
#define _included_cs_topology_h

/*! \defgroup registration CoreSight component and topology registration
 *  
 * \brief Detection and registration of components. Definition of topology.
 *
 * Before the library can be used to program devices, the caller must register
 * the devices using the registration API, so that the library knows the list
 * of devices and their connections. This must be done each time the library is
 * instantiated into a new address space and initialized using cs_init().
 * The library caller is responsible for providing the information to the library,
 * although the library may be able to discover some information e.g. by scanning
 * ROM tables.
 *
 * Device and topology information may come from a variety of sources, e.g.
 *   - device datasheets
 *   - discovery via ROM tables and CoreSight topology detection
 *   - debugger configuration files.
 *
 * The basic registration procedure is:
 *   - register the devices, in any order, either individually or by scanning a ROM table
 *   - register ATB connections between trace devices
 *   - set CPU affinities if required
 *   - register trigger connections between non-CPU devices and CTIs
 *   - call cs_registration_complete()
 *
 * In general it is not necessary to register devices that will not directly or
 * indirectly be used.  Examples of where devices are indirectly used include
 *   - funnels
 *   - non-active trace sinks (e.g. TPIU) that must be disabled to avoid generating back-pressure
 *
 * During the registration phase, programming API calls should not be used.
 * Once the registration phase is complete, cs_registration_complete() should be
 * called and the CoreSight devices can then be programmed.
 *
 * @{ 
 */

/** Register devices listed in a CoreSight ROM table, and any secondary ROM tables it points to.
 *  cs_exclude_range() can be used to exclude ranges of device addresses.
 */
int cs_register_romtable(cs_physaddr_t addr);

/** Register a device.  Device type and properties will be automatically discovered.
 *  If device is already registered then no change is made.
 *  \param addr Physical address of the device
 * 
 *  \return pointer to registered device.
 */
cs_device_t cs_device_register(cs_physaddr_t addr);

/** Exclude a range of physical addresses from ROM table probing.
    This avoids problems when some components are not accessible
    and would cause bus hangs if probed. */
int cs_exclude_range(cs_physaddr_t from, cs_physaddr_t to);


/** Indicate that a component (such as an ETM or CTI) is attached to a CPU.
    \param dev The component
    \param cpu The CPU
 */
int cs_device_set_affinity(cs_device_t dev, cs_cpu_t cpu);

/** Set the device power domain.
    Where devices have different power domains this sets the number, overriding any value
    extracted from a ROM table.
    \param dev The component.
    \param power_domain The power domain ID number.
 */
int cs_device_set_power_domain(cs_device_t dev,
			       cs_power_domain_t power_domain);

/** Register a trace bus connection between two components.
 *
 *  This API call is used to define the trace bus topology.
 *  Non-programmable one-to-one links (bus resizers, bridges etc.) need not appear.
 *  All other links (ETF, funnels, replicators) should be explicit in the topology.
 *
 *  \param from      Source device
 *  \param from_port Output trace port on source device - may be non-zero for e.g. replicators
 *  \param to        Destination device
 *  \param to_port   Input trace port on destination device - may be non-zero for e.g. funnels
 */
int cs_atb_register(cs_device_t from, unsigned int from_port,
		    cs_device_t to, unsigned int to_port);


/** Check if trace source identifier is valid.  This does not check if the
    trace source identifier is unique in the currently configured system. */
int cs_atid_is_valid(cs_atid_t id);

/** Register a non-programmable (non-memory-mapped) replicator.
 *  This may be necessary to complete the registration of the topology.
 *  \param n_out_ports  Number of output ports of the replicator.
 */
cs_device_t cs_atb_add_replicator(unsigned int n_out_ports);

/** Indicate that registration is complete */
int cs_registration_complete(void);

/** Indicates whether registration is completed.
 */
int cs_registration_completed(void);


/** @} End of component registration section */


/*! \defgroup topologyIterator CoreSight device and topology iterators
 *
 * \brief Set of functions to find devices and navigate the registered topology.
 * @{
 */

/** Get first device in global list. */
cs_device_t cs_device_first(void);

/**
Get next device in global list.

\return Device or CS_ERRDESC if at end of list.
*/
cs_device_t cs_device_next(cs_device_t dev);

/** Macro to iterate over all registered devices */
#define cs_for_each_device(d) \
  for (d = cs_device_first(); d != CS_ERRDESC; d = cs_device_next(d))

/** Get device by physical address */
cs_device_t cs_device_get(cs_physaddr_t addr);

/** Return a count of the registered devices.
 */
unsigned int cs_n_devices(void);

/** Return true if device has all specified classes.
 *  \param dev Device to be tested
 *  \param cls Set of classes, ORed together - e.g. CS_DEVCLASS_SOURCE
 */
int cs_device_has_class(cs_device_t dev, unsigned int cls);

/** Return device type.
 *  \param dev Device to be examined
 *  
 */
cs_devtype_t cs_device_get_type(cs_device_t dev);

/** Retrieve the number of out ports a device has
 *  \param dev Device descriptor
 */
int cs_num_out_ports(cs_device_t dev);

/** Retrieve the number of in ports a device has
 *  \param dev Device descriptor
 */
int cs_num_in_ports(cs_device_t dev);

/** Retrieve the device connected to `dev' via `dev's' `port' as the out port
 *  \param dev Device descriptor
 *  \param port Out port number on `dev'
 */
cs_device_t cs_get_device_at_outport(cs_device_t dev, unsigned int port);

/** Retrieve the input port on some connected device that `dev' is connected to through
 * `dev's' `port'
 *  \param dev Device descriptor
 *  \param port Out port number on `dev'
 */
unsigned char cs_get_dest_inport(cs_device_t dev, unsigned int port);

/** Retrieve the device connected to `dev' via `dev's' `port' as the in port
 *  \param dev Device descriptor
 *  \param port In port number on `dev'
 */
cs_device_t cs_get_device_at_inport(cs_device_t dev, unsigned int port);

/** Retrieve the output port on some connected device that `dev' is connected to through
 * `dev's' `port'
 *  \param dev Device descriptor
 *  \param port In port number on `dev'
 */
unsigned char cs_get_src_outport(cs_device_t dev, unsigned int port);

/** Get the CPU that a device is attached to.
 *
 *  This number is whatever the caller has set up through
 *  cs_device_set_affinity.  It is expected to be a small integer indicating
 *  the CPU number as defined by the OS.
 */
cs_cpu_t cs_device_get_affinity(cs_device_t dev);

/** Get the MPIDR for a CPU-affine device.
 *
 *  This might be 0x0000ccpp for cc=cluster, pp=processor.
 *
 *  Warning: this might read as always zero, depending on CoreSight configuration.
 *
 *  On Linux, the various files in /sys/devices/system/cpu/cpu<n>/topology
 *  may be helpful in relating MPIDR to CPU numbers.
 */
unsigned int cs_device_get_MPIDR(cs_device_t dev);

/**
Given a CPU, get a CPU-specific device of a specific class (e.g. ETM, CTI).
*/
cs_device_t cs_cpu_get_device(cs_cpu_t cpu, unsigned int classes);


/** @} End of topology iteration section */


#endif				/* _included_cs_topology_h */

/* end of  cs_topology.h */
