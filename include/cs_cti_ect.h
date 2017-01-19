/*!
 * \file       cs_cti_ect.h
 * \brief      CS Access API - program CTI and ECT registers
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

#ifndef _included_cs_cti_ect_h
#define _included_cs_cti_ect_h

/*
  Embedded Cross Trigger
*/

/**
   \defgroup ctilow Cross-trigger low-level (CTI-level) interface

   This supports configuring individual CTI components.
   @{
*/

/** Enable a CTI */
int cs_cti_enable(cs_device_t dev);

/** Disable a CTI */
int cs_cti_disable(cs_device_t dev);

/** Map CTI cross trigger channel(s) to a CTI trigger input port.
 *
 *  @param cti Target CTI device.
 *  @param ctiport TRIGIN port number - maps to a CTIINEN<n> register
 *  @param mask Bitmask defining CTI channels to map - value written to CTIINEN register 
 *
 */
int cs_cti_set_trigin_channels(cs_device_t cti, unsigned int ctiport,
			       unsigned int mask);

/** Map CTI cross trigger channel(s) to a CTI trigger output port.
 *
 *  @param cti Target CTI device.
 *  @param ctiport TRIGOUT port number - maps to a CTIOUTEN<n> register
 *  @param mask Bitmask defining CTI channels to map - value written to CTIOUTEN register 
 *
 */
int cs_cti_set_trigout_channels(cs_device_t cti, unsigned int ctiport,
				unsigned int mask);

/** Control propagation of the selected channels to the cross-trigger matrix. 
 *
 *  @param cti Target CTI device.
 *  @param mask Bitmask defining CTI channels to propogate to CTM - value written to CTIGATE register 
 */
int cs_cti_set_global_channels(cs_device_t cti, unsigned int mask);

/** Return a mask indicating which channels are in use i.e. connected to one or more triggers */
unsigned int cs_cti_used_channels(cs_device_t cti);

/** Pulse a channel active on a CTI.
 *  \param cti      CTI to send the pulse from
 *  \param channel  Channel number (0..3)
 */
int cs_cti_pulse_channel(cs_device_t cti, unsigned int channel);

/** Set a channel active on a CTI.
 *
 * Use the CTI APPSET register to set the correct bit corresponding to the channel number.
 *  \param cti      CTI to set an channel active.
 *  \param channel  Channel number (0..3)
 */
int cs_cti_set_active_channel(cs_device_t cti, unsigned int channel);

/** Clear an output channel on a CTI.
 *  \param cti      CTI to clear an active channel.
 *  \param channel  Channel number (0..3)
 */
int cs_cti_clear_active_channel(cs_device_t cti, unsigned int channel);

/** All channels on a CTI are set to the inactive state.
 *  \param cti      CTI to clear all active channels.
 */
int cs_cti_clear_all_active_channels(cs_device_t cti);


/** 
 * Return a mask indicating which trigger inputs are active.
 * Reads the CTITRIGINSTATUS register.
 *
 * \param cti      Target CTI Device
 */
unsigned int cs_cti_trigin_status(cs_device_t cti);

/** Return a mask indicating which trigger outputs are active. 
 * Reads the CTITRIGOUTSTATUS register.
 *
 * \param cti      Target CTI Device 
 */
unsigned int cs_cti_trigout_status(cs_device_t cti);

/**
 *  Program a CTI to something approximating its reset state:
 *
 *   - the CTI is disabled
 *   - no trigger inputs are connected to any channels
 *   - no channels are connected to any trigger outputs
 *   - channel interface propagation is enabled for all channels
 */
int cs_cti_reset(cs_device_t cti);

/** @} */

/** Show current cross-trigger configuration (to diagnostic stream) */
void cs_cti_diag(void);


/**
   \defgroup ctiregistration Cross-trigger registration interface

   This API group tells the library about how the trigger
   inputs and outputs on non-CTI components (ETMs, ETBs etc.),
   are connected to CTI ports in the cross-trigger fabric.

   It is not necessary to register the connections between CPU
   triggers (e.g. EDBGRQ) and the CPU's own CTI.

   @{
*/

/**
   Trigger source object.  This is a trigger output port on some device.
*/
typedef struct {
    cs_device_t cti;	  /**< CTI device */
    unsigned int ctiport; /**< CTI input port (0..7) */
} cs_trigsrc_t;

/**
   Trigger destination object.  This is a trigger input port on some device.
*/
typedef struct {
    cs_device_t cti;	  /**< CTI device */
    unsigned int ctiport; /**< CTI output port (0..7) */
} cs_trigdst_t;

/** Create a trigger source object */
cs_trigsrc_t cs_cti_trigsrc(cs_device_t cti, unsigned int portid);

/** Create a trigger destination object */
cs_trigdst_t cs_cti_trigdst(cs_device_t cti, unsigned int portid);

/** Get the CTI for a trigger source object */
cs_device_t cs_trigsrc_cti(cs_trigsrc_t src);

/** Get the CTI input port number from a trigger source object. 
    _FUNCTION NOT IMPLEMENTED_
*/
unsigned int cs_trigsrc_portid(cs_trigsrc_t src);	/* NOT IMPLEMENTED */

/** Get the CTI for a trigger destination object */
cs_device_t cs_trigdst_cti(cs_trigdst_t dst);

/** Get the CTI output port number for a trigger destination object.
    _FUNCTION NOT IMPLEMENTED_
*/
unsigned int cs_trigdst_portid(cs_trigdst_t dst);	/* NOT IMPLEMENTED */




/** @name Device Trigger Signal Port Numbers
    Zero based indexes for the Trigger I/O connected from trace components 
    to CTI devices.
    @{*/
#define CS_TRIGIN_CPU_EDBGRQ 0	      /**< CPU EDBGRQ - request to enter halted debug state */
#define CS_TRIGIN_CPU_DBGRESTART 1    /**< CPU DBGRESTART - request to exit halted debug state */

#define CS_TRIGOUT_CPU_DBGTRIGGER 0   /**< CPU DBGTRIGGER - CPU has accepted request to enter debug state */
#define CS_TRIGOUT_CPU_EXTOUT0 1      /**< CPU EXTOUT0 - external output #0 from ETM */

#define CS_TRIGIN_ETB_TRIGIN 0	      /**< ETB TRIGIN */
#define CS_TRIGIN_ETB_FLUSHIN 1	      /**< ETB FLUSHIN */

#define CS_TRIGOUT_ETB_ACQCOMP 0      /**< ETB ACQCOMP - acquisition complete */
#define CS_TRIGOUT_ETB_FULL 1	      /**< ETB FULL */

#define CS_TRIGIN_TPIU_TRIGIN 0	      /**< TPIU TRIGIN */
#define CS_TRIGIN_TPIU_FLUSHIN 1      /**< TPIU FLUSHIN */

#define CS_TRIGOUT_ITM_TRIGOUT 0      /**< ITM TRIGOUT */

#define CS_TRIGOUT_STM_TRIGOUTSPTE 0  /**< Pulsed on STMSPTER match */
#define CS_TRIGOUT_STM_TRIGOUTSW   1  /**< Pulsed on write to TRIG extended stimulus port */
#define CS_TRIGOUT_STM_TRIGOUTHETE 2  /**< Pulsed on STMHETER match */
#define CS_TRIGOUT_STM_ASYNCOUT    3  /**< STM Async out trigger*/

#define CS_TRIGIN_STM_HWEVENT_0    0  /**< CTI output connected to edge triggered STM HW event input */
#define CS_TRIGIN_STM_HWEVENT_1    1  /**< CTI output connected to edge triggered STM HW event input */
#define CS_TRIGIN_STM_HWEVENT_2    2  /**< CTI output connected to edge triggered STM HW event input */
#define CS_TRIGIN_STM_HWEVENT_3    3  /**< CTI output connected to edge triggered STM HW event input */

/** @name CTI trigger connections
    @{*/
/** Output trigger index. 
    The index applies to this library only and designates named trigger output ports on 
    non-CTI components, for example #CS_TRIGOUT_ETB_FULL.
*/
typedef unsigned int cs_trigoutix_t;

/** Input trigger index. 
    The index applies to this library only and designates named trigger input 
    ports on non-CTI components, for example #CS_TRIGIN_ETB_TRIGIN.
*/
typedef unsigned int cs_triginix_t;

/** Register that some device trigger output is connected to a CTI. */
int cs_cti_connect_trigsrc(cs_device_t dev, cs_trigoutix_t devportid,
			   cs_trigsrc_t src);

/** Register that a CTI is connected to some device trigger input. */
int cs_cti_connect_trigdst(cs_trigdst_t dst, cs_device_t dev,
			   cs_triginix_t devportid);

/**
   Find the CTI input port connected to some non-CTI component trigger output port.

   Return an error indicator if not found.
   The error indicator has a CTI of CS_ERRDESC.
*/
cs_trigsrc_t cs_trigsrc(cs_device_t dev, cs_trigoutix_t devportid);

/**
   Find the CTI output port connected to some non-CTI component trigger input port.

   Return an error indicator if not found.
   The error indicator has a CTI of CS_ERRDESC.
*/
cs_trigdst_t cs_trigdst(cs_device_t dev, cs_triginix_t devportid);
/** @}*/

/** @} */

/**
   \defgroup ctimid Cross-trigger mid-level interface, independent of individual CTI components

   The mid-level interface allows the user to specify a cross-trigger channel
   connecting multiple trigger sources to multiple trigger components.
   The library will then map this requested channel to a specific channel number
   within the cross-trigger fabric.

   Where the requested trigger inputs and outputs are local to a single CTI,
   the channel will be gated off from the system-wide cross-trigger fabric.

   The mid-level interface is independent of the semantics of specific trigger
   sources and destinations.

   @{
*/

/** Channel request object.

    Contains a list of output triggers and input triggers.
*/
typedef void *cs_channel_t;

/** Create a new channel request object */
cs_channel_t cs_ect_get_channel(void);

/** Add a trigger output (source) to the channel request */
int cs_ect_add_trigsrc(cs_channel_t chan, cs_trigsrc_t src);

/** Add a trigger input (destination) to the channel request */
int cs_ect_add_trigdst(cs_channel_t chan, cs_trigdst_t dst);

/** Show contents of channel request */
int cs_ect_diag(cs_channel_t chan);

/** Configure the cross-trigger fabric.
    This frees the channel request object. */
int cs_ect_configure(cs_channel_t chan);

/** Reset the system-wide cross-trigger fabric by calling cs_cti_reset() on all CTIs. */
int cs_ect_reset(void);

/** @} */

/** \defgroup cticonns Known CTI connections.
    \ingroup ctiregistration 
    \brief CTI connections from ARM TRM
    

    Lists of CTI connections from ARM TRM material.
    ==============================================

    Indicate that a CTI in/out port is connected to some other component (e.g. ETB, STM).
    These connections will have been decided as part of the SoC design.

    The "trigger port id" on the other component is an index defined for convenience by
    this library - its value does not correspond to anything in the CoreSight architecture.

    Connections from the CPU to its CTI are defined in each CPU's TRM.

    For Cortex-A8 (see Cortex-A8 TRM 15.2):
    ---------------------------------------

    CTI input triggers:      |    CTI output triggers:
    -------------------------|------------------------
    0: Debug entry (pulsed)  |    0: EDBGRQ
    1: !nPMUIRQ              |    1: EXTIN[0]
    2: EXTOUT[0]             |    2: EXTIN[1]
    3: EXTOUT[1]             |    3: EXTIN[2]
    4: COMMRX                |    4: EXTIN[3]
    5: COMMTX                |    5: PMUEXTIN[0]
    6: TRIGGER               |    6: PMUEXTIN[1]
    7: .                     |    7: DBGRESTART
    8: .                     |    8: !nCTIIRQ

    For Cortex-A9 (see Cortex-A9 TRM A.13.3)
    ----------------------------------------
    ARM A-series Procs & CSSoC 400 integration manual - 3.2 - CTI connections inside the PIL

    CTI input triggers:       |   CTI output triggers:
    --------------------------|-------------------------
    0: Debug entry            |   0: EDBGRQ
    1: !nPMUIRQ - overflow    |   1: EXTIN[0]
    2: EXTOUT[0]              |   2: EXTIN[1]
    3: EXTOUT[1]              |   3: EXTIN[2]
    4: COMMRX                 |   4: EXTIN[3]
    5: COMMTX                 |   5: PMUEXTIN[0]
    6: Trace TRIGGER          |   6: PMUEXTIN[1]
    7: .                      |   7: DBGRESTART
    8: .                      |   8: !nCTIIRQ

    For Cortex-A15 (see Cortex-A15 TRM 13.2):
    -----------------------------------------

    CTI input triggers:      |    CTI output triggers:
    -------------------------|------------------------
    0: DBGTRIGGER (pulsed)   |    0: EDBGRQ
    1: !nPMUIRQ              |    1: EXTIN[0]
    2: EXTOUT[0]             |    2: EXTIN[1]
    3: EXTOUT[1]             |    3: EXTIN[2]
    4: COMMTX                |    4: EXTIN[3]
    5: COMMRX                |    5: CTIEXTTRIG
    6: PTMTRIGGER            |    6: nCTIIRQ
    7: .                     |    7: DBGRESTART

    For Cortex-A7 (see Cortex-A7 Integration Manual A.1):
    -----------------------------------------------------
    same as A15, except names used are ETMTRIGGER and DBGRQ

    For Cortex-A57 (see Cortex-A57 TRM 12.2):
    -----------------------------------------

    CTI input triggers:      |    CTI output triggers:
    -------------------------|-------------------------
    0: DBGTRIGGER (pulsed)   |    0: EDBGRQ
    1: !nPMUIRQ              |    1: DBGRESTART
    2: .                     |    2: CTIIRQ
    3: .                     |    3: .
    4: EXTOUT[0]             |    4: EXTIN[0]
    5: EXTOUT[1]             |    5: EXTIN[1]
    6: EXTOUT[2]             |    6: EXTIN[2]
    7: EXTOUT[3]             |    7: EXTIN[3]

    For CSSYS CTI on TC2:
    ---------------------

    CTI input triggers:     |     CTI output triggers:
    ------------------------|-------------------------
    0:                      |     0: ETB.FLUSHIN
    1:                      |     1: ETB.TRIGIN
    2: ETB.FULL             |     2: TPIU.FLUSHIN
    3: ETB.ACQCOMP          |     3: TPIU.TRIGIN
    4: ITM                  |     4:
    5:                      |     5:
    6:                      |     6:
    7:                      |     7:

    @{*/
/** @}*/



#endif				/* _included_cs_cti_ect_h */

/* end of  cs_cti_ect.h */
