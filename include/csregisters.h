/*!
 * \file      csregisters.h
 * \brief     CS Access API: CoreSight architectural definitions.
 * 
 * This header defines macros defining register names, offsets and values for ARM CoreSight devices.
 *
 * \ copyright Copyright (C) ARM Limited, 2013-2016. All rights reserved.
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


#ifndef _included_csregisters_h
#define _included_csregisters_h

/** @defgroup reg_defs  Definitions for register offsets and values for CoreSight devices.

The information is taken from ARM publications.
e.g. CoreSight architecture specifications and CoreSight component TRMs.

Nothing in here is specific to any driver implementation - this header
could be used for kernel drivers, userspace drivers, remote tools etc.
@{
*/

/** @defgroup cs_reg_mgmnt CoreSight Architecture management registers. 
    @ingroup reg_defs

Common register definitions in the management group of all CoreSight devices

@{
*/

/** @name CoreSight ID 
 Common device identification registers on all CoreSight components
 */
/**@{*/
/* CSARCH2 3.3.1 table 3.2*/
#define CS_CIDR3 0xFFC	/**< CS Component ID register 3 */
#define CS_CIDR2 0xFF8	/**< CS Component ID register 2 */
#define CS_CIDR1 0xFF4	/**< CS Component ID register 1 */
#define CS_CIDR0 0xFF0	/**< CS Component ID register 0 */

#define CS_CLASS_OF(cidr1) (((cidr1) >> 4) & 15) /**< Extract class value from CIDR1 register */

/* Table 3.3: CLASS field encodings */
#define CS_CLASS_ROMTABLE  0x01	/**< CoreSight Class value for ROM table */
#define CS_CLASS_CORESIGHT 0x09	/**< CoreSight Class value for CoreSight component */
#define CS_CLASS_GENERIC   0x0E	/**< CoreSight Class value for Generic component */
#define CS_CLASS_PRIMECELL 0x0F	/**< CoreSight Class value for Primecell component table */

#define CS_PIDR4 0xFD0	    /**< CS Peripheral ID register 4 */
#define CS_PIDR3 0xFEC	    /**< CS Peripheral ID register 3 */
#define CS_PIDR2 0xFE8	    /**< CS Peripheral ID register 2 */
#define CS_PIDR1 0xFE4	    /**< CS Peripheral ID register 1 */
#define CS_PIDR0 0xFE0	    /**< CS Peripheral ID register 0 */

/**@}*/

/** @name CoreSight Management

 Common device identification and management registers on all CoreSight components.
*/

/**@{*/
#define CS_DEVTYPE 0xFCC    /**< CS Device Type register */
#define CS_DEVID   0xFC8    /**< CS Device ID register */
#define CS_DEVID1  0xFC4    /**< CS Device ID register 1 */
#define CS_DEVID0  0xFC0    /**< CS Device ID register 0 */

#define CS_DEVARCH  0xFBC   /**< CS device architecture register  */
#define CS_DEVAFF0  0xFA8   /**< CS device affinity register 0 */
#define CS_DEVAFF1  0xFAC   /**< CS device affinity register 1 */

#define CS_CLAIMSET  0xFA0  /**< CS component claim tag set register */
#define CS_CLAIMCLR  0xFA4  /**< CS component claim tag clear register */

#define CS_LAR  0xFB0	    /**< CS component Software Lock access register */
#define CS_LSR  0xFB4	    /**< CS component Software Lock status register */
#define CS_KEY  0xC5ACCE55  /**< CS component Software Lock - unlock key value */
/**@}*/

/** @} */

/** @defgroup cs_etmv3_ptm CoreSight ETMv3 and PTM registers. 
    @ingroup reg_defs

Register definitions and bitfield values for the ETM architecture v3 and 
Program Flow Trace (PTM) macrocells .

@{
*/

/** @name Trace Control
Registers used to control tracing
@{*/
#define CS_ETMCR          0x000	   /**< Control Register */
#define CS_ETMCR_PowerDown  0x001    /**< Control Register: Bitfield - Controls ETM power and disables trace */
#define CS_ETMCR_MonitorCPRT 0x002   /**< Control Register: Bitfield - Trace CPRTs */
#define CS_ETMCR_Data       0x004    /**< Control Register: Bitfield - Trace data portion of access */
#define CS_ETMCR_Address    0x008    /**< Control Register: Bitfield - Trace address portion of access */
#define CS_ETMCR_AddressData 0x00C   /**< Control Register: Bitfield - Trace address and data of access */
#define CS_ETMCR_BranchBroadcast 0x100	 /**< Control Register: Bitfield - Enable branch broadcast */
#define CS_ETMCR_ProgBit    0x400    /**< Control Register: Bitfield - Selects between programming and trace mode */
#define CS_ETMCR_ETMEN      0x800    /**< Control Register: Bitfield - Controls an external output, ETMEN (up to v3.5) */
#define CS_ETMCR_CycleAccurate 0x00001000  /**< Control Register: Bitfield - Cycle-accurate */
#define CS_ETMCR_TSEn          0x10000000  /**< Control Register: Bitfield - Timestamp enable (v3.5) */
#define CS_ETMCR_ReturnStack   0x20000000  /**< Control Register: Bitfield - Return stack enable */
#define CS_ETMCCR         0x004	   /**< Configuration Code Register (RO) */
#define CS_ETMTRIGGER     0x008	   /**< Trigger Event Register */
#define CS_ETMASICCR      0x00C	   /**< ASIC Control Register */
#define CS_ETMSTATUS      0x010	   /**< ETM Status Register */
#define CS_ETMSR_ProgBit    0x002    /**< ETM Status Register : Bitfield - Indicates the current effective value of ProgBit */
#define CS_ETMSCR         0x014	   /**< System Configuration Register (RO) */
#define CS_ETMTSSCR       0x018	   /**< TraceEnable Start/Stop Control Register */
#define CS_ETMTECR2       0x01C	   /**< TraceEnable Control 2 Register */
#define CS_ETMTEEVR       0x020	   /**< TraceEnable Event Register */
#define CS_ETMTECR1       0x024	   /**< TraceEnable Control 1 Register */
#define CS_ETMTECR1_SSEN    0x02000000	/**< TECR1 : Bitfield - Tracing is controlled by trace start/stop logic */
#define CS_ETMTECR1_EXCLUDE 0x01000000	/**< TECR1 : Bitfield - Resources in [23:0] and TECR2 specify exclusion */
#define CS_ETMFFRR        0x028	   /**< FIFOFULL Region Register */
#define CS_ETMVDEVR       0x030	   /**< ViewData Event Register */
/** ViewData Control Register (n).
Generate offset for register (n), 0 indexed */
#define CS_ETMVDCR(n)     (0x34 + 4*(n))
/** @}*/

/** @name ETM event descriptors
 * CS_ETMEVENT() constructs event descriptor values.
 * These descriptor values combine up to two event resources with a function.
 * They can be programmed into event registers such as Trace Enable Event register.
 *
 @{*/
#define CS_ETMEVENT(fn,a,b) (((fn)<<14) | ((b)<<7) | (a))   /**< Build event descriptor. Uses resources \b 'a' and \b 'b' combined with function \b 'fn' */
#define CS_ETME_WHEN(a) CS_ETMEVENT(0,(a),0)		    /**< Event Descriptor : <tt> \b 'a' is true </tt>*/
#define CS_ETME_NOT(a) CS_ETMEVENT(1,(a),0)		    /**< Event Descriptor : <tt>NOT(\b 'a') true </tt>*/
#define CS_ETME_AND(a,b) CS_ETMEVENT(2,(a),(b))		    /**< Event Descriptor : <tt>\b 'a' AND \b 'b' true </tt>*/
#define CS_ETME_NOT_A_AND_B(a,b) CS_ETMEVENT(3,(a),(b))	    /**< Event Descriptor : <tt>NOT(\b 'a') AND \b 'b' true </tt>*/
#define CS_ETME_NEITHER(a,b) CS_ETMEVENT(4,(a),(b))	    /**< Event Descriptor : <tt>NOT(\b 'a') AND NOT(\b 'b') true </tt>*/
#define CS_ETME_NOT_A_AND_NOT_B(a,b) CS_ETME_NEITHER(a,b)   /**< Event Descriptor : <tt>NOT(\b 'a') AND NOT(\b 'b') true </tt>*/
#define CS_ETME_OR(a,b) CS_ETMEVENT(5,(a),(b))		    /**< Event Descriptor : <tt>\b 'a'  OR \b 'b' true </tt>*/
#define CS_ETME_NOT_A_OR_B(a,b) CS_ETMEVENT(6,(a),(b))	    /**< Event Descriptor : <tt>NOT(\b 'a')  OR \b 'b' true </tt>*/
#define CS_ETME_NOTBOTH(a,b) CS_ETMEVENT(7,(a),(b))	    /**< Event Descriptor : <tt>NOT(\b 'a')  OR NOT(\b 'b') true </tt>*/
#define CS_ETME_NOT_A_OR_NOT_B(a,b) CS_ETME_NOTBOTH(a,b)    /**< Event Descriptor : <tt>NOT(\b 'a')  OR NOT(\b 'b') true </tt>*/
/** @}*/

/** @name ETM Event resources.
 * Event resource selectors consist of a seven bit field: 'type'[6:4] and 'index'[3:0]. These 
 * resource selectors are then used in the #CS_ETMEVENT macros as 'a' or 'b' resources to create the 
 * event descriptor.
 *
 * Due to the way events are encoded, an event resource
 * value can also be interpreted as the corresponding event, i.e.
 *   CS_ETMER_XXX == #CS_ETME_WHEN(CS_ETMER_XXX)
 *
 * Sequencer states are numbered 1..3 as in the ETM architecture.
 *
 * Comparators, external inputs etc. are numbered from 0, contrary to
 * the ETM architecture.
 @{*/
#define CS_ETMER_SAC(n) ((n) + 0x00)	/**< Single address comparator 1-16 [n=0-15] */
#define CS_ETMER_RANGE(n) ((n) + 0x10)	/**< Address comparator range 1-8 [n=0-7] */
#define CS_ETMER_INST(n) ((n) + 0x18)	/**< Instrumentation resource 1-4 [n=0-3] (implementation defined) */
#define CS_ETMER_EICE(n) ((n) + 0x20)	/**< EICE watchpoint comparators 1-8 [n=0-7] (implementation defined) */
#define CS_ETMER_MMAPDEC(n) ((n) + 0x30)    /**< Memory map decodes 1-16 [n=0-15] */
#define CS_ETMER_CZERO(n) ((n) + 0x40)	    /**< Counter 1-4 at zero [n=0-3] */
#define CS_ETMER_SEQSTATE(n) (((n) - 1) + 0x50)	/**< Sequencer states 1-3 [n=1-3] */
#define CS_ETMER_CXID(n) ((n) + 0x58)	    /**< Context ID comparator 1-3 [n=0-2] */
#define CS_ETMER_VMID(n) ((n) + 0x5B)	    /**< VMID comparator [n=0] */
#define CS_ETMER_TRENABLE 0x5F		    /**< Trace start/stop resource */
#define CS_ETMER_EXTIN(n) ((n) + 0x60)	    /**< EXTIN 1-4 [n=0-3]  */
#define CS_ETMER_EXTEXTIN(n) ((n) + 0x68)   /**< Extended EXTIN 1-4 [n=0-3] */
#define CS_ETMER_NS 0x6D		    /**< Processor in Non-secure state */
#define CS_ETMER_TPROH 0x6E		    /**< Trace prohibited by procesor */
#define CS_ETMER_ALWAYS 0x6F		    /**< Hardwired always TRUE resource input */
/** Never event. Note that "NEVER" is an event, but not an event resource. */
#define CS_ETME_NEVER CS_ETME_NOT(CS_ETMER_ALWAYS)

/** @}*/


/** @name Address Comparators 
@{*/
#define CS_ETMACVR(n)    (0x040 + 4*(n))  /**< Address Comparator Value register (n) */
#define CS_ETMACTR(n)    (0x080 + 4*(n))  /**< Address Comparator Type register (n) */
/** @}*/

/** @name Address comparator bitfields
 * Values for the #CS_ETMACTR registers.
 * See [ETM] table 3-29.
 * n.b. some fields are different between 3.4 and 3.5 - program as for 3.5 and have
   the library convert for older ones @{*/
#define CS_ETMACT_FETCH     0x00000000	 /**< Access Type: Instruction fetch  */
#define CS_ETMACT_EX        0x00000001	 /**< Access Type: Instruction Execute (ignored on PTM) */
#define CS_ETMACT_EXPASS    0x00000002	 /**< Access Type: Instruction Executed and passed condition code test*/
#define CS_ETMACT_EXFAIL    0x00000003	 /**< Access Type: Instruction executed and failed condition code test */
#define CS_ETMACT_DATA_LDST 0x00000004	 /**< Access Type: Data load or store */
#define CS_ETMACT_DATA_LD   0x00000005	 /**< Access Type: Data load */
#define CS_ETMACT_DATA_ST   0x00000006	 /**< Access Type: Data store */
#define CS_ETMACT_BYTE      0x00000000	 /**< Access Size: Java instruction or Byte data */
#define CS_ETMACT_HALFWORD  0x00000008	 /**< Access Size: Thumb instruation or halfword data */
#define CS_ETMACT_THUMB1    CS_ETMACT_HALFWORD	 /**< Access Size: Thumb or halfword data only */
#define CS_ETMACT_WORD      0x00000018	 /**< Access Size: ARM instruction or word data */
#define CS_ETMACT_ARMTHUMB  CS_ETMACT_WORD	 /**< Access Size: ARM or Thumb fetch */
#define CS_ETMACT_EXACT     0x00000080	 /**< Exact match bit */
#define CS_ETMACT_CXID(n)   ((n+1) << 8)   /**< Match if Context ID comparator (n) also matches. Assuming numbering from #0 */
#define CS_ETMACT_S_NS_ALL  0x00000000	/**< Match all modes in NS or S state */
#define CS_ETMACT_S_3v2     0x00000800	/**< Match if secure state (v3.2+) */
#define CS_ETMACT_NS_3v2    0x00000400	/**< Match if none-secure state (v3.2+) */
#define CS_ETMACT_S_KERNEL  0x00001000	/**< Match !user in secure state (v3.5) */
#define CS_ETMACT_NS_KERNEL 0x00002000	/**< Match !user in none-secure state (v3.5)*/
#define CS_ETMACT_S_NEVER   0x00000400	/**< Match never in secure state (v3.5) */
#define CS_ETMACT_NS_NEVER  0x00000800	/**< Match never in none-secure state  (v3.5)*/
#define CS_ETMACT_KERNEL    (CS_ETMACT_S_KERNEL|CS_ETMACT_NS_KERNEL) /**< Match !user in all security states (v3.5) */
#define CS_ETMACT_S_USER    0x00001400	/**< match only user in secure state  (v3.5)*/
#define CS_ETMACT_NS_USER   0x00002800	/**< match only user in non-secure state  (v3.5)*/
#define CS_ETMACT_USER      (CS_ETMACT_S_USER|CS_ETMACT_NS_USER) /**< match only user all security states  (v3.5) */
#define CS_ETMACT_HYP       0x00004000	 /**< match if processor in Hyp mode (v3.5) */
#define CS_ETMACT_VMID      0x00008000	 /**< match if VIMD comparator also matches (v3.5) */
/** @}*/

/** @name Data comparators
@{*/
#define CS_ETMDCVR(n)       (0x0c0 + 8*(n))  /**< Data Comparator Value Register (n) */
#define CS_ETMDCMR(n)       (0x100 + 8*(n))  /**< Data Comparator Mask Register (n) */
/** @}*/
/** @name Counters 
@{*/
#define CS_ETMCNTRLDVR(n)  (0x140 + 4*(n))   /**< Counter Reload Value Register (n) */
#define CS_ETMCNTENR(n)    (0x150 + 4*(n))   /**< Counter Enable Register (n) */
#define CS_ETMCNTRLDEVR(n) (0x160 + 4*(n))   /**< Counter Reload Event Register (n)*/
#define CS_ETMCNTVR(n)     (0x170 + 4*(n))   /**< Counter Value Register (n)*/
/** @}*/

/** @name Sequencer control
Registers and definitions used to program the ETM sequencer.
@{*/

/** Test sequence transition 'a'->'b' as value against 'n' */
#define CS_SF(a,b,n) ((((a) << 4) | (b)) == n)

/** Calculate the event register offset for transition 'a'->'b' (uses #CS_SF macro) */
#define CS_ETMSQOFF(a,b) (CS_SF(a,b,0x12) ? 0 : CS_SF(a,b,0x21) ? 1 : CS_SF(a,b,0x23) ? 2 : CS_SF(a,b,0x31) ? 3 : CS_SF(a,b,0x32) ? 4 : CS_SF(a,b,0x13) ? 5 : -1)

#define CS_ETMSQEVRRAW(n) (0x180 + 4*(n))   /**< Sequencer Transition event register (n) [n=0-5] - get address offset by index */
#define CS_ETMSQEVR(a,b)  (0x180 + 4*CS_ETMSQOFF(a,b))	/**< Sequencer Transition event register for transition 'a'->'b' - get address offset by transition */
#define CS_ETMSEQ_STATES 3	/**< Number of sequencer states */
#define CS_ETMSEQ_TRANSITIONS (CS_ETMSEQ_STATES * (CS_ETMSEQ_STATES-1))	/**< Number of sequencer transitions */

#define CS_ETMSQ12EVR     0x180	    /**< Sequencer Transition Event Register: transition state 1->2 */
#define CS_ETMSQ21EVR     0x184	    /**< Sequencer Transition Event Register: transition state 2->1 */
#define CS_ETMSQ23EVR     0x188	    /**< Sequencer Transition Event Register: transition state 2->3 */
#define CS_ETMSQ31EVR     0x18C	    /**< Sequencer Transition Event Register: transition state 3->1 */
#define CS_ETMSQ32EVR     0x190	    /**< Sequencer Transition Event Register: transition state 3->2 */
#define CS_ETMSQ13EVR     0x194	    /**< Sequencer Transition Event Register: transition state 1->3 */
#define CS_ETMSQR         0x19C	    /**< Sequencer State Register */
/** @}*/

/** @name Additional Event and control registers
@{*/
/** External Output Event Register (n) */
#define CS_ETMEXTOUTEVR(n) (0x1A0 + 4*(n))

#define CS_ETMCIDCVR(n)  (0x1B0 + 4*(n))  /**< Context ID Comparator Value register (n) [n=0-2] */
#define CS_ETMCIDCMR      0x1BC	   /**< Context ID Comparator Mask register */

#define CS_ETMSYNCFR      0x1E0	   /**< Synchronization Frequency Register */
#define CS_ETMIDR         0x1E4	   /**< ID Register (RO) */
#define CS_ETMCCER        0x1E8	   /**< Configuration Code Extension Register (RO) */

#define CS_ETMTSEVR       0x1F8	   /**< Timestamp Event Register */
#define CS_ETMAUXCR       0x1FC	   /**< Auxiliary Control Register */

#define CS_ETMTRACEIDR    0x200	   /**< CoreSight Trace ID Register */
#define CS_ETMIDR2        0x208	   /**< ETM ID Register 2 (RO) */

#define CS_ETMVMIDCVR     0x240	   /**< VMID Comparator Value Register */

#define CS_ETMOSLAR       0x300	   /**< OS Lock Access Register (WO) */
#define CS_ETMOSLSR       0x304	   /**< OS Lock Status Register (RO) */
#define CS_ETMPDSR        0x314	   /**< ETM Power-Down Status Register. \b Note: Read has side effects due to sticky status bit */
#define CS_ETMLSR         CS_LSR    /**< ETM LSR - same as standard #CS_LSR */
/** @}*/

/** @} */


/** @defgroup cs_etmv4 CoreSight ETMv4 registers. 
    @ingroup reg_defs

Register definitions and bitfield values for the ETM architecture v4

@{
*/

/** @name Trace control 
@{*/
#define CS_ETMV4_PRGCTLR        0x004	/**< ETM Programming control register */
#define CS_ETMV4_PRGCTLR_en     0x01	/**< #CS_ETMV4_PRGCTLR bitfield : ETM trace enabled (disable for programming) */
#define CS_ETMV4_PROCSELR       0x008	/**< PE Select control register */
#define CS_ETMV4_STATR          0x00C	/**< Trace Status register  */
#define CS_ETMV4_STATR_idle      0x01	/**< #CS_ETMV4_STATR bitfield : ETM trace idle */
#define CS_ETMV4_STATR_pmstable  0x02	/**< #CS_ETMV4_STATR bitfield : ETM programmers model stable */
#define CS_ETMV4_CONFIGR        0x010	/**< Trace configuration register */
#define CS_ETMV4_AUXCTLR        0x018	/**< Auxiliary control register  */
#define CS_ETMV4_EVENTCTL0R     0x020	/**<  Event control 0 register */
#define CS_ETMV4_EVENTCTL1R     0x024	/**<  Event control 1 register */
#define CS_ETMV4_STALLCTLR      0x02C	/**<  Stall control register */
#define CS_ETMV4_TSCTLR         0x030	/**<  Global timestamp control register */
#define CS_ETMV4_SYNCPR         0x034	/**<  Synchronisation period register */
#define CS_ETMV4_CCCTLR         0x038	/**<  Cycle count control register */
#define CS_ETMV4_BBCTLR         0x03C	/**<  Branch broadcast control register */
#define CS_ETMV4_TRACEIDR       0x040	/**<  Trace ID register */
#define CS_ETMV4_QCTLR          0x044	/**<  Q element control register */
/** @}*/
/** @name TraceConfigR Bitfields
Bitfield values for trace configuration register (#CS_ETMV4_CONFIGR)
@{*/
#define CS_ETMV4_CONFIGR_InstP0_off     0x00000	    /**< Don't trace LD and ST as P0 */
#define CS_ETMV4_CONFIGR_InstP0_LD      0x00002	    /**< Trace LD as P0 */
#define CS_ETMV4_CONFIGR_InstP0_ST      0x00004	    /**< Trace ST as P0 */
#define CS_ETMV4_CONFIGR_InstP0_LDST    0x00006	    /**< Trace LD and ST as P0 */
#define CS_ETMV4_CONFIGR_BBMode         0x00008	    /**< Branch Broadcast Mode Enable */
#define CS_ETMV4_CONFIGR_CCI            0x00010	    /**< Enable Cycle count in Instruction trace */
#define CS_ETMV4_CONFIGR_CID            0x00040	    /**< Enable Context ID trace */
#define CS_ETMV4_CONFIGR_VMID           0x00080	    /**< Enable VMID trace */
#define CS_ETMV4_CONFIGR_COND_LD        0x00100	    /**< Conditional LD traced */
#define CS_ETMV4_CONFIGR_COND_ST        0x00200	    /**< Conditional ST traced */
#define CS_ETMV4_CONFIGR_COND_LDST      0x00300	    /**< Conditional LD and ST traced */
#define CS_ETMV4_CONFIGR_COND_ALL       0x00700	    /**< All Conditional instructions traced */
#define CS_ETMV4_CONFIGR_TS             0x00800	    /**< Global timestamp trace enabled */
#define CS_ETMV4_CONFIGR_RS             0x01000	    /**< Return stack enabled */
#define CS_ETMV4_CONFIGR_QE_with_cnt    0x02000	    /**< Q elements with instr counts enabled */
#define CS_ETMV4_CONFIGR_QE_all         0x06000	    /**< Q elements with and without instr counts enabled */
#define CS_ETMV4_CONFIGR_DA             0x10000	    /**< Data address tracing enabled */
#define CS_ETMV4_CONFIGR_DV             0x20000	    /**< Data Value tracing enabled */
/** @}*/

/** @name ViewInst Control 
@{*/
#define CS_ETMV4_VICTLR         0x080	/**< ViewInst control register */
#define CS_ETMV4_VIIECTLR       0x084	/**< ViewInst Include/Exclude control register */
#define CS_ETMV4_VISSCTLR       0x088	/**< ViewInst Start/Stop control register */
#define CS_ETMV4_VIPSSCTLR      0x08C	/**< ViewInst Start/Stop PE Comparator Control register */
/** @}*/
/** @name ViewData Control 
@{*/
#define CS_ETMV4_VDCTLR         0x0A0	/**< ViewData Main control register */
#define CS_ETMV4_VDSACCTLR      0x0A4	/**< ViewData Include/Exclude Single Address comparator control register */
#define CS_ETMV4_VDARCCTLR      0x0A8	/**< ViewData Include/Exclude Address Range comparator control register */
/** @}*/
/** @name Sequencer 
@{*/
#define CS_ETMV4_SEQEVR(n)     (0x100+(0x4*n)) /**< Sequencer State Transistion Control Register (n) [0-2] */
#define CS_ETMV4_SEQRSTEVR      0x118	       /**< Sequencer Reset Control Register */
#define CS_ETMV4_SEQSTR         0x11C	       /**< Sequencer State Register */
/** @}*/
/** @name Counters 
@{*/
#define CS_ETMV4_CNTRLDVR(n)   (0x140+(0x4*n))	     /**< Counter Reload Register (n) [0-3] */
#define CS_ETMV4_CNTCTLR(n)    (0x150+(0x4*n))	     /**< Counter Control Register (n) [0-3] */
#define CS_ETMV4_CNTCTLR_rldself 0x10000	     /**< CNTCTLR bitfield - reload self on zero @ decrement event */
#define CS_ETMV4_CNTCTLR_chain   0x20000	     /**< CNTCTLR bitfield - chain - reload of previous indexed counter decrements this */
#define CS_ETMV4_CNTVR(n)      (0x160+(0x4*n))	     /**< Counter Value Register (n) [0-3] */
/** @}*/

/** @name Resource Selection Control 
Set of macros defining registers and selection values.
Also macros to set event values that use selector registers.
@{*/
#define CS_ETMV4_EXTINSELR      0x120		     /**< External Input Select Register */
#define CS_ETMV4_RSCTLR(n)     (0x200+(0x4*n))	     /**< Resource Selection Control Register (n) [2-31] */
#define CS_ETMV4_RSCTLR_pairinv   0x200000	     /**< RSCTLR bitfield : pair invert. */
#define CS_ETMV4_RSCTLR_inv       0x100000	     /**< RSCTLR bitfield : invert. */
#define CS_ETMV4_RSCTLR_SEL_EXTIN(N) (0x00000U | (0x1U << (N & 0x3)))	/**< RSCTLR resource sel: EXTIN(N) */
#define CS_ETMV4_RSCTLR_SEL_PECOMP(N)(0x10000U | (0x1U << (N & 0x7)))	/**< RSCTLR resource sel: PECOMP(N) */
#define CS_ETMV4_RSCTLR_SEL_CNTZ(N)  (0x20000U | (0x1U << (N & 0x3)))	/**< RSCTLR resource sel: COUNT at 0 (N) */
#define CS_ETMV4_RSCTLR_SEL_SEQST(N) (0x20000U | (0x4U << (N & 0x3)))	/**< RSCTLR resource sel: Sequencer state (N) */
#define CS_ETMV4_RSCTLR_SEL_SSCMP(N) (0x30000U | (0x1U << (N & 0x7)))	/**< RSCTLR resource sel: Single Shot comp (N) */
#define CS_ETMV4_RSCTLR_SEL_SAC(N)   (0x40000U | (0x1U << (N & 0xF)))	/**< RSCTLR resource sel: Single Address comp (N) */
#define CS_ETMV4_RSCTLR_SEL_ARC(N)   (0x50000U | (0x1U << (N & 0x7)))	/**< RSCTLR resource sel: Address Range comp (N) */
#define CS_ETMV4_RSCTLR_SEL_CID(N)   (0x60000U | (0x1U << (N & 0x7)))	/**< RSCTLR resource sel: Context ID comp (N) */
#define CS_ETMV4_RSCTLR_SEL_VMID(N)  (0x70000U | (0x1U << (N & 0x7)))	/**< RSCTLR resource sel: VMID comp (N) */
#define CS_ETMV4_RSCTLR_SEL(G,S)  (0U | ((G & 0xF) << 16) | (S & 0xFFFF))  /**< RSCTLR resource sel: Group (G) with Select Bitfield (S) */

#define CS_ETMV4_EVENT_ALWAYS       0x01    /**< Single event using the ALWAYS resource selector */
#define CS_ETMV4_EVENT_NEVER        0x00    /**< Single event using the NEVER resource selector - program any event register with this to disable feature */
#define CS_ETMV4_EVENT_SINGLE(N)    (0x00U | ( N & 0x1FU ))	/**< Single event using resource selector N (N=2-31) */
#define CS_ETMV4_EVENT_PAIR(N)      (0x80U | ( N & 0x0FU ))	/**< Event Pair using resource selectors N and N+1 (N=1-15) [N=0 would select to ALWAYS and NEVER resource selectors] */

/** @}*/

/** @name Single Shot Comparator Control
@{*/
#define CS_ETMV4_SSCCR(n)      (0x280+(0x4*n))	     /**< Single Shot Comparator Control Register (n) [0-7] */
#define CS_ETMV4_SSCSR(n)      (0x2A0+(0x4*n))	     /**< Single Shot Comparator Status Register (n) [0-7] */
#define CS_ETMV4_SSPCICR(n)    (0x2C0+(0x4*n))	     /**< Single Shot PE Comparator Input Control Register (n) [0-7] */
/** @}*/

/** @name Comparator Resources 
@{*/
#define CS_ETMV4_ACVR(n)      (0x400+(0x8*n))	     /**< Address Comparator Value Register (n) [0-15] (64 bit) */
#define CS_ETMV4_ACATR(n)     (0x480+(0x8*n))	     /**< Address Comparator Access Type Register (n) [0-15] (64 bit) */
#define CS_ETMV4_DVCVR(n)      (0x500+(0x10*n))	     /**< Data Value Comparator Value Register (n) [0-7] (64 bit) */
#define CS_ETMV4_DVCMR(n)      (0x580+(0x10*n))	     /**< Data Value Comparator Mask Register (n) [0-7] (64 bit) */
#define CS_ETMV4_CIDCVR(n)     (0x600+(0x8*n))	     /**< Context ID Comparator Value Register (n) [0-7] (64 bit) */
#define CS_ETMV4_VMIDCVR(n)    (0x640+(0x8*n))	     /**< VMID Comparator Value Register (n) [0-7] (64 bit) */
#define CS_ETMV4_CIDCCTLR0      0x680	/**< Context ID comparator control register 0  */
#define CS_ETMV4_CIDCCTLR1      0x684	/**< Context ID comparator control register 1  */
#define CS_ETMV4_VMIDCCTLR0     0x688	/**< VMID comparator control register 0  */
#define CS_ETMV4_VMIDCCTLR1     0x68C	/**< VMID comparator control register 1  */
/** @}*/
/** @name ACATR Bitfields 
Address Comparator Type register bits. 
@{*/
#define CS_ETMV4_ACATR_IA           0x0	    /**< Instruction Address Type */
#define CS_ETMV4_ACATR_DL           0x1	    /**< Data Load Address Type */
#define CS_ETMV4_ACATR_DS           0x2	    /**< Data Store Address Type */
#define CS_ETMV4_ACATR_DL_DS        0x3	    /**< Data Load or Data Store Address Type */

#define CS_ETMV4_ACATR_CTXT         0x4	    /**< Context ID comparison */
#define CS_ETMV4_ACATR_VMID         0x8	    /**< VMID comparison */
#define CS_ETMV4_ACATR_CTXT_VMID    0xC	    /**< Context ID and VMID comparison */

#define CS_ETMV4_ACATR_CTXTID(N)    ((N & 0x7) << 4)	/**< Context ID comparator number when VMID or Context ID matching */

#define CS_ETMV4_ACATR_ExEL0_S     0x100    /**< Exclude Secure EL0 from comparison */
#define CS_ETMV4_ACATR_ExEL1_S     0x200    /**< Exclude Secure EL1 from comparison */
#define CS_ETMV4_ACATR_ExEL3_S     0x800    /**< Exclude Secure EL3 from comparison */

#define CS_ETMV4_ACATR_ExEL0_NS   0x1000    /**< Exclude Non-Secure EL0 from comparison */
#define CS_ETMV4_ACATR_ExEL1_NS   0x2000    /**< Exclude Non-Secure EL1 from comparison */
#define CS_ETMV4_ACATR_ExEL2_NS   0x4000    /**< Exclude Non-Secure EL2 from comparison */

#define CS_ETMV4_ACATR_DMATCH    0x10000    /**< Data value match if values are identical */
#define CS_ETMV4_ACATR_DMATCH_n  0x30000    /**< Data value match if values are different */

#define CS_ETMV4_ACATR_DSIZE_B   0x00000    /**< Data value match size byte */
#define CS_ETMV4_ACATR_DSIZE_HW  0x40000    /**< Data value match size half word */
#define CS_ETMV4_ACATR_DSIZE_W   0x80000    /**< Data value match size word*/
#define CS_ETMV4_ACATR_DSIZE_DW  0xC0000    /**< Data value match size double word */

#define CS_ETMV4_ACATR_DRANGE   0x100000    /**< Use address range for data value comparison */
/** @}*/

/** @name CS Management

  ETMv4 specific management registers. See \ref cs_reg_mgmnt "CoreSight Management registers" for common component management registers.
@{*/
#define CS_ETMv4_IDR0           0x1E0 /**< ID register 0: Defines trace capabilites of this ETM implementation */
#define CS_ETMv4_IDR1           0x1E4 /**< ID register 1: Defines architecture version and revision */
#define CS_ETMv4_IDR2           0x1E8 /**< ID register 2: Defines further trace capabilites of this implementation */
#define CS_ETMv4_IDR3           0x1EC /**< ID register 3: Defines number of PEs and EL information */
#define CS_ETMv4_IDR4           0x1F0 /**< ID register 4: Defines number of resources available to  implementation */
#define CS_ETMv4_IDR5           0x1F4 /**< ID register 5: Defines number of resources available to  implementation */
#define CS_ETMv4_IDR6           0x1F8 /**< ID register 6: Res0 */
#define CS_ETMv4_IDR7           0x1FC /**< ID register 7: Res0 */
#define CS_ETMv4_IDR8           0x180 /**< ID register 8: MaxSpec - max speculation depth */
#define CS_ETMv4_IDR9           0x184 /**< ID register 9: NumP0key : Number of P0 RH Keys  */
#define CS_ETMv4_IDR10          0x188 /**< ID register 10: NumP1Key : Number of P1 RH Keys */
#define CS_ETMv4_IDR11          0x18C /**< ID register 11: NumP1spc : Number of special P1 RH Keys */
#define CS_ETMv4_IDR12          0x190 /**< ID register 12: NumCondKey : Number of conditional instruction RH Keys */
#define CS_ETMv4_IDR13          0x194 /**< ID register 13: NumCondSpc : Number of special conditional instruction RH Keys */

#define CS_ETMv4_OSLAR          0x300 /**< OS Lock access register */
#define CS_ETMv4_OSLSR          0x304 /**< OS lock status register */
#define CS_ETMv4_PDCR           0x310 /**< ETM power down control register */
#define CS_ETMv4_PDSR           0x314 /**< ETM power down status register */

#define CS_ETMv4_AUTHSTATUS     0xFB8 /**< Trace authentication status register */

/** @}*/

/** @name PDSR bitfields
Values for TRCPDSR. See #CS_ETMv4_PDSR for register info.
@{*/
#define CS_ETMv4_PDSR_PowerUp           0x01	/**< ETM powered up.*/
#define CS_ETMv4_PDSR_StickyPowerUp     0x02	/**< ETM sticky power up.*/
#define CS_ETMv4_PDSR_OSLock            0x20	/**< ETM OS Locked.*/
/** @}*/

/** @} */

/** @defgroup cs_stm_itm CoreSight SW Stimulus device registers 
    @ingroup reg_defs

Register definitions and bitfield values for the ITM and STM software stimulus 
trace devices.

@{
*/

/** @name CoreSight ITM registers */
/**@{*/
#define CS_ITM_STIMPORT(d)   (0x000 + 4*(d)) /**< ITM stimulus port (d) [d=0-31] */
#define CS_ITM_TRCEN      0xE00	      /**< ITM Trace Enable Register (TER) */
#define CS_ITM_TRTRIG     0xE20	      /**< ITM Trace Trigger Register (TTR) */
#define CS_ITM_CTRL       0xE80	      /**< ITM control register  */
#define CS_ITM_CTRL_ITMEn       0x01  /**< #CS_ITM_CTRL register bitfield: ITM enable */
#define CS_ITM_CTRL_TSSEn       0x02  /**< #CS_ITM_CTRL register bitfield: TSS enable */
#define CS_ITM_CTRL_ITMBusy 0x800000  /**< #CS_ITM_CTRL register bitfield: ITM busy */
#define CS_ITM_SYNCCTRL   0xE90	      /**< Sychronisation control register */
#define CS_ITM_DCR        0xFC8	      /**< Device Configuration Register */
/**@}*/

/** @name CoreSight STM registers */
/**@{*/
#define CS_STM_STIMR(p)     (0x000 + 4*(p))   /**< STM basic stimulus port(p) [p=0-31]. */
#define CS_STM_SPER         0xE00
#define CS_STM_SPTER        0xE20
#define CS_STM_PRIVMASKR    0xE40
#define CS_STM_SPSCR        0xE60
#define CS_STM_SPSCR_PORTCTL    0x03
#define CS_STM_SPMSCR       0xE64
#define CS_STM_SPMSCR_MASTCTL   0x01
#define CS_STM_SPOVERRIDER  0xE68
#define CS_STM_SPMOVERRIDER 0xE6C
#define CS_STM_SPTRIGCSR    0xE70
#define CS_STM_TCSR         0xE80
#define CS_STM_TCSR_EN          0x01   /**< Enable STM */
#define CS_STM_TCSR_TSEN        0x02   /**< Enable timestamps */
#define CS_STM_TCSR_SYNCEN      0x04   /**< Enable synchronization packets */
#define CS_STM_TCSR_HWTEN       0x08   /**< Enable hardware event trace */
#define CS_STM_TCSR_SWOEN       0x10
#define CS_STM_TCSR_COMPEN      0x20   /**< Enable compression */
#define CS_STM_TCSR_BUSY        0x800000  /**< STM is busy, e.g. FIFO not empty */
#define CS_STM_TSSTIMR      0xE84      /**< Timestamp Stimulus Register */
#define CS_STM_TSFREQR      0xE8C      /**< Timestamp Frequency Register */
#define CS_STM_SYNCR        0xE90
#define CS_STM_FEAT1R       0xEA0
#define CS_STM_FEAT2R       0xEA4
#define CS_STM_FEAT3R       0xEA8
#define CS_STM_DEVID        0xFC8

/* STM extended ports */
#define CS_STM_EXT_PORT(p)        (0x00 + 256*(p))   /**< STM extended port: Byte offset to 256-byte area for port */
#define CS_STM_EXT_PORT_I_DMTS(p) (CS_STM_EXT_PORT((p)) + 0x80)
/**@}*/

/** @} */


/** @defgroup cs_link_sink CoreSight Trace Sinks and Links device registers 
    @ingroup reg_defs

Register definitions and bitfield values for the TPIU, ETB, Trace Funnel,
programmable replicator and TMC trace devices.

@{
*/

/** @name CoreSight TPIU registers */
/**@{*/

#define CS_TPIU_FLFMT_STATUS    0x300	/**< TPIU status register  */
#define CS_TPIU_FLFMT_STATUS_FtStopped 0x02    /**< TPIU status bitfield: Formatter stopped */
#define CS_TPIU_FLFMT_STATUS_FlInProg  0x01    /**< TPIU status bitfield: Flush in progress */
#define CS_TPIU_FLFMT_CTRL      0x304	/**< TPIU control register  */
#define CS_TPIU_FLFMT_CTRL_StopFl   0x1000     /**< TPIU control bitfield:  Stop when flush completes */
#define CS_TPIU_FLFMT_CTRL_FOnMan   0x0040     /**< TPIU control bitfield:  Initiate a flush */

/**@}*/

/** @name CoreSight Single Wire Output registers */
/**@{*/
/* SWO */
#define CS_SWO_FLFMT_STATUS     0x300	/**< SWO Status register */
#define CS_SWO_FLFMT_CTRL       0x304	/**< SWO control register */
/**@}*/

/** @name CoreSight ETB registers 

ETB: [CoreSight SoC TRM 3.10] - n.b. the register names there are more cryptic 
*/
/**@{*/
#define CS_ETB_RAM_DEPTH     0x004     /**< ETB RAM Depth Register (in width-units) */
#define CS_ETB_RAW_WIDTH     0x008     /**< ETB RAM Width Register (in bits) [Legacy ETBs only] */
#define CS_ETB_STATUS        0x00C     /**< ETB Status Register */
#define CS_ETB_STATUS_FtEmpty    0x08  /**< ETB Status bitfield (#CS_ETB_STATUS):Formatter pipeline empty. All data stored to RAM */
#define CS_ETB_STATUS_AcqComp    0x04  /**< ETB Status bitfield (#CS_ETB_STATUS):Acquisition complete */
#define CS_ETB_STATUS_Triggered  0x02  /**< ETB Status bitfield (#CS_ETB_STATUS):Trigger observed */
#define CS_ETB_STATUS_Full       0x01  /**< ETB Status bitfield (#CS_ETB_STATUS):RAM Full: RAM write pointer has wrapped around */
#define CS_ETB_RAM_DATA      0x010     /**< ETB RAM Read Data Register */
#define CS_ETB_RAM_RD_PTR    0x014     /**< ETB RAM Read Pointer Register */
#define CS_ETB_RAM_WR_PTR    0x018     /**< ETB RAM Write Pointer Register */
#define CS_ETB_TRIGGER_COUNT 0x01C     /**< ETB Trigger Counter Register */
#define CS_ETB_CTRL          0x020     /**< ETB Control Register */
#define CS_ETB_CTRL_TraceCaptEn  0x01  /**< ETB Control bitfield (#CS_ETB_CTRL) : Trace Capture Enable*/
#define CS_ETB_RAM_WRITE_DATA 0x024	/**< ETB RAM Write Data Register */
#define CS_ETB_FLFMT_STATUS  0x300	/**< ETB Formatter and Flush Status Register */
#define CS_ETB_FLFMT_CTRL    0x304     /**< ETB Formatter and Flush Control Register */
/**@}*/

/** @name ETB FFCR bitfields
Bitfield definitions for the ETB Formatter and Flush Control Register (#CS_ETB_FLFMT_CTRL).
@{*/
#define CS_ETB_FLFMT_CTRL_StopTrig  0x2000 /**< Stop formatter when trigger event observed */
#define CS_ETB_FLFMT_CTRL_StopFl    0x1000 /**< Stop formatter when flush complete */
#define CS_ETB_FLFMT_CTRL_TrigFl    0x0400 /**< Indicate a trigger on Flush completion */
#define CS_ETB_FLFMT_CTRL_TrigEvt   0x0200 /**< Indicate a trigger on a trigger event */
#define CS_ETB_FLFMT_CTRL_TrigIn    0x0100 /**< Indicate a trigger on TRIGIN being asserted */
#define CS_ETB_FLFMT_CTRL_FOnMan    0x0040 /**< Flush on Manual */
#define CS_ETB_FLFMT_CTRL_FOnTrig   0x0020 /**< Flush on Trigger */
#define CS_ETB_FLFMT_CTRL_FOnFlIn   0x0010 /**< Flush on Flush in */
#define CS_ETB_FLFMT_CTRL_EnFCont   0x0002  /**< Continuous Formatting */
#define CS_ETB_FLFMT_CTRL_EnFTC     0x0001  /**< Enable Formatting */
/** @}*/

/** @name ETB FFSR bitfields 
Bitfield definitions for the ETB Formatter and Flush Status Register (#CS_ETB_FLFMT_STATUS).
@{*/
#define CS_ETB_FLFMT_STATUS_FtStopped 0x02 /**< Formatter stopped */
#define CS_ETB_FLFMT_STATUS_FlInProg  0x01 /**< Flush in progress */
/** @}*/

/** @name CoreSight Trace Memory Controller registers 
TMC specific registers - see ETB definitions for common register set between ETB and TMC */
/**@{*/
/* TMC */
#define CS_TMC_STATUS_Empty     0x10  /**< TMC does not contain any valid data in memory */
#define CS_TMC_STATUS_TMCReady  0x04  /**< TMC Status bitfield (#CS_ETB_STATUS): TMC ready (renamed from AcqComp) */
#define CS_TMC_MODE          0x028  /**< TMC mode control register */
#define CS_TMC_MODE_CIRCULAR   0    /**< TMC is currently in circular buffer mode */
#define CS_TMC_MODE_SWFIFO     1    /**< TMC is currently in software FIFO mode */
#define CS_TMC_MODE_HWFIFO     2    /**< TMC is currently in hardware FIFO mode */
#define CS_TMC_LBUFLEVEL     0x02C  /**< Latched buffer fill level register */
#define CS_TMC_CBUFLEVEL     0x030  /**< Current buffer fill level register */
#define CS_TMC_BUFWM         0x034  /**< Latched buffer water mark register */

#define CS_TMC_RRPHI         0x038  /**< RAM read pointer High register [ETR config only] */
#define CS_TMC_RWPHI         0x038  /**< RAM write pointer High register [ETR config only] */
#define CS_TMC_AXICTL        0x110  /**< AXI control register [ETR config only]*/
#define CS_TMC_DBALO         0x118  /**< Data buffer address low register [ETR config only]*/
#define CS_TMC_DBAHI         0x11C  /**< Data buffer address high register [ETR config only]*/

/**< TMC configuration type - a static property indicating which TMC features
     were configured in at design time.  These values match bits [7:6] in DEVID.
*/
#define CS_TMC_CONFIG_TYPE_ETB  0   /**< TMC ETB configuration - internal static buffer. */
#define CS_TMC_CONFIG_TYPE_ETR  1   /**< TMC ETR configuration - external bus master. */
#define CS_TMC_CONFIG_TYPE_ETF  2   /**< TMC ETF configuration - internal buffer and ATB output. */

/**@}*/

/** @name CoreSight Trace Funnel registers */
/**@{*/
/* CSTF (funnel) */
#define CS_FUNNEL_CTRL       0x000  /**< Funnel Control register */
#define CS_FUNNEL_MAX_PORTS  8	/**< Maximun number of funnel ports  */
/** @}*/

/** @name CoreSight Programmable Trace Replicator registers */
/**@{*/
#define CS_REPLICATOR_IDFILTER0  0x000	/**< ID filtering for ATB master port 0 */
#define CS_REPLICATOR_IDFILTER1  0x004	/**< ID filtering for ATB master port 1 */
#define CS_REPLICATOR_IDFILTER(n) (0x000 + 4*(n))  /**< ID filtering for ATB master port (n) */
/**@}*/

/** @} */

/** @defgroup cs_cti CoreSight Cross Trigger registers 
    @ingroup reg_defs

Register definitions and bitfield values for the Cross Trigger Interface component.
The cross trigger matrix does not have any programmable elements so needs no register definitions.
@{
*/

/* CTI */
#define CS_CTICONTROL        0x000     /**< CTI Control Register */
#define CS_CTICONTROL_GLBEN    0x00000001  /**< CTI CTRL bitfield (#CS_CTICONTROL): Enables or disables the ECT */
#define CS_CTIAPPSET         0x014     /**< CTI Application Channel Trigger Set Register */
#define CS_CTIAPPCLEAR       0x018     /**< CTI Application Channel Trigger Clear Register */
#define CS_CTIAPPPULSE       0x01C     /**< CTI Application Channel Pulse Register */
#define CS_CTIINEN(n)        (0x020 + (n)*4)	 /**< CTI Input Trigger (n) to Channel Enable */
#define CS_CTIOUTEN(n)       (0x0A0 + (n)*4)	 /**< CTI Channel to Output Trigger (n) Enable */
#define CS_CTITRIGINSTATUS   0x130     /**< CTI Trigger In Status Register */
#define CS_CTITRIGOUTSTATUS  0x134     /**< CTI Trigger Out Status Register */
#define CS_CTICHINSTATUS     0x138     /**< CTI Channel In Status Register */
#define CS_CTICHOUTSTATUS    0x13C     /**< CTI Channel Out Status Register */
#define CS_CTIGATE           0x140     /**< Enable CTI Channel Gate Register */

/** CTI Event channel enable bitfield values.
 'OR' combine for multiple channel source/sink for event. 
 */
#define CS_CTI_CHAN0_EN     0x01       /**< Enable Channel 0 bitfield value */
#define CS_CTI_CHAN1_EN     0x02       /**< Enable Channel 1 bitfield  value */
#define CS_CTI_CHAN2_EN     0x04       /**< Enable Channel 2 bitfield  value */
#define CS_CTI_CHAN3_EN     0x08       /**< Enable Channel 3 bitfield  value */

/** @} */

/** @defgroup cs_ts_r CoreSight Timestamp Generator registers 
    @ingroup reg_defs

Register definitions and bitfield values for the Timestamp Generator.
@{
*/
#define CS_CNTCR             0x000	/**< Counter Control Register */
#define CS_CNTCR_ENA            0x01	    /**< CNTCR bitfield : enable counter */
#define CS_CNTCR_HDBG           0x02	    /**< CNTCR bitfield : halt on debug  */
#define CS_CNTSR             0x004	/**< RO: Counter Status Reigster */
#define CS_CNTSR_DBGH           0x02	    /**< CNTSR bitfield : debug halted  */
#define CS_CNTCVL            0x008	/**< Current Counter Value Lower Register */
#define CS_CNTCVU            0x00C	/**< Current Counter Value Upper Register */
#define CS_CNTFID0           0x020	/**< Base Frequency ID register */

#define CS_RO_CNTCVL         0x000	 /**< Read-only interface, counter value low register  */
#define CS_RO_CNTCVU         0x004	 /**< Read-only interface, counter value high register */


/** @} */

/** @defgroup cs_debug CoreSight Core Debug registers (Arch v7) 
    @ingroup reg_defs

Register definitions and bitfield values for the Architecture v7 Cortex Core debug registers.
@{
*/

/* CPU debug */
#define CS_DBGDIDR           0x000     /**< Debug ID */
/** @name DBGDIDR Bit Values 
 see #CS_DBGDIDR
@{*/
#define CS_DBGDIDR_PCSR_imp    0x00002000    /**< DBGPCSR is register 33 */
#define CS_DBGDIDR_DEVID_imp   0x00008000    /**< DBGDEVID implemented */
/**@}*/

#define CS_DBGWFAR           0x018     /**< Watchpoint Fault Address */
#define CS_DBGVCR            0x01C     /**< Vector Catch */
#define CS_DBGECR            0x024     /**< Event Catch */
#define CS_DBGDSCCR          0x028     /**< Debug State Cache Control */
#define CS_DBGDSMCR          0x02C     /**< Debug State MMU Control */
#define CS_DBGDTRRX          0x080     /**< Host to Target Data Transfer */
#define CS_DBGPCSR_33        0x084     /**< RO: PC sampling register (when 33) */
#define CS_DBGITR            0x084     /**< WO: Instruction Transfer */

#define CS_DBGDSCR           0x088     /**< Debug Status and Control */
/** @name DBGDSCR Bit Values 
 see #CS_DBGDSCR
@{*/
#define CS_DBGDSCR_HALTED       0x00000001   /**< Processor Halted */
#define CS_DBGDSCR_RESTARTED    0x00000002   /**< Processor Restarted */
#define CS_DBGDSCR_SDABORT_l    0x00000040   /**< Sticky Synchronous Data Abort */
#define CS_DBGDSCR_ADABORT_l    0x00000080   /**< Sticky Asynchronous Data Abort */
#define CS_DBGDSCR_ITRen        0x00002000   /**< Execute ARM instruction enable */
#define CS_DBGDSCR_HDBGen       0x00004000   /**< Halting debug-mode enable */
#define CS_DBGDSCR_MDBGen       0x00008000   /**< Monitor debug-mode enable */
#define CS_DBGDSCR_NS           0x00020000   /**< Non-secure state status */
#define CS_DBGDSCR_InstrCompl_l 0x01000000   /**< Instruction Complete (latched) */
#define CS_DBGDSCR_PipeAdv      0x02000000   /**< Sticky Pipeline Advance */
#define CS_DBGDSCR_TXfull       0x20000000   /**< DBGDTRTX full */
#define CS_DBGDSCR_RXfull       0x40000000   /**< DBGDTRRX full */
/**@}*/
#define CS_DBGDTRTX          0x08C     /**< Target to Host Data Transfer */
#define CS_DBGDRCR           0x090     /**< WO: Debug Run Control */
/** @name DBGDRCR Bit Values 
 see #CS_DBGDRCR
@{*/
#define CS_DBGDRCR_HRQ         0x00000001   /**< Halt */
#define CS_DBGDRCR_RRQ         0x00000002   /**< Restart */
#define CS_DBGDRCR_CSE         0x00000004   /**< Clear Sticky Exceptions */
#define CS_DBGDRCR_CSPA        0x00000008   /**< Clear Sticky Pipeline Advance */
#define CS_DBGDRCR_CBRRQ       0x00000010   /**< Cancel Bus Requests */
/**@}*/
#define CS_DBGPCSR_40        0x0A0     /**< Program Counter Sampling (when 40) */
#define CS_DBGCIDSR          0x0A4     /**< Context ID Sampling */
#define CS_DBGVIDSR          0x0A8     /**< Virtualization ID Sampling */
#define CS_DBGBVR(n)         (0x100 + (n)*4)  /**< Breakpoint Value */
#define CS_DBGBCR(n)         (0x140 + (n)*4)  /**< Breakpoint Control */
#define CS_DBGWVR(n)         (0x180 + (n)*4)  /**< Watchpoint Value */
#define CS_DBGWCR(n)         (0x1C0 + (n)*4)  /**< Watchpoint Control */
#define CS_DBGPRCR           0x310     /**< Device Powerdown and Reset Control */
#define CS_DBGPRSR           0x314     /**< Device Powerdown and Reset Status */
/** @name DBGPRSR Bit Values 
 see #CS_DBGPRSR
@{*/
#define CS_DBGPRSR_HALTED      0x0010	   /**< (7.1) Processor Halted */
/**@}*/

#define CS_DBGAUTHSTATUS     0xFB8     /**< Authentication Status */
#define CS_DBGDEVID          0xFC8     /**< Debug Device ID */
#define CS_DBGDEVID1         0xFC4     /**< Debug Device ID 1 */

/** @} */

/** @defgroup cs_debug_v8 CoreSight Core Debug registers (Arch v8) 
    @ingroup reg_defs

Register definitions and bitfield values for the Architecture v8 Cortex Core debug registers.
@{
*/

#define CS_V8EDPCSR_l   0x0A0	    /**< Program Counter Sample register (low 32 bits) */
#define CS_V8EDCIDSR    0x0A4	    /**< Context ID Sample register */
#define CS_V8EDVIDSR    0x0A8	    /**< VMID Sample register */
#define CS_V8EDPCSR_h   0x0AC	    /**< Program Counter Sample register (high 32 bits) */

#define CS_V8EDPRSR     0x314	    /**< Device Powerdown and Reset Status Register */

/** @name EDPRSR Bit Values 
 Also contains masks and access valid values. See #CS_V8EDPRSR
@{*/
#define CS_V8EDPRSR_PWRUP       0x0001	    /**< Processor powered up. */
#define CS_V8EDPRSR_RESET       0x0004	    /**< Processor in reset state. */
#define CS_V8EDPRSR_HALTED      0x0010	    /**< Processor in halted debug state. */
#define CS_V8EDPRSR_OSLK        0x0020	    /**< OS Lock set. */
#define CS_V8EDPRSR_DLK         0x0040	    /**< Double lock set. */
#define CS_V8EDPRSR_EPMAD       0x0200	    /**< External PMU registers disable*/
#define CS_V8EDPRSR_COREOK_MSK  0x0075	    /**< Core Domain accessible mask.  Register bits that affect access to core power domain registers. */
#define CS_V8EDPRSR_COREOK_VAL  0x0001	    /**< Core Domain accessible value. If masked register value equal to this then we can access core power domain registers. */
/**@}*/


#define CS_V8EDPFR_l    0xD20	     /**< Processor feature register (lo) . Available ELs */
#define CS_V8EDDFR_l    0xD28	     /**< Debug Feature register (lo). Defines WP, BP, CTXT etc. */
#define CS_V8EDDEVID    0xFC8	     /**< Debug Device ID0. PC Sampling Availability */
/** @name EDDEVID Bit Values 
 Also contains masks and access valid values. See #CS_V8EDDEVID
@{*/
#define CS_V8EDDEVID_SMPL_MSK       0xF	   /**< Mask for the PC Sample support value */
#define CS_V8EDDEVID_SMPL_NONE      0x0	   /**< PC Sample support  not present */
#define CS_V8EDDEVID_SMPL_P_C       0x2	   /**< PC Sample support has PC sammple and CID sample only.*/
#define CS_V8EDDEVID_SMPL_P_C_V     0x3	   /**< PC Sample support has PC sammple CID and VMID.*/
/**@}*/

/** @} */

/** @defgroup cs_pmu CoreSight PMU registers 
    @ingroup reg_defs

Register definitions and bitfield values for the Performance monitoring unit 
on a cortex core.
@{
*/
#define CS_PMEVCNTR(n,scale) (0x000 + ((n)<<(scale)))  /**< Event Count Register (n) */
#define CS_PMEVCNTR32(n)     (0x000 + (n)*4)	/**< Event Count Register (32-bit) (n) */
#define CS_PMEVCNTR64(n)     (0x000 + (n)*8)	/**< Event Count Register (64-bit) (n) */
#define CS_PMXEVCNTR(n)      CS_PMEVCNTR32(n)	/**< Event Count Register (n) - deprecated, assumes 32-bit */
#define CS_PMCCNTR           0x07C     /**< Cycle Count Register - deprecated, assumes 32-bit */
#define CS_PMCCNTRW(scale)   CS_PMEVCNTR(31,scale)   /**< Cycle Count Register */
#define CS_PMXEVTYPER(n)     (0x400 + (n)*4)	/**< Event Type Register(n) */
#define CS_PMXEVTYPER31      0x47C     /**< Event Type Select Register (filter register) for CCNT */
#define CS_PMCNTENSET        0xC00     /**< Count Enable Set Register */
#define CS_PMCNTENCLR        0xC20     /**< Count Enable Clear Register */
#define CS_PMINTENSET        0xC40     /**< Interrupt Enable Set Register */
#define CS_PMINTENCLR        0xC60     /**< Interrupt Enable Clear Register */
#define CS_PMOVSR            0xC80     /**< Overflow Flag Status Register */
#define CS_PMSWINC           0xCA0     /**< Software Increment Register (WO) */
#define CS_PMOVSSET          0xCC0     /**< Overflow Flag Set Register */
#define CS_PMCFGR            0xE00     /**< RO: Configuration Register */
#define CS_PMCR              0xE04     /**< PMU Control Register */
#define CS_PMCR_E              0x01	  /**< PMCR Bitfield (#CS_PMCR): Enable */
#define CS_PMCR_P              0x02	  /**< PMCR Bitfield (#CS_PMCR): Event counter reset */
#define CS_PMCR_C              0x04	  /**< PMCR Bitfield (#CS_PMCR): Cycle counter reset */
#define CS_PMCR_D              0x08	  /**< PMCR Bitfield (#CS_PMCR): Cycle counter clock divider */
#define CS_PMCR_X              0x10	  /**< PMCR Bitfield (#CS_PMCR): Event bus export */
#define CS_PMUSERENR         0xE08     /**< User Enable Register */
#define CS_PMCEID0           0xE20     /**< Common Event Identification 0 */
#define CS_PMCEID1           0xE24     /**< Common Event Identification 1 */
#define CS_PMAUTHSTATUS      0xFB8     /**< Authentication Status Register */
/** @} */

/** @}*/

#endif				/* included */


/* end of csregisters.h */
