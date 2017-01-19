/*!
 * \file       cs_etmv4_types.h
 * \brief      CS Access API - ETM/PTM programming
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

#ifndef _included_cs_etmv4_types_h
#define _included_cs_etmv4_types_h

#include "cs_etm_types.h"

/**
   \defgroup etmv4_types ETMv4 Data types.
   @ingroup etm_api

   Data types representing register programming models for ETMv4.

   @{
*/

/**
 * \brief ETMv4 TRACEIDR0 bit structure.
 *
 * ETMv4 Trace ID register 0 - shows trace features supported by
 * this implementation of the macrocell.
 * 
 */
typedef union {
    unsigned int reg; /**< complete register value */
    struct {
        unsigned int _res1_b0:1;
        unsigned int instp0:2;
        unsigned int trcdata:2;
        unsigned int trcbb:1;
        unsigned int trccond:1;
        unsigned int trccci:1;
        unsigned int _res0_b8:1;
        unsigned int retstack:1;
        unsigned int numevent:2;
        unsigned int condtype:2;
        unsigned int qfilt:1;
        unsigned int qsupp:2;
        unsigned int trcexdata:1;
        unsigned int _res0_b18_b23:6;
        unsigned int tssize:5;
        unsigned int commopt:1;
    } bits; /**< register bitfields */
} etm_v4_idr0_ut;

/**
 * \brief ETMv4 TRACEIDR1 bit structure.
 *
 * ETMv4 Trace ID register 1 - architecture versions for 
 * this implementation of the macrocell.
 * 
 */
typedef union {
    unsigned int reg;	/**< complete register value */
    struct {
        unsigned int revision:4;      /**< Revision */
        unsigned int trcarchmin:4;    /**< ETM arch version minor */
        unsigned int trcarchmaj:4;    /**< ETM arch version major */
        unsigned int _res1_b12_15:4;  /**< res1 */
        unsigned int _res0_b16_23:8;  /**< res0 */
        unsigned int designer:8;      /**< Component designer */
    } bits; /**< register bitfields */
} etm_v4_idr1_ut;


/**
 * \brief ETMv4 TRACEIDR2 bit structure.
 *
 * ETMv4 Trace ID register 2 - shows trace features supported by
 * this implementation of the macrocell.
 * 
 */
typedef union {
    unsigned int reg; /**< complete register value */
    struct {
        unsigned int iasize:5;
        unsigned int cidsize:5;
        unsigned int vmidsize:5;
        unsigned int dasize:5;
        unsigned int dvsize:5;
        unsigned int ccsize:4;
    } bits; /**< register bitfields */
} etm_v4_idr2_ut;

/**
 * \brief ETMv4 TRACEIDR3 bit structure.
 *
 * ETMv4 Trace ID register 3 - shows trace features supported by
 * this implementation of the macrocell.
 * 
 */
typedef union {
    unsigned int reg; /**< complete register value */
    struct {
        unsigned int ccitmin:12;
        unsigned int _res0:4;
        unsigned int exlevel_s:4;
        unsigned int exlevel_ns:4;
        unsigned int trcerr:1;
        unsigned int syncpr:1;
        unsigned int stallctl:1;
        unsigned int sysstall:1;
        unsigned int numproc:3;
        unsigned int nooverflow:1;
    } bits; /**< register bitfields */
} etm_v4_idr3_ut;

/**
 * \brief ETMv4 TRACEIDR4 bit structure.
 *
 * ETMv4 Trace ID register 4 - shows trace features supported by
 * this implementation of the macrocell.
 * 
 */
typedef union {
    unsigned int reg; /**< complete register value */
    struct {
        unsigned int numacpairs:4;
        unsigned int numdvc:4;
        unsigned int suppdac:1;
        unsigned int _res0:3;
        unsigned int numpc:4;
        unsigned int numrspair:4;
        unsigned int numsscc:4;
        unsigned int numcidc:4;
        unsigned int numvmidc:4;
    } bits; /**< register bitfields */
} etm_v4_idr4_ut;

/**
 * \brief ETMv4 TRACEIDR5 bit structure.
 *
 * ETMv4 Trace ID register 5 - shows trace features supported by
 * this implementation of the macrocell.
 * 
 */
typedef union {
    unsigned int reg; /**< complete register value */
    struct {
        unsigned int numextin:9;
        unsigned int numextinsel:3;
        unsigned int _res0a:4;
        unsigned int traceidsize:6;
        unsigned int atbtrig:1;
        unsigned int lpoverride:1;
        unsigned int _res0b:1;
        unsigned int numseqstate:3;
        unsigned int numcntr:3;
        unsigned int redfuncntr:1;
    } bits; /**< register bitfields */
} etm_v4_idr5_ut;

/** \brief ETMv4 static structure
    Structure representing the static RO configuration for the ETMv4. 
    Read from target hardware on component registration.
*/
typedef struct {
    etm_v4_idr0_ut idr0;    /**< ID register 0 */
    etm_v4_idr1_ut idr1;    /**< ID register 1 */
    etm_v4_idr2_ut idr2;    /**< ID register 2 */
    etm_v4_idr3_ut idr3;    /**< ID register 3 */
    etm_v4_idr4_ut idr4;    /**< ID register 4 */
    etm_v4_idr5_ut idr5;    /**< ID register 5 */
    unsigned int idr8;	    /**< ID register 8 */
    unsigned int idr9;	    /**< ID register 9 */
    unsigned int idr10;	     /**< ID register 10 */
    unsigned int idr11;	     /**< ID register 11 */
    unsigned int idr12;	     /**< ID register 12 */
    unsigned int idr13;	     /**< ID register 13 */
} cs_etm_v4_static_config_t;

/** \brief Get ETMv4 static structure.

    Extracts the ETMv4 static structure from the extension pointer in the 
    common static structure.

    \param sc_ptr pointer to the common static structure
    \return pointer to the cs_etm_v4_static_config_t structure.
*/
cs_etm_v4_static_config_t *get_etmv4_sc_ptr(cs_etm_static_config_t *
                                            sc_ptr);

/** \brief ETMv4 Trace Config reg stucture.
 * enables trace features.
 */
typedef union {
    unsigned int reg; /**< complete register value */
    struct {
        unsigned int _res1_0:1;
        unsigned int instp0:2;
        unsigned int bb:1;
        unsigned int cci:1;
        unsigned int _res0_5:1;
        unsigned int cid:1;
        unsigned int vmid:1;
        unsigned int cond:3;
        unsigned int ts:1;
        unsigned int rs:1;
        unsigned int qe:2;
        unsigned int _res0_15:1;
        unsigned int da:1;
        unsigned int dv:1;
    } bits; /**< register bitfields */
} cs_etm_v4_configr_t;

/** \brief ETMv4 dynamic configuration structure.
 *
 *  This structure contains the details of filters, events etc. to be
 *  programmed into or read from the ETM hardware.
 *  
 * The flags field defines which blocks of attributes are to be transferred 
 * using the set/get API.
 */
typedef struct cs_etmv4_config {
/** @name Base Config info.
    Version and access control set by `cs_etm_config_init_ex()` call.
    @{*/
    /** Actions: specify which fields to set/get */
    unsigned int flags;		/**< Configurations to action - register blocks to read or write on ETM hardware */
    unsigned int *idr;		/**< Pointer to ETMIDR - e.g. ETM version */
    cs_etm_v4_static_config_t *scv4; /**< Pointer to ETMv4 static configuration */
/** @}*/
/** @name Trace Control 
    General trace control configuration read/written with #CS_ETMC_CONFIG bit set in flags.
    @{*/
    cs_etm_v4_configr_t configr;  /**< Trace feature configuration */
    unsigned int stallcrlr;	  /**< Stall Control */
    unsigned int syncpr;	  /**< synchronisation period */
    unsigned int ccctlr;	  /**< Cycle count control  */
    unsigned int bbctlr;	  /**< Branch broadcast control */
    unsigned int traceidr;	  /**< Trace source ID  */
    unsigned int qctlr;		  /**< Q packet control */
/** @}*/
/** @name Trace Events
    Trace event selection and control accessed with #CS_ETMC_EVENTSELECT bit set in flags.

    Flags #CS_ETMC_TS_EVENT, #CS_ETMC_TRIGGER_EVENT #CS_ETMC_EXTOUT unused in ETMv4 as functionality has been
    combined in the event select and enable registers.
    @{*/
    unsigned int eventctlr0r;	  /**< Event selection */
    unsigned int eventctlr1r;	  /**< Event enables */
    unsigned int tsctlr;	  /**< Global Timestamp control event */
/** @}*/
/** @name Trace Enable
    Trace ViewInst, ViewData, start/stop and enable event configuration accessed with #CS_ETMC_TRACE_ENABLE bit set in flags
    @{*/
    unsigned int victlr;	  /**< ViewInst control */
    unsigned int viiectlr;	  /**< ViewInst include/exclude control */
    unsigned int vissctlr;	  /**< ViewInst Start/Stop control */
    unsigned int vipcssctlr;	  /**< ViewInst Start/Stop PE comparator control */

    unsigned int vdctlr;	  /**< ViewData control */
    unsigned int vdsacctlr;	  /**< ViewData inc/exc single address comparator control*/
    unsigned int vdarcctlr;	  /**< ViewData inc/exc address range comparator control*/
/** @}*/
/** @name Sequencer
    Trace sequencer programming access when #CS_ETMC_SEQUENCER is set in flags.
    @{*/
#define ETMv4_NUM_SEQ_EVT_MAX 3	/**< Max number of sequencer state transition event registers. */
    unsigned int seqevr[ETMv4_NUM_SEQ_EVT_MAX];	  /**< Sequencer state transition event */
    unsigned int seqrstevr;   /**< Sequencer reset control  */
    unsigned int seqstr;      /**< Sequencer state */
/** @}*/

/** @name Counters
    Counter programming access when #CS_ETMC_COUNTER is set in flags
    @{*/
#define ETMv4_NUM_COUNTERS_MAX 4    /**< Max number of counters */
    /** Group of registers to program a counter. */
    struct _cntrs {
        unsigned int cntrldvr;	/**< counter reload values */
        unsigned int cntctlr;	/**< counter control */
        unsigned int cntvr;	/**< counter value */
    } counter[ETMv4_NUM_COUNTERS_MAX];	  /**< set of counter registers */
    unsigned int counter_acc_mask; /**< Selection mask for counters to read / write (bin n = 1, access counter n. )*/
/** @}*/

/** @name Resource Selection
    Trace resource selectors, external input selection - accessed when #CS_ETMC_RES_SEL set in flags
    @{*/
#define ETMv4_NUM_RES_SEL_CTL_MAX 32	/**< Number of resource selection registers (/2 for pairs) */
    unsigned int rsctlr[ETMv4_NUM_RES_SEL_CTL_MAX];   /**< Resource selectors */
    unsigned int extinselr;   /**< External Input select */
    unsigned int rsctlr_acc_mask;      /**< Select rsctlrs to access, n=2-31 (0 and 1 are reserved and never accessed) */
/** @}*/

/** @name Single Shot control 
    Single shot comparator control - accessed when #CS_ETMC_SSHOT_CTRL set in flags
    @{*/
#define ETMv4_NUM_SS_COMP_MAX 8	/**< max number of SS comparator controls */
    /** Group of registers to program a single shot comparator. */
    struct _sscmp {
        unsigned int ssccr;   /**< SS comparator control */
        unsigned int sscsr;   /**< SS comparator status */
        unsigned int sspcicr; /**< SS PE comparator input  */
    } ss_comps[ETMv4_NUM_SS_COMP_MAX];	  /**< Set of Single Shot comparator resources */
    unsigned int ss_comps_acc_mask;   /**< Bitfield Select ss_comps to access */
/** @}*/

/** @name Address Comparators
    Address Comparator logic - accessed when #CS_ETMC_ADDR_COMP is set in flags
    @{*/
#define ETMv4_NUM_ADDR_COMP_MAX 16  /**< max number of Address comparators */
    /** Group of registers to program an address comparator */
    struct _adrcmp {
        unsigned int acvr_l;  /**< Address Comparator Value low [31:0] */
        unsigned int acvr_h;  /**< Address comparator value hi  [63:32] */
        unsigned int acatr_l; /**< Address comparator type low [31:0] */
    } addr_comps[ETMv4_NUM_ADDR_COMP_MAX];    /**< Set of address comparators */
    unsigned int addr_comps_acc_mask; /**< Bitfield selects address comps to access */
/** @}*/

/** @name Data Value Comparators
    Data Value Comparator logic - accessed when #CS_ETMC_DATA_COMP is set in flags

    When these elements are written back to the ETM, the mask is used to zero out the masked
    bits in the value as required by the ETMv4 architecture specification.
    @{*/
#define ETMv4_NUM_DATA_COMP_MAX 16  /**< max number of data value comparators */
    /** Group of registers to program a data comparator. */
    struct _dvcmp {
        unsigned int dvcvr_l;	  /**< data comparator value lo [31:0]  */
        unsigned int dvcvr_h;	  /**< data comparator value hi [63:32] */
        unsigned int dvcmr_l;	  /**< data comparator mask lo [31:0]  */
        unsigned int dvcmr_h;	  /**< data comparator mask hi [63:32] */
    } data_comps[ETMv4_NUM_DATA_COMP_MAX];    /**< set of data value comparators */
    unsigned int data_comps_acc_mask; /**< bitfield selects data comps to access */
/** @}*/

/** @name Context ID Comparators 
    Context ID Comparator logic - accessed when #CS_ETMC_CXID_COMP is set in flags
    @{*/
#define ETMv4_NUM_CXID_COMP_MAX 8   /**< max number of context ID comparators */
    /** Group of registers to program a context ID comparator */
    struct _ctxtidcmp {
        unsigned int cidcvr_l;	  /**< context ID comparator value lo [31:0] */
        unsigned int cidcvr_h;	  /**< context ID comparator value hi [63:32] */
    } cxid_comps[ETMv4_NUM_CXID_COMP_MAX];    /**< set of context ID comparators */
    unsigned int cidcctlr0;   /**< context ID comparator control 0 */
    unsigned int cidcctlr1;   /**< context ID comparator control 1 */
    unsigned int cxid_comps_acc_mask; /**< bitfield selects CID comps to access - control always accessed */
/** @}*/

/** @name VMID Comparators 
    VMID Comparator logic - accessed when #CS_ETMC_VMID_COMP is set in flags
    @{*/
#define ETMv4_NUM_VMID_COMP_MAX 8   /**< max number of VMID comparators */
    /** Group of registers to program a VMID comparator. */
    struct _vmidcmp {
        unsigned int vmidcvr_l;	      /**< VMID comparator value lo [31:0] */
        unsigned int vmidcvr_h;	      /**< VMID comparator value hi [63:32] */
    } vmid_comps[ETMv4_NUM_VMID_COMP_MAX];    /**< set of VMID comparators */
    unsigned int vmidcctlr0;	      /**< VMID comparator control 0 */
    unsigned int vmidcctlr1;	      /**< VMID comparator control 0 */
    unsigned int vmid_comps_acc_mask;	  /**< bitfield selects VMID comps to access - control always accessed */
/** @}*/
} cs_etmv4_config_t;


/** @} */


#endif /*_included_cs_etmv4_types_h */
