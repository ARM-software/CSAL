/*!
 * \file       cs_etm_types.h
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

#ifndef _included_cs_etm_types_h
#define _included_cs_etm_types_h

/**
   \defgroup etm_api ETM programming API 

   @brief ETM Programming API functions and types.
 
   Programming interface for the ETM v3.x, PTM v1.x and ETM v4.x hardware.

   @{
*/

/**
   \defgroup etm_ptm_types ETMv3 Data types. 
   @ingroup etm_api

   Types and structures representing register programming models for ETM v3 and PTM.
   @{
*/

/** \brief ETMv3 ETMCCR bit structure.
 
    Static configuration - read from ETMCCR. Defines available ETM resources.

*/
typedef union etmv3_ccr {
    unsigned int reg;	/**< complete register value */
    struct {
        unsigned int n_addr_comp_pairs:4;
        unsigned int n_data_comp:4;
        unsigned int n_memory_map_decoders:5;
        unsigned int n_counters:3;
        unsigned int sequencer_present:1;
        unsigned int n_ext_in:3;
        unsigned int n_ext_out:3;
        unsigned int fifofull_present:1;
        unsigned int _variant:7;
        unsigned int etmid_present:1;
    } s;    /**< Common resource IDs - all ETM variants */
    struct {
        unsigned int _common:24;
        unsigned int n_cxid_comp:2;
        unsigned int tssb_present:1;
    } s3x;  /**< Additional fields for ETMv3 */
} etm_v3_ccr_ut;

/**
 * \brief ETMv3 ETMSCR bit structure.
 *
 * System configuration register - shows ETM features supported by
 * this implementation of the macrocell.
 * 
 */
typedef struct etm_v3_scr {
    union {
        unsigned int reg; /**< complete register value */
        struct {
            unsigned int _variant_0:8;
            unsigned int fifofull:1;
            unsigned int _variant_1:3;
            unsigned int n_supported_proc:3;
        } sc;	  /**< Common ETM static configuration  */
        struct {
            unsigned int max_port_size_20:3;
            unsigned int _common_0:6;
            unsigned int max_port_size_3:1;
            unsigned int cur_port_size_supported:1;
            unsigned int cur_port_mode_supported:1;
            unsigned int _common_1:5;
            unsigned int no_fetch_comp:1;
        } sc3x;	  /**< ETM static config for v3.x  */
    } raw; /**< register bitfields */
    unsigned int max_port_size;	/**< Port size from combined port size bit fields.*/
} etm_v3_scr_t;

/**
 * \brief ETMv3 ETMCCER bit structure.
 *
 * ETM Configuration Code Extension Register - shows ETM features supported by
 * this implementation of the macrocell.
 * 
 */
typedef union etm_v3_ccer {
    unsigned int reg; /**< complete register value */
    struct {
        unsigned int n_ext_in_selectors:3;
        unsigned int ext_in_bus_size:8;
        unsigned int all_reg_readable:1;
        unsigned int data_comp_not_supported:1;
        unsigned int n_inst:3;
        unsigned int n_EICE_wp_inputs:4;
        unsigned int tssb_use_EICE:1;
        unsigned int etmeibcr:1;
        unsigned int timestamping:1;
        unsigned int return_stack:1;  /* PTM only */
        unsigned int _reserved:2;
        unsigned int virt_ext:1;
        unsigned int reduced_counter:1;
        unsigned int timestamp_enc:1;
        unsigned int timestamp_size:1;
    } cce;  /**< CCE bitfields */
} etm_v3_ccer_ut;

/** @} */

/**
   \defgroup etm_common ETM Common data types. 
   @ingroup etm_api

   Common structures types and defines for ETM programming.

   @{*/

/** \brief ETM static configuration structure.
 *
 * This structure contains the details of the static configuration of
 * the ETM, and whether or not certain features are supported or not.
 *
 *  Read from target hardware on component registration.
 */
typedef struct cs_etm_static_config {

    etm_v3_ccr_ut ccr;	    /**< ETMCCR  - ETMv3/PTM basic configuration */

    etm_v3_scr_t scr;	    /**< ETMSCR  - ETMv3/PTM additional configuration */

    etm_v3_ccer_ut ccer;    /**< ETMCCR - ETMv3/PTM additional configuration  */

    unsigned int version;   /**< ETM architecture version */

    void *p_cfg_ext;	    /**< pointer to extended static config information - Arch specific, ETMv4 + */
} cs_etm_static_config_t;

/** @name ETM config request flags.

    Bit flags defining the register configuration blocks to be read from or written to ETM 
    hardware. 
    @{*/
#define CS_ETMC_NONE           0x0000	/**< No configuration */
#define CS_ETMC_ADDR_COMP      0x0001	/**< Address comparators */
#define CS_ETMC_DATA_COMP      0x0002	/**< Data comparators */
#define CS_ETMC_COUNTER        0x0004	/**< Counters */
#define CS_ETMC_TRACE_ENABLE   0x0008	/**< Trace enabling conditions */
#define CS_ETMC_TS_EVENT       0x0010	/**< Timestamp event */
#define CS_ETMC_TRIGGER_EVENT  0x0020	/**< Trigger event */
#define CS_ETMC_CXID_COMP      0x0040	/**< CONTEXTID comparators */
#define CS_ETMC_CONFIG         0x0080	/**< General configuration */
#define CS_ETMC_SEQUENCER      0x0100	/**< Sequencer */
#define CS_ETMC_EXTOUT         0x0200	/**< External outputs */
#define CS_ETMC_VMID_COMP      0x0400	/**< VMID comparator */
#define CS_ETMC_EVENTSELECT    0x1000	/**< ETMv4 event selection and control */
#define CS_ETMC_RES_SEL        0x2000	/**< ETMv4 resource selection */
#define CS_ETMC_SSHOT_CTRL     0x4000	/**< ETMv4 single shot comparator control */
#define CS_ETMC_ALL            0xFFFF	/**< All configuration */
/**@} */

/** @name ETM Major version defines. 
 * 
 * Extracts major version from ETM architecture version byte.
 @{*/
#define CS_ETMVERSION_ETMv3  0x20   /**< Major version value for ETMv3 */
#define CS_ETMVERSION_PTM    0x30   /**< Major version value for PTM */
#define CS_ETMVERSION_ETMv4  0x40   /**< Major version value for ETMv4 */
#define CS_ETMVERSION(maj, min) ((maj) | (min))
#define CS_ETMVERSION_MAJOR(x) ((x) & 0xF0) /**< Major version number from ETM ID register */
#define CS_ETMVERSION_MINOR(x) ((x) & 0x0F) /**< Minor version number from ETM ID register */
#define CS_ETMVERSION_IS_ETMV3(x) ((x) < CS_ETMVERSION_PTM) /**< Version is ETMv3 */
#define CS_ETMVERSION_IS_PTM(x) (((x) >= CS_ETMVERSION_PTM) && ((x) < CS_ETMVERSION_ETMv4))	/**< Version is PTM */
#define CS_ETMVERSION_IS_ETMV4(x) ((x) >=  CS_ETMVERSION_ETMv4)	    /**< Version is ETMv4 */
/**@}*/

/** @} */


/** \brief ETMv3/PTM dynamic configuration structure.
 * @ingroup etm_ptm_types
 *
 *  This structure contains the details of filters, events etc. to be
 *  programmed into or read from the ETM hardware.
 *  
 * The flags field defines which attributes are to be transferred using the set/get API.
 */
typedef struct cs_etm_config {
/** @name Base Config info.
    Version and access control set by `cs_etm_config_init_ex()` call.
    @{*/
    unsigned int flags;		/**< Configurations to action - read or write on ETM hardware */
    unsigned int *idr;		/**< Pointer to ETMIDR - e.g. ETM version */
    cs_etm_static_config_t *sc;	/**< Pointer to static configuration */
/** @}*/
/** @name Trace Control 
    General trace control configuration read/written with #CS_ETMC_CONFIG bit set in flags.
    @{*/
    /** ETM dynamic control register */
    struct _cr {
        union _u_cr_reg_bits {
            unsigned int reg; /**< Control register - dynamic configuration */
            struct _cr_bits {
                unsigned int etm_power_down:1;
                unsigned int monitor_cprt:1;
                unsigned int data_access:2;
                unsigned int _port_size_20:3;
                unsigned int stall_processor:1;
                unsigned int branch_output:1;
                unsigned int debug_req_ctrl:1;
                unsigned int prog_mode:1;
                unsigned int etm_en:1;
                unsigned int cycle_accurate:1;
                unsigned int _port_mode_2:1;
                unsigned int cxid_size:2;
                unsigned int _port_mode_10:2;
                unsigned int suppress_data:1;
                unsigned int filter_cprt:1;
                unsigned int data_only_mode:1;
                unsigned int _port_size_3:1;
                unsigned int disable_dbg_writes:1;
                unsigned int disable_sw_writes:1;
                unsigned int instr_res_ac:1;
                unsigned int proc_select:3;
                unsigned int timestamp_enabled:1;
                unsigned int ret_stack:1;
                unsigned int vmid_trace:1;
            } c;  /**< register bit fields */
        } raw;	 /**< Union between the raw control register and its bit fields */
        unsigned int port_size;	    /**< Port size value extracted from bit fields */
        unsigned int port_mode;	    /**< Port mode value extracted from bit fields */
    } cr;
/** @}*/


/** @name Progrmming constants 
    Constants defined for trace programming
    @{*/
#define CS_ETMC_MAX_ADDR_COMP 16     /**< Maximum number of single address comparators */
#define CS_ETMC_MAX_DATA_COMP (CS_ETMC_MAX_ADDR_COMP / 2) /**< Maximum number of data comparators */
#define CS_ETMC_MAX_COUNTER   8	   /**< Maximum number of counters */
#define CS_ETMC_MAX_CXID_COMP 3	   /**< Maximum number of context id comparators */
#define CS_ETMC_MAX_EXTOUT    4	   /**< Maximum number of external outputs */
/** @}*/

    /* Data for get/set */
/** @name Timestamp Events
    Registers read/written with #CS_ETMC_TS_EVENT bit set in flags.
    @{*/
    unsigned int timestamp_event;    /**< Event that causes a timestamp packet */
/** @}*/

/** @name Trace Enable Events
    Registers read/written with #CS_ETMC_TRACE_ENABLE bit set in flags.
    @{*/
    unsigned int trace_enable_event; /**< Event that enables trace */
    unsigned short trace_start_comparators;  /**< Mask of address comparators to start trace */
    unsigned short trace_stop_comparators;   /**< Mask of address comparators to stop trace */
    unsigned int trace_enable_cr1;   /**< CR1 enable - see ETM docs for details */
    unsigned int trace_enable_cr2;   /**< CR2 enable - see ETM docs for details */

    unsigned int vdata_event;	  /**< View Data Event Register */
    unsigned int vdata_ctl1;	  /**< View Data control register 1 */
    unsigned int vdata_ctl2;	  /**< View Data control register 2 */
    unsigned int vdata_ctl3;	  /**< View Data control register 3 */
/** @}*/

/** @name Trace Trigger Event
    Registers read/written with #CS_ETMC_TRIGGER_EVENT bit set in flags.
    @{*/
    unsigned int trigger_event;	     /**< Event that causes trigger */
/** @}*/

/** @name Address Comparators
    Registers read/written with #CS_ETMC_ADDR_COMP bit set in flags.
    @{*/
    /** Group of regs for Address comparator configuration */
    struct _acompregs {
        unsigned int address;	       /**< Address to be compared against */
        unsigned int access_type;      /**< Access type */
    } addr_comp[CS_ETMC_MAX_ADDR_COMP];
    unsigned int addr_comp_mask;     /**< Mask of address comparators to action */
/** @}*/

/** @name Data Comparators
    Registers read/written with #CS_ETMC_DATA_COMP bit set in flags.
    @{*/
    /** Group of regs for Data comparator configuration */
    struct _dcompregs {
        unsigned int value; /**< Data compare value */
        unsigned int data_mask;	    /**< Data compare mask */
    } data_comp[CS_ETMC_MAX_DATA_COMP];
    unsigned int data_comp_mask;     /**< Mask of data comparators to action */
/** @}*/

/** @name Counters
    Registers read/written with #CS_ETMC_COUNTER bit set in flags.
    @{*/
    /** Group of Counter configuration registers */
    struct _cntrregs {
        unsigned int reload_value;     /**< Value to be reloaded into counter */
        unsigned int enable_event;     /**< Event that enables counter decrement */
        unsigned int reload_event;     /**< Event that causes counter reload */
        unsigned int value;	       /**< Current value of counter */
    } counter[CS_ETMC_MAX_COUNTER];
    unsigned int counter_mask;	     /**< Mask of counters to action */
/** @}*/

/** @name Context ID comparators
    Registers read/written with #CS_ETMC_CXID_COMP bit set in flags.
    @{*/
    unsigned int cxid_mask;	     /**< Mask to be used for all CONTEXTID comparisons */
    /** Context ID comparators */
    struct _ctxtidregs {
        unsigned int cxid;	       /**< Context id (or mask) to compare against */
    } cxid_comp[CS_ETMC_MAX_CXID_COMP];
    unsigned int cxid_comp_mask;     /**< Mask of CONTEXTID comps to action */
/** @}*/

/** @name Event Sequencer
    Registers read/written with #CS_ETMC_SEQUENCER bit set in flags.
    @{*/
    /** Sequencer configuration */
    struct _seqregs {
        unsigned int state;	       /**< Current state of sequencer */
        unsigned int transition_event[ /*CS_ETMSEQ_TRANSITIONS */ 6];
        /**< Event that causes sequencer change */
    } sequencer;
/** @}*/

/** @name Extout Events 
    Registers read/written with #CS_ETMC_EXTOUT bit set in flags.
    @{*/
    unsigned int extout_event[CS_ETMC_MAX_EXTOUT];  /**< Event that causes external output */
    unsigned int extout_mask;	     /**< Mask of external outputs to action */
/** @}*/

} cs_etm_config_t;

/** @} */

#endif				/* _included_cs_etm_types_h */
