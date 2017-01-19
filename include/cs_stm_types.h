/*!
 * \file    cs_stm_types.h
 * \brief   CS Access API - STM programming
 * 
 * \copyright Copyright (c) 2015, ARM Limited. All Rights Reserved.
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

/*
 * Revision $Revision: $
 * SVN $Id: $
 */

#ifndef ARM_CS_STM_TYPES_H_INCLUDED
#define ARM_CS_STM_TYPES_H_INCLUDED

/**
   \defgroup stm_types STM Data types.
   @ingroup sw_stim

   Data types representing register programming models for STM

   @{
*/

/** 
 * \brief STM SPFEAT1R bit structure
 *  Features register 1 for the STM implmentation.
 */
typedef union stm_spfeat1 {
    unsigned int reg;	/**< complete register value */
    struct {
        unsigned int prot:4;
        unsigned int ts:2;
        unsigned int tsfreq:1;
        unsigned int forcets:1;
        unsigned int sync:2;
        unsigned int tracebus:4;
        unsigned int trigctl:2;
        unsigned int tsprescale:2;
        unsigned int hwten:2;
        unsigned int syncen:2;
        unsigned int swoen:2;
    } bits;	/**< register bitfields */
} stm_spfeat1_ut;

/** 
 * \brief STM SPFEAT2R bit structure
 *  Features register 2 for the STM implmentation.
 */
typedef union stm_spfeat2 {
    unsigned int reg;	/**< complete register value */
    struct {
        unsigned int spter:2;
        unsigned int sper:1;
        unsigned int res_3:1;
        unsigned int spcomp:2;
        unsigned int spoerride:1;
        unsigned int privmask:2;
        unsigned int sptrtype:2;
        unsigned int res_11:1;
        unsigned int dsize:4;
        unsigned int sptype:2;
    } bits;	/**< register bitfields */
} stm_spfeat2_ut;

/** 
 * \brief STM SPFEAT3R bit structure
 *  Features register 3 for the STM implmentation.
 */
typedef union stm_spfeat3 {
    unsigned int reg;	/**< complete register value */
    struct {
        unsigned int nummast:7;
    } bits;	/**< register bitfields */
} stm_spfeat3_ut;

/**
 * \brief STM Trace control and status register
 * 
 * Primary trace control register for the STM.
 */
typedef union stm_tcsr {
    unsigned int reg;  /**< complete register value */
    struct {
        unsigned int en:1;
        unsigned int tsen:1;
        unsigned int syncen:1;
        unsigned int hwten:1;
        unsigned int swoen:1;
        unsigned int compen:1;
        unsigned int res_6_7:2;
        unsigned int tsprescale:2;
        unsigned int res_10_15:6;
        unsigned int traceid:7;
        unsigned int busy:1;
    } bits; /**< register bitfields */
} stm_tcsr_t;


/**
 * \brief STM static configuration structure.
 * 
 * RO registers that describe the STM feature set.
 * 
 */
typedef struct stm_static_config {
/** @name feature registers
    @{*/
    /** feature registers */
    stm_spfeat1_ut spfeat1; /**< sp feat register 1 */
    stm_spfeat2_ut spfeat2; /**< sp feat register 2 */
    stm_spfeat3_ut spfeat3; /**< sp feat register 3 */
/** @}*/
} stm_static_config_t;

/**
 * \brief STM dynamic configuration structure.
 * 
 * Configuration for the STM. Registers that can be programmed to 
 * determine the operation of the STM software stimulus ports.
 * 
 */
typedef struct stm_config {

/** @name Stimulus port control registers
    @{*/
    unsigned int sper;
    unsigned int spter;
    unsigned int privmaskr;
    unsigned int spscr;
    unsigned int spmscr;
    unsigned int spoverrider;
    unsigned int spmoverrider;
    unsigned int sptrigcsr;
/** @}*/

/** @name Primary control and status registers 
    @{*/
    stm_tcsr_t tcsr;
    unsigned int syncr;
/** @}*/

    unsigned int config_op_flags;      /**< operations to perform on config structure */
} stm_config_t;


/** @name STM config operation flags.
    Bitflags defining the register blocks to read or write in dynamic config structure.
    @{*/
#define CS_STMC_NONE    0x0000	/**< clear the flags */
#define CS_STMC_CTRL    0x0001	/**< TCSR */
#define CS_STMC_SYNC    0x0002	/**< SYNCR */
#define CS_STMC_PENA    0x0004	/**< Port enable regs (SPER, SPTER, SPSCR, SPMCR, PRIVMASKR */
#define CS_STMC_OVER    0x0008	/**< Override regs (OVERIDERR, MOVERRIDER) */
#define CS_STMC_TRIG    0x0010	/**< Trigger control (SPTRIGCSR) */
#define CS_STMC_ALL     0xFFFF	/**< access all config registers */
/** @}*/

/** @name STM extended operation types
    Extended stimulus transaction types. 
    These are converted into offsets into the base port address for the type.
    @{*/

#define G_DMTS      0
#define G_DM        1
#define G_DTS       2
#define G_D         3
#define I_DMTS      4
#define I_DM        5
#define I_DTS       6
#define I_D         7
#define G_FLAGTS    8
#define G_FLAG      9
#define G_TRIGTS   10
#define G_TRIG     11
#define I_FLAGTS   12
#define I_FLAG     13
#define I_TRIGTS   14
#define I_TRIG     15

#define STM_OP_VALID(op) ((op >= G_DMTS) && (op <= I_TRIG))
#define STM_OP_DATA(op)  ((op >= G_DMTS) && (op <= I_D))

/** @}*/


/** @}*/

/* TBD add in hw event and dma configs.*/

#endif				// ARM_CS_STM_TYPES_H_INCLUDED

/* End of File cs_stm_types.h */
