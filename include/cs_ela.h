/*!
 * \file       cs_ela.h
 * \brief      CS Access API - access an ELA (Embedded Logic Anlyzer) device
 *
 * Only basic features of ELA are provided. The user is assumed
 * to be familiar with ELA configuration and trace analysis,
 * as described in the ELA Technical Reference Manual and
 * the Application Note (ARM-ECM-0442477).
 *
 * An ELA device will either have an internal RAM or be an ATB trace source.
 * The ATB trace source option is only available on ELA-600 onwards.
 *
 * The general procedure is:
 *
 *   - cs_device_register() each ELA device
 *   - if ELA is using ATB, use CSAL APIs to connect the ELA to the
 *     ATB trace fabric and set the ATB trace source id
 *   - discover ELA device configuration, if not already known
 *   - use device-specific information (not provided here) to select
 *     signals to match. Construct suitable cs_ela_trigconf_t structures
 *     using cs_ela_set_compare_value() to set fields.
 *   - cs_ela_set_config()
 *   - cs_ela_set_trigconf() for each trigger state configuration
 *   - cs_ela_enable()
 *   - cs_ela_disable()
 *   - if ELA is using ATB, retrieve trace from CoreSight trace sink
 *   - if ELA is using internal RAM, use cs_ela_read_init() and
 *     cs_ela_read_ram_entry()
 *
 * This API does not have any knowledge of the ELA's input signals.
 * The end user is assumed to know details of signal groups.
 *
 * ELAs with internal RAM may apply scrambling to captured signals.
 * The details of this scrambling are device-specific.
 *
 * \copyright  Copyright (C) ARM Limited, 2022. All rights reserved.
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
#ifndef _included_cs_ela_h
#define _included_cs_ela_h

#include <stdint.h>
#include "cs_types.h"

#define CS_ELA_MAX_SIGNALS 256    /* Maximum supported in any ELA configuration */
#define CS_ELA_MAX_SIGNAL_WORDS (CS_ELA_MAX_SIGNALS/32)

/**
   Bit vector for signal group comparators, and internal RAM.
 */
typedef struct {
    unsigned short n_bits;
    union {
        unsigned char bytes[CS_ELA_MAX_SIGNALS/8];
        uint32_t words[CS_ELA_MAX_SIGNAL_WORDS];
    } v;
} cs_ela_signals_t;



/**
   ELA action specifier.

   Use a combination of CS_ELA_ACTION_xxx flags.

   Generally, values other than CS_ELA_ACTION_TRACE require expert
   knowledge of how the ELA is integrated into target silicon.

   CS_ELA_ACTION_TRACE         - enable trace
   CS_ELA_ACTION_STOPCLOCK     - stop clocks for serial scan dump
   CS_ELA_ACTION_CTTRIGOUT(x)  - drive 2-bit value on CCTRIGOUT[1:0] CTI output
   CS_ELA_ACTION_ELAOUTPUT(x)  - drive 4-bit value on ELAOUTPUT[3:0]
 */
typedef uint32_t cs_ela_action_t;


/**
   Overall ELA configuration.
 */
typedef struct {
    /* Usually use CS_ELA_TIMECTRL_TSEN | (tsbit << CS_ELA_TIMECTRL_TSINT_SHIFT) */
    uint32_t timectrl;           /**< 0x004: Timestamp configuration */
    /* When n_trigger_states is 5 or 8, tssr can be set to the one-hot value
       of the last trigger state, to enable independent trace from that state.
       I.e. the only valid values are 0 or (1<<(N_TRIGGER_STATES-1)).
       If the ELA has 4 trigger states, this feature is not available. */
    uint32_t tssr;               /**< 0x008: Trigger state select (if available) */
    cs_ela_action_t ptaction;    /**< 0x010: Pre-trigger actions */
    uint32_t counter_select;     /**< 0x018: Counter select for trace (ELA-600 only) */
} cs_ela_config_t;


/**
   ELA ATB output configuration.

   Note: this structure contains the ATID (in ATBCTRL), but is not used to set it.
   Instead, call cs_set_trace_source_id() from the general CSAL API.
 */
typedef struct {
    uint32_t atbctrl;            /**< 0x00C: ATB control (ELA-600 ATB only) */
    uint32_t auxctrl;            /**< 0x014: Auxiliary control (ELA-600 ATB only) */
} cs_ela_atb_config_t;


/**
   Trigger state configuration for a single trigger state.
   Some fields are only available from ELA-600 onwards.

   Signal fields can be set using cs_ela_set_compare_value().
 */
typedef struct {
    unsigned int signal_group;   /**< 0x100: Signal group select 1<<(0..11): one-hot */
    uint32_t trigger_control;    /**< 0x104: Trigger control */
    uint32_t next_state;         /**< 0x108: Next state: one-hot or zero */
    cs_ela_action_t action;      /**< 0x10C: Action on match */
    uint32_t alt_next_state;     /**< 0x110: Alternative next state */
    cs_ela_action_t alt_action;  /**< 0x114: Alternative action */
    uint32_t comp_control;       /**< 0x118: Comparator control (ELA-600) */
    uint32_t alt_comp_control;   /**< 0x11C: Alternative comparator control (ELA-600) */
    uint32_t counter_compare;    /**< 0x120: Counter compare */
    uint32_t twbsel;             /**< 0x128: Trace write byte select (ELA-600 ATB) */
    uint32_t external_mask;      /**< 0x130: External mask */
    uint32_t external_value;     /**< 0x134: External compare value */
    uint32_t qualifier_mask;     /**< 0x138: Qualifier mask (ELA-600) */
    uint32_t qualifier_value;    /**< 0x13C: Qualifier value (ELA-600) */
    cs_ela_signals_t compare_mask;    /**< 0x140: Signal mask bit vector */
    cs_ela_signals_t compare_value;   /**< 0x180: Signal compare bit vector */
} cs_ela_trigconf_t;


/**
   ELA current state - can be read while ELA is active.
 */
typedef struct {
    unsigned int active:1;   /**< True if ELA is active */
    uint32_t trigger_state;  /**< Current trigger state */
    uint32_t counter;        /**< Current value of the counter */
    uint32_t action;         /**< Current action */
} cs_ela_state_t;


/**
    ELA trace record, from internal SRAM.
 */
typedef struct {
   // unsigned char header;           /**< Header byte */
    unsigned char type;               /**< Record type: counter, signals or timestamp */
#define CS_ELA_RECORD_COUNTER     0   /**< Record contains counters (ELA-600 only) */
#define CS_ELA_RECORD_SIGNALS     1   /**< Record contains GRP_WIDTH bits of data */
#define CS_ELA_RECORD_TS          2   /**< Record contains a timestamp value */
    unsigned char trigger_state;      /**< Trigger state when captured */
    cs_ela_signals_t signals;         /**< Payload */
} cs_ela_record_t;


/**
   Extract the type of a record, e.g. CS_ELA_RECORD_SIGNALS.
 */
unsigned int cs_ela_record_type(cs_ela_record_t const *);


/**
   For a timestamp record, extract the timestamp as an integer value.
 */
uint64_t cs_ela_record_timestamp(cs_ela_record_t const *);


/**
   Clear a signal buffer to zeroes.
 */
int cs_ela_clear_signals(cs_device_t, cs_ela_signals_t *);

/**
   Extract a value, up to 64 bits, at an arbitrary offset.
 */
uint64_t cs_ela_get_signals(cs_ela_signals_t const *, unsigned int pos, unsigned int n);

/**
   Insert a value, up to 64 bits, at an arbitrary offset.
 */
int cs_ela_set_signals(cs_ela_signals_t *, unsigned int pos, unsigned int n, uint64_t value);


/**
   Insert a value and suitable mask into a trigger state configuration.
 */
int cs_ela_set_compare_value(cs_ela_trigconf_t *, unsigned int pos, unsigned int n, uint64_t value);


/**
   ELA static property: incoming signal width, in bits (64, 128 or 256)
 */
int cs_ela_signal_width(cs_device_t);

/**
   ELA static property: number of trigger states (4, 5 or 8)
 */
int cs_ela_n_trigger_states(cs_device_t);


/**
   Total number of entries in the static RAM.
   0 for non-RAM configuration. 64 might be a typical RAM configuration.
   Total RAM size is this multiplied by the signal group size eg. 64x256 bits.
 */
int cs_ela_ram_n_entries(cs_device_t);


/* ELA programming */


/**
   Set ELA overall programming configuration.
 */
int cs_ela_set_config(cs_device_t, cs_ela_config_t const *);


/**
   Set ELA ATB output port configuration.
   This does not update ATBCTRL.ATID (if present). ATB trace source ID
   must be set by calling cs_set_trace_source_id().
 */
int cs_ela_set_atb_config(cs_device_t, cs_ela_atb_config_t const *);


/**
   Get ELA overall programming configuration.
   Error if ELA does not have ATB output.
 */
int cs_ela_get_config(cs_device_t, cs_ela_config_t *);


/**
   Get ELA ATB output port configuration.
   Error if ELA does not have ATB output.
 */
int cs_ela_get_atb_config(cs_device_t, cs_ela_atb_config_t *);


/**
   Set trigger #<n> configuration
*/
int cs_ela_set_trigconf(cs_device_t, unsigned int ts, cs_ela_trigconf_t const *);

/**
   Read trigger #<n> configuration
*/
int cs_ela_get_trigconf(cs_device_t, unsigned int ts, cs_ela_trigconf_t *);


/**
   Set the internal RAM write pointer to the start of the RAM.

   Error if ELA does not have internal RAM.
 */
int cs_ela_reset_ram(cs_device_t);


/* ELA run control */

/**
   Enable the ELA.

   If the ELA has internal RAM, this calls cs_ela_reset_ram() before enabling.
*/
int cs_ela_enable(cs_device_t);


/**
   Inspect the current state of the ELA. Can be used at any time.
 */
int cs_ela_get_state(cs_device_t, cs_ela_state_t *);


/**
   Disable the ELA and wait for BUSY to clear. Return error if it does not clear.
*/
int cs_ela_disable(cs_device_t);


/**
   Initialize for reading, and return the number of available entries.
   Return -1 if this ELA does not have an internal RAM.
*/
int cs_ela_read_init(cs_device_t);

/**
   Read the first available entry, and then step to the next one.
 */
int cs_ela_read_ram_entry(cs_device_t, cs_ela_record_t *);

#endif /* end of cs_ela.h */
#ifdef __cplusplus
}
#endif
