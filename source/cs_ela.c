/*!
 * \file       cs_ela.c
 * \brief      CS Access API - access an ELA (Embedded Logic Anlyzer) device
 *
 * Only basic features of ELA are provided. The user is assumed
 * to be familiar with ELA configuration and trace analysis.
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

#include "cs_ela.h"
#include "cs_access_cmnfns.h"

#define ela_has_atb(d) (d->v.ela.ram_size == 0)
#define ela_is_600(d)  (d->v.ela.is_ela600)

/*
 * Initialize a signal vector to the signal width of the ELA. N.b. comparator width may be smaller.
 */
int cs_ela_clear_signals(cs_device_t dev, cs_ela_signals_t *sigs)
{
    unsigned int i;
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    for (i = 0; i < d->v.ela.signal_width/32; ++i) {
        sigs->v.words[i] = 0;
    }
    /* Don't set sigs->n_bits, in case this is actually a (smaller) comparator vector */
    return 0;
}


/* Helper function - no device access */
int cs_ela_set_signals(cs_ela_signals_t *sigs, unsigned int bit_offset, unsigned int n_bits, uint64_t value)
{
    if (sigs->n_bits != 0 && (bit_offset + n_bits > sigs->n_bits)) {
        if (0) {
            fprintf(stderr, "trying to set bits [%u:%u] in %u-bit signal vector\n",
                bit_offset+n_bits-1, bit_offset, sigs->n_bits);
        }
        return 1;
    }
    while (n_bits) {
        unsigned int wix = bit_offset / 32;
        unsigned int pos_in_word = bit_offset % 32;
        unsigned int n_bits_this_word = (n_bits+pos_in_word) > 32 ? 32-pos_in_word : n_bits;
        uint32_t data = (uint32_t)value;
        if (n_bits_this_word < 32) { 
            uint32_t mask = (((uint32_t)1 << n_bits_this_word) - 1) << pos_in_word;
            assert(mask != 0);
            data = (sigs->v.words[wix] & ~mask) | ((data << pos_in_word) & mask);
        }
        sigs->v.words[wix] = data;
        bit_offset += n_bits_this_word;
        n_bits -= n_bits_this_word;
        value >>= n_bits_this_word;
        assert(n_bits == 0 || (bit_offset%32) == 0);
    }
    assert(value == 0);
    return 0;
}

#define ONES(n) (((n) == 64 ? ~(uint64_t)0 : ((uint64_t)1 << (n)) - 1))

int cs_ela_set_compare_value(cs_ela_trigconf_t *tc, unsigned int bit_offset, unsigned int n_bits, uint64_t value)
{
    int rc;
    rc = cs_ela_set_signals(&tc->compare_value, bit_offset, n_bits, value);
    if (!rc) {
        rc = cs_ela_set_signals(&tc->compare_mask, bit_offset, n_bits, ONES(n_bits));
    }
    return rc;
}

/* Helper function - no device access */
uint64_t cs_ela_get_signals(cs_ela_signals_t const *sigs, unsigned int bit_offset, unsigned int n_bits)
{
    uint64_t value = 0;
    unsigned int value_offset = 0;
    while (n_bits) {
        unsigned int wix = bit_offset / 32;
        unsigned int pos_in_word = bit_offset % 32;
        unsigned int n_bits_this_word = (n_bits+pos_in_word) > 32 ? 32-pos_in_word : n_bits;
        uint32_t data = sigs->v.words[wix];
        if (n_bits_this_word < 32) {
            uint32_t mask = (((uint32_t)1 << n_bits_this_word) - 1) << pos_in_word;
            assert(mask != 0);
            data = (data & mask) >> pos_in_word;
        }
        value |= (uint64_t)data << value_offset;
        bit_offset += n_bits_this_word;
        n_bits -= n_bits_this_word;
        value_offset += n_bits_this_word;
        assert(n_bits == 0 || (bit_offset%32) == 0);
    }
    return value; 
}

static int read_regs(struct cs_device *d, unsigned int off, unsigned int n_words, uint32_t *data)
{
    unsigned int i;
    for (i = 0; i < n_words; ++i) {
        data[i] = _cs_read(d, off+(4*i));
    }
    return 0;
}

/* Read signal vector from device registers, e.g. comparator value or mask */
static int read_signals(struct cs_device *d, unsigned int off, unsigned int n_bits, cs_ela_signals_t *sigs)
{
    sigs->n_bits = n_bits;
    return read_regs(d, off, n_bits/32, sigs->v.words);
}

static int write_regs(struct cs_device *d, unsigned int off, unsigned int n, uint32_t const *data)
{
    unsigned int i;
    for (i = 0; i < n; ++i) {
        _cs_write(d, off+(4*i), data[i]);
    }
    return 0;
}

int cs_ela_get_config(cs_device_t dev, cs_ela_config_t *c)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    c->ptaction = _cs_read(d, CS_ELA_PTACTION);
    c->timectrl = _cs_read(d, CS_ELA_TIMECTRL);
    if (ela_is_600(d)) {
        c->counter_select = _cs_read(d, CS_ELA_CNTSEL);
    } else {
        c->counter_select = 0;
    }
    return 0;
}


int cs_ela_get_atb_config(cs_device_t dev, cs_ela_atb_config_t *c)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    if (ela_has_atb(d)) {
        c->atbctrl = _cs_read(d, CS_ELA_ATBCTRL);
        c->auxctrl = _cs_read(d, CS_ELA_AUXCTRL);
    } else {
        return -1;
    }
    return 0;
}


int cs_ela_set_config(cs_device_t dev, cs_ela_config_t const *c)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    _cs_write(d, CS_ELA_PTACTION, c->ptaction);
    _cs_write(d, CS_ELA_TIMECTRL, c->timectrl);
    if (d->v.ela.n_trigger_states >= 5) {
        _cs_write(d, CS_ELA_TSSR, c->tssr);
    } else {
        assert(c->tssr == 0);
        if (c->tssr != 0) {
            return -1;
        }
    }
    if (ela_is_600(d)) {
        _cs_write(d, CS_ELA_CNTSEL, c->counter_select);
    } else {
        assert(c->counter_select == 0);
        if (c->counter_select != 0) {
            return -1;
        }
    }
    return 0;
}


int cs_ela_set_atb_config(cs_device_t dev, cs_ela_atb_config_t const *c)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    if (ela_has_atb(d)) {
        /* Avoid writing the ATID. Caller must call cs_set_trace_source_id(). */
        uint32_t old_atbctrl_atid = _cs_read(d, CS_ELA_ATBCTRL) & 0x0000ff00;
        _cs_write(d, CS_ELA_ATBCTRL, (c->atbctrl & ~0x0000ff00) | old_atbctrl_atid);
        _cs_write(d, CS_ELA_AUXCTRL, c->auxctrl);
    } else {
        return -1;
    }
    return 0;
}


int cs_ela_get_trigconf(cs_device_t dev, unsigned int ts, cs_ela_trigconf_t *tc)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    if (ts >= d->v.ela.n_trigger_states) {
        return -1;
    }
    tc->signal_group = _cs_read(d, CS_ELA_SIGSEL(ts));
    tc->trigger_control = _cs_read(d, CS_ELA_TRIGCTRL(ts));
    tc->next_state = _cs_read(d, CS_ELA_NEXTSTATE(ts));
    tc->action = _cs_read(d, CS_ELA_ACTION(ts));
    tc->alt_next_state = _cs_read(d, CS_ELA_ALTNEXTSTATE(ts));
    tc->alt_action = _cs_read(d, CS_ELA_ALTACTION(ts));
    if (ela_has_atb(d)) {
        tc->twbsel = _cs_read(d, CS_ELA_TWBSEL(ts));
    }
    tc->external_mask = _cs_read(d, CS_ELA_EXTMASK(ts));
    tc->external_value = _cs_read(d, CS_ELA_EXTCOMP(ts));
    tc->counter_compare = _cs_read(d, CS_ELA_COUNTCOMP(ts));
    if (ela_is_600(d)) {
        tc->comp_control = _cs_read(d, CS_ELA_COMPCTRL(ts));
        tc->alt_comp_control = _cs_read(d, CS_ELA_ALTCOMPCTRL(ts));
        tc->qualifier_mask = _cs_read(d, CS_ELA_QUALMASK(ts));
        tc->qualifier_value = _cs_read(d, CS_ELA_QUALCOMP(ts));
    } else {
        /* If we read these undefined registers from ELA-500,
           we probably get zeroes anyway. But it's neater to test. */
        tc->comp_control = 0;
        tc->alt_comp_control = 0;
        tc->qualifier_mask = 0;
        tc->qualifier_value = 0;
    }
    read_signals(d, CS_ELA_SIGMASK(ts), d->v.ela.comp_width, &tc->compare_mask);
    read_signals(d, CS_ELA_SIGCOMP(ts), d->v.ela.comp_width, &tc->compare_value);
    return 0;
}

/* True if word has one bit set, or is zero */
static int __attribute__((unused)) is_zero_one_hot(uint32_t n)
{
    return (n & -n) == n;
}

/* True if word has exactly one bit set */
static int __attribute__((unused)) is_one_hot(uint32_t n)
{
    return n != 0 && is_zero_one_hot(n);
}


int cs_ela_log2(uint32_t x)
{
    int p = 0;
    if (!is_one_hot(x)) {
        return -1;
    }
    while (x != 1) {
        ++p;
        x >>= 1;
    }
    return p;
}


int cs_ela_init_trigconf(cs_device_t dev, cs_ela_trigconf_t *tc)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    tc->compare_mask.n_bits = d->v.ela.comp_width;
    tc->compare_value.n_bits = d->v.ela.comp_width;
    return 0;
}


int cs_ela_set_trigconf(cs_device_t dev, unsigned int ts, cs_ela_trigconf_t const *tc)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    assert(is_one_hot(tc->signal_group));
    if (!is_one_hot(tc->signal_group)) {
        return -1;
    }
    if (ts >= d->v.ela.n_trigger_states) {
        return -1;
    }
    _cs_write(d, CS_ELA_SIGSEL(ts), tc->signal_group);
    _cs_write(d, CS_ELA_TRIGCTRL(ts), tc->trigger_control);
    assert(is_zero_one_hot(tc->next_state));
    if (!is_zero_one_hot(tc->next_state)) {
        return -1;
    }
    _cs_write(d, CS_ELA_NEXTSTATE(ts), tc->next_state);   /* 0 means don't change, final state */
    _cs_write(d, CS_ELA_ACTION(ts), tc->action);
    _cs_write(d, CS_ELA_ALTNEXTSTATE(ts), tc->alt_next_state);
    _cs_write(d, CS_ELA_ALTACTION(ts), tc->alt_action);
    if (ela_is_600(d)) {
        _cs_write(d, CS_ELA_COMPCTRL(ts), tc->comp_control);
        _cs_write(d, CS_ELA_ALTCOMPCTRL(ts), tc->alt_comp_control);
        _cs_write(d, CS_ELA_QUALMASK(ts), tc->qualifier_mask);
        _cs_write(d, CS_ELA_QUALCOMP(ts), tc->qualifier_value);
    } else {
        /* If we wrote the registers on ELA-500, they'd be ignored. */
        assert(tc->comp_control == 0);
        assert(tc->alt_comp_control == 0);
        assert(tc->qualifier_mask == 0);
        assert(tc->qualifier_value == 0);
        if (tc->comp_control != 0 || tc->alt_comp_control != 0 ||
            tc->qualifier_mask != 0 || tc->qualifier_value != 0) {
            return -1;
        }
    }
    if (ela_has_atb(d)) {
        _cs_write(d, CS_ELA_TWBSEL(ts), tc->twbsel);
    }
    _cs_write(d, CS_ELA_EXTMASK(ts), tc->external_mask);
    _cs_write(d, CS_ELA_EXTCOMP(ts), tc->external_value);
    _cs_write(d, CS_ELA_COUNTCOMP(ts), tc->counter_compare);
    write_regs(d, CS_ELA_SIGMASK(ts), d->v.ela.comp_width/32, tc->compare_mask.v.words);
    write_regs(d, CS_ELA_SIGCOMP(ts), d->v.ela.comp_width/32, tc->compare_value.v.words);
    return 0;
}


int cs_ela_signal_width(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    return d->v.ela.signal_width;
}

int cs_ela_comparator_width(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    return d->v.ela.comp_width;
}

int cs_ela_n_trigger_states(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    return d->v.ela.n_trigger_states;
}

int cs_ela_ram_n_entries(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    return d->v.ela.ram_size;
}


int cs_ela_reset_ram(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    if (d->v.ela.ram_size == 0) {
        return -1;
    }
    /* "Write to the RWAR to set the first RAM address to be written and to clear the WRAP bit." */
    _cs_write(d, CS_ELA_RWAR, 0x00000000);
    return 0;
}


int cs_ela_enable(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    /* Having cs_ela_enable() automatically reset the internal RAM (if present)
       is an API design decision - it's not necessary in the hardware. */
    if (d->v.ela.ram_size > 0) {
        cs_ela_reset_ram(d);
    }
    /* Set the RUN bit. ELA should be active from this point on, no need to wait. */
    return _cs_write(d, CS_ELA_CTRL, CS_ELA_CTRL_RUN);
}

int cs_ela_disable(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    /* Unset the RUN bit, and then wait for BUSY to clear. */
    _cs_write(d, CS_ELA_CTRL, 0);
    return _cs_waitnot(d, CS_ELA_CTRL, CS_ELA_CTRL_TRACE_BUSY);
}

int cs_ela_get_state(cs_device_t dev, cs_ela_state_t *st)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    st->active = _cs_isset(d, CS_ELA_CTRL, CS_ELA_CTRL_RUN); 
    /* Reading CTSR samples the state and some other data. Can be done when RUN=1. */
    st->trigger_state = _cs_read(d, CS_ELA_CTSR);
    st->counter = _cs_read(d, CS_ELA_CCVR);
    st->action = _cs_read(d, CS_ELA_CAVR);
    return 0;
}

int cs_ela_read_ram_entry(cs_device_t dev, cs_ela_record_t *rec)
{
    unsigned int i;
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_ELA);
    /* "The first read of the RRD after an RRA update returns the trace data header byte value" */
    {
        unsigned int const header = _cs_read(d, CS_ELA_RRDR);
        rec->type = header & 0x3;
        rec->trigger_state = (header >> 2) & 0x7;
    }
    /* All record types require RAM reads as if reading a signal group. */
    for (i = 0; i < d->v.ela.signal_width/32; ++i) {
        rec->signals.v.words[i] = _cs_read(d, CS_ELA_RRDR);
    }
    rec->signals.n_bits = d->v.ela.signal_width;
    return 0;
}


unsigned int cs_ela_record_type(cs_ela_record_t const *rec)
{
    return rec->type;
}


uint64_t cs_ela_record_timestamp(cs_ela_record_t const *rec)
{
    uint64_t timestamp = 0;
    if (rec->type == 2) {
        /* Probably this is a no-op on little-endian systems. */
        timestamp = ((uint64_t)rec->signals.v.words[1] << 32) | rec->signals.v.words[0];
    }
    return timestamp;
}


int cs_ela_read_init(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    int n_entries = -1;
    assert(d->type == DEV_ELA);
    if (d->v.ela.ram_size != 0) {
        uint32_t ram_lo;
        uint32_t rwa = _cs_read(d, CS_ELA_RWAR);   /* get the current write pointer */
        if (rwa & 0x80000000) {
            /* RAM has wrapped */
            ram_lo = rwa & 0x7fffffff;
            n_entries = d->v.ela.ram_size;
        } else {
            /* RAM has not wrapped */
            ram_lo = 0;
            n_entries = rwa;
        }
        /* "Writes to the RRA cause the trace SRAM data at that address to be
           transferred into the holding register. After the SRAM read data is
           transferred to the holding register, RRA increments by one.
           This prepares the RRA address for sequential RRDR reads."
           So we use an unchecked write (no read-back). */
        _cs_write_wo(d, CS_ELA_RRAR, ram_lo);
    }
    return n_entries;
}

/* end of cs_ela.c */
