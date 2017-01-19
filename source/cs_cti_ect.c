/*
  Coresight Access Library - API component register access functions

  Copyright (C) ARM Limited, 2013. All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include "cs_access_cmnfns.h"
#include "cs_cti_ect.h"

/* ---------- Local functions ------------- */
/**
 *  A channel descriptor records the connection of a set of trigger sources
 *  (i.e. trigger outputs from devices) to a set of trigger destinations
 *  (i.e. trigger inputs to devices).  The channel descriptor also records
 *  the set of distinct CTI devices involved.
 */
struct cs_channel {
    unsigned int n_src;
    unsigned int n_dst;
    unsigned int n_cti;		/* Number of distinct CTIs involved */
    /* Arbitrary array size just for prototyping this API, not a limit of CS architecture */
#define CS_CHAN_LIMIT 16
#define CS_CHAN_CTI_LIMIT 16
    cs_trigsrc_t sources[CS_CHAN_LIMIT];
    cs_trigdst_t dests[CS_CHAN_LIMIT];
    cs_device_t ctis[CS_CHAN_CTI_LIMIT];
};


static unsigned int cs_cti_get_global_channels(cs_device_t cti)
{
    struct cs_device *d = DEV(cti);
    assert(d->type == DEV_CTI);

    _cs_unlock(d);
    return _cs_read(d, CS_CTIGATE);
}

/**
 *  Check if a channel can be handled entirely within one CTI without
 *  needing to use the cross-trigger matrix.
 */
static int cs_ect_is_local(cs_channel_t chan)
{
    struct cs_channel *c = (struct cs_channel *) chan;
    assert(c->n_cti != 0);
    return c->n_cti == 1;
}

/**
 *  Check whether a channel descriptor already uses a given CTI device.
 */
static int cs_channel_uses_cti(cs_channel_t chan, cs_device_t cti)
{
    unsigned int i;
    struct cs_channel const *c = (struct cs_channel const *) chan;
    assert(DEV(cti)->type == DEV_CTI);
    for (i = 0; i < c->n_cti; ++i) {
        if (cti == c->ctis[i])
            return 1;
    }
    return 0;
}

static int cs_ect_add_cti(struct cs_channel *c, cs_device_t cti)
{
    if (cs_channel_uses_cti(c, cti)) {
        return 0;		/* already used - nothing to do */
    } else {
        if (c->n_cti == CS_CHAN_CTI_LIMIT - 1) {
            return -1;
        } else {
            c->ctis[c->n_cti++] = cti;
            return 0;
        }
    }
}

static unsigned int cs_cti_used_global_channels(cs_device_t cti)
{
    return cs_cti_used_channels(cti) & cs_cti_get_global_channels(cti);
}

static unsigned int cs_cti_unused_channels(cs_device_t cti)
{
    return (~cs_cti_used_channels(cti)) & CTI_CHANNEL_MASK;
}

/* ========== API functions ================ */

/*
  CTI low-level interface - programs CTI components in isolation.
*/

int cs_cti_enable(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_CTI);
    return _cs_set(d, CS_CTICONTROL, CS_CTICONTROL_GLBEN);
}

int cs_cti_disable(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    assert(d->type == DEV_CTI);
    return _cs_clear(d, CS_CTICONTROL, CS_CTICONTROL_GLBEN);
}

int cs_cti_set_trigin_channels(cs_device_t cti, unsigned int ctiport,
                               unsigned int mask)
{
    struct cs_device *d = DEV(cti);
    assert(d->type == DEV_CTI);
    assert(ctiport <= CTI_MAX_IN_PORTS);

    _cs_unlock(d);
    return _cs_write(d, CS_CTIINEN(ctiport), mask);
}

int cs_cti_set_trigout_channels(cs_device_t cti, unsigned int ctiport,
                                unsigned int mask)
{
    struct cs_device *d = DEV(cti);
    assert(d->type == DEV_CTI);
    assert(ctiport <= CTI_MAX_OUT_PORTS);

    _cs_unlock(d);
    return _cs_write(d, CS_CTIOUTEN(ctiport), mask);
}

int cs_cti_set_global_channels(cs_device_t cti, unsigned int mask)
{
    struct cs_device *d = DEV(cti);
    assert(d->type == DEV_CTI);

    _cs_unlock(d);
    return _cs_write(d, CS_CTIGATE, mask);
}



/*
  Return the mask of channels "in use" - i.e. allocated to a trigger input and/or output
*/
unsigned int cs_cti_used_channels(cs_device_t cti)
{
    unsigned int i;
    struct cs_device *d = DEV(cti);
    unsigned int mask = 0;

    assert(d->type == DEV_CTI);
    for (i = 0; i < d->v.cti.n_triggers; ++i) {
        mask |= _cs_read(d, CS_CTIINEN(i));
    }
    for (i = 0; i < d->v.cti.n_triggers; ++i) {
        mask |= _cs_read(d, CS_CTIOUTEN(i));
    }
    return mask;
}

int cs_cti_pulse_channel(cs_device_t cti, unsigned int channel)
{
    struct cs_device *d = DEV(cti);
    assert(d->type == DEV_CTI);
    assert(channel < d->v.cti.n_channels);

    _cs_unlock(d);
    return _cs_write_wo(d, CS_CTIAPPPULSE, (1U << channel));
}

int cs_cti_set_active_channel(cs_device_t cti, unsigned int channel)
{
    struct cs_device *d = DEV(cti);
    assert(d->type == DEV_CTI);
    assert(channel < d->v.cti.n_channels);

    _cs_unlock(d);
    return _cs_set(d, CS_CTIAPPSET, (0x1U << channel));
}

int cs_cti_clear_active_channel(cs_device_t cti, unsigned int channel)
{
    struct cs_device *d = DEV(cti);
    assert(d->type == DEV_CTI);
    assert(channel < d->v.cti.n_channels);

    _cs_unlock(d);
    return _cs_set(d, CS_CTIAPPCLEAR, (0x1U << channel));
}

int cs_cti_clear_all_active_channels(cs_device_t cti)
{
    unsigned int clear_mask = 0;

    struct cs_device *d = DEV(cti);
    assert(d->type == DEV_CTI);

    _cs_unlock(d);
    clear_mask = ((0x1U << d->v.cti.n_channels) - 1);
    return _cs_set(d, CS_CTIAPPCLEAR, clear_mask);
}

unsigned int cs_cti_trigin_status(cs_device_t cti)
{
    struct cs_device *d = DEV(cti);
    assert(d->type == DEV_CTI);

    _cs_unlock(d);
    return _cs_read(d, CS_CTITRIGINSTATUS);
}

unsigned int cs_cti_trigout_status(cs_device_t cti)
{
    struct cs_device *d = DEV(cti);
    assert(d->type == DEV_CTI);

    _cs_unlock(d);
    return _cs_read(d, CS_CTITRIGOUTSTATUS);
}

int cs_cti_reset(cs_device_t cti)
{
    int rc;
    int i;
    struct cs_device *d = DEV(cti);
    assert(d->type == DEV_CTI);

    _cs_unlock(d);
    rc = _cs_clear(d, CS_CTICONTROL, CS_CTICONTROL_GLBEN);
    if (rc != 0) {
        return rc;
    }
    for (i = 0; i < d->v.cti.n_triggers; ++i) {
        _cs_write(d, CS_CTIINEN(i), 0);
    }
    for (i = 0; i < d->v.cti.n_triggers; ++i) {
        _cs_write(d, CS_CTIOUTEN(i), 0);
    }
    /* Enable channel interface propagation for all channels, as on reset */
    return _cs_write(d, CS_CTIGATE, CTI_CHANNEL_MASK);
}

void cs_cti_diag(void)
{
    struct cs_device *d;
    for (d = G.device_top; d != NULL; d = d->next) {
        unsigned int sin, sout, cact, cgate, cin, cout;
        unsigned int i, j;
        if (d->type != DEV_CTI)
            continue;
        diagf("CTI at %" CS_PHYSFMT "", d->phys_addr);
        if (d->affine_cpu != CS_CPU_UNKNOWN && d->affine_cpu != CS_NO_CPU) {
            diagf(" (cpu #%u)", d->affine_cpu);
        }
        diagf(" (%sabled)",
              (_cs_isset(d, CS_CTICONTROL, CS_CTICONTROL_GLBEN) ? "en" :
               "dis"));
        diagf(":\n");
        /* Show static and dynamic configuration, and status */
        sin = _cs_read(d, CS_CTITRIGINSTATUS);
        sout = _cs_read(d, CS_CTITRIGOUTSTATUS);
        cact = _cs_read(d, CS_CTIAPPSET);
        cgate = _cs_read(d, CS_CTIGATE);
        cin = _cs_read(d, CS_CTICHINSTATUS);
        cout = _cs_read(d, CS_CTICHOUTSTATUS);

        diagf
            ("  TIN=%02X TOUT=%02X CIN=%02X COUT=%02X CACTIVE=%02X CGATE=%02X\n",
             sin, sout, cin, cout, cact, cgate);
        diagf("  channels (%u):\n", d->v.cti.n_channels);
        if (cact != 0 || cin != 0 || cout != 0 ||
            cgate != CTI_CHANNEL_MASK
            || cs_cti_used_channels(DEVDESC(d)) != 0) {
            for (i = 0; i < d->v.cti.n_channels; ++i) {
                diagf("    #%u:", i);
                for (j = 0; j < d->v.cti.n_triggers; ++j) {
                    if (_cs_isset(d, CS_CTIINEN(j), (1U << i)))
                        diagf(" %u", j);
                }
                diagf(" ->");
                for (j = 0; j < d->v.cti.n_triggers; ++j) {
                    if (_cs_isset(d, CS_CTIOUTEN(j), (1U << i)))
                        diagf(" %u", j);
                }
                if ((cin & (1U << i)) != 0)
                    diagf(" (input-active)");
                if ((cout & (1U << i)) != 0)
                    diagf(" (output-active)");
                if ((cact & (1U << i)) != 0)
                    diagf(" (active)");
                if ((cgate & (1U << i)) == 0)
                    diagf(" (local)");
                diagf("\n");
            }
        } else {
            diagf("    none in use\n");
        }

        diagf("  incoming triggers (%u):\n", d->v.cti.n_triggers);
        for (i = 0; i < d->v.cti.n_triggers; ++i) {
            unsigned int chans = _cs_read(d, CS_CTIINEN(i));
            int is_active = (sin & (1U << i)) != 0;
            struct cs_device *dev = d->v.cti.src[i].dev;
            if (dev == NULL && chans == 0 && !is_active) {
                continue;
            }
            diagf("    #%u:", i);
            if (d->v.cti.src[i].dev != NULL) {
                diagf(" %s:%" CS_PHYSFMT "", cs_device_type_name(dev),
                      dev->phys_addr);
                diagf(".%u ", d->v.cti.src[i].devportid);
            }
            if (chans != 0) {
                diagf(" -> chans %X", chans);
            }
            if (is_active) {
                diagf(" (active)");
            }
            diagf("\n");
        }
        diagf("  outgoing triggers (%u):\n", d->v.cti.n_triggers);
        for (i = 0; i < d->v.cti.n_triggers; ++i) {
            unsigned int chans = _cs_read(d, CS_CTIOUTEN(i));
            int is_active = (sout & (1U << i)) != 0;
            struct cs_device *dev = d->v.cti.dst[i].dev;
            if (dev == NULL && chans == 0 && !is_active) {
                continue;
            }
            diagf("    #%u:", i);
            if (d->v.cti.dst[i].dev != NULL) {
                diagf(" %s:%" CS_PHYSFMT "", cs_device_type_name(dev),
                      dev->phys_addr);
                diagf(".%u ", d->v.cti.dst[i].devportid);
            }
            if (chans != 0) {
                diagf(" <- chans %X", chans);
            }
            if ((sout & (1U << i)) != 0) {
                diagf(" (active)");
            }
            diagf("\n");
        }
    }
}


/*
  CTI registration interface
*/
#define trigisvalid(s) (s.cti != NULL && DEV(s.cti)->type == DEV_CTI)

cs_trigsrc_t cs_cti_trigsrc(cs_device_t cti, unsigned int portid)
{
    cs_trigsrc_t s;
    s.cti = cti;
    s.ctiport = portid;
    assert(trigisvalid(s));
    return s;
}

cs_trigdst_t cs_cti_trigdst(cs_device_t cti, unsigned int port)
{
    cs_trigdst_t s;
    s.cti = cti;
    s.ctiport = port;
    assert(trigisvalid(s));
    return s;
}

cs_device_t cs_trigsrc_cti(cs_trigsrc_t src)
{
    return src.cti;
}

cs_device_t cs_trigdst_cti(cs_trigdst_t dst)
{
    return dst.cti;
}


int cs_cti_connect_trigsrc(cs_device_t dev, unsigned int devport,
                           cs_trigsrc_t src)
{
    struct cs_device *d = DEV(src.cti);
    assert(DEV(dev)->type != DEV_CTI);
    assert(trigisvalid(src));
    d->v.cti.src[src.ctiport].dev = DEV(dev);
    d->v.cti.src[src.ctiport].devportid = devport;
    return 0;
}

int cs_cti_connect_trigdst(cs_trigdst_t dst, cs_device_t dev,
                           unsigned int devport)
{
    struct cs_device *d = DEV(dst.cti);
    assert(DEV(dev)->type != DEV_CTI);
    assert(trigisvalid(dst));
    d->v.cti.dst[dst.ctiport].dev = DEV(dev);
    d->v.cti.dst[dst.ctiport].devportid = devport;
    return 0;
}

cs_trigsrc_t cs_trigsrc(cs_device_t dev, unsigned int devportid)
{
    struct cs_device *d;
    for (d = G.device_top; d != NULL; d = d->next) {
        unsigned int i;
        if (d->type != DEV_CTI)
            continue;
        for (i = 0; i < d->v.cti.n_triggers; ++i) {
            if (d->v.cti.src[i].dev == DEV(dev)
                && d->v.cti.src[i].devportid == devportid) {
                return cs_cti_trigsrc(DEVDESC(d), i);
            }
        }
    }
    {
        cs_trigsrc_t s;
        s.cti = CS_ERRDESC;
        s.ctiport = 0;
        return s;
    }
}

cs_trigdst_t cs_trigdst(cs_device_t dev, unsigned int devportid)
{
    struct cs_device *d;
    for (d = G.device_top; d != NULL; d = d->next) {
        unsigned int i;
        if (d->type != DEV_CTI)
            continue;
        /* Check all outbound triggers */
        for (i = 0; i < d->v.cti.n_triggers; ++i) {
            if (d->v.cti.dst[i].dev == DEV(dev)
                && d->v.cti.dst[i].devportid == devportid) {
                return cs_cti_trigdst(DEVDESC(d), i);
            }
        }
    }
    {
        cs_trigdst_t s;
        s.cti = CS_ERRDESC;
        s.ctiport = 0;
        return s;
    }
}



/*
  Mid-level interface to cross-triggering.
*/





cs_channel_t cs_ect_get_channel(void)
{
    struct cs_channel *c =
        (struct cs_channel *) malloc(sizeof(struct cs_channel));
    assert(c != NULL);
    memset(c, 0, sizeof(struct cs_channel));
    return c;
}

int cs_ect_add_trigsrc(cs_channel_t chan, cs_trigsrc_t src)
{
    struct cs_channel *c = (struct cs_channel *) chan;
    if (c->n_src == CS_CHAN_LIMIT - 1) {
        return -1;
    } else {
        c->sources[c->n_src++] = src;
        return cs_ect_add_cti(c, src.cti);
    }
}

int cs_ect_add_trigdst(cs_channel_t chan, cs_trigdst_t dst)
{
    struct cs_channel *c = (struct cs_channel *) chan;
    if (c->n_dst == CS_CHAN_LIMIT - 1) {
        return -1;
    } else {
        c->dests[c->n_dst++] = dst;
        return cs_ect_add_cti(c, dst.cti);
    }
}

int cs_ect_diag(cs_channel_t chan)
{
    int i;
    struct cs_channel const *c = (struct cs_channel const *) chan;

    diagf("Channel request:\n");
    diagf("  Trigger sources:\n");
    for (i = 0; i < c->n_src; ++i) {
        diagf("    %p %u\n", c->sources[i].cti, c->sources[i].ctiport);
    }
    diagf("  Trigger destinations:\n");
    for (i = 0; i < c->n_dst; ++i) {
        diagf("    %p %u\n", c->dests[i].cti, c->dests[i].ctiport);
    }
    diagf("  CTIs:\n");
    for (i = 0; i < c->n_cti; ++i) {
        diagf("    %p\n", c->ctis[i]);
    }
    return 0;
}

int cs_ect_configure(cs_channel_t chandesc)
{
    unsigned int i;
    unsigned int channo;
    int is_local;
    struct cs_channel *c = (struct cs_channel *) chandesc;

    assert(c != NULL);

    if (c->n_src == 0) {
        return cs_report_error("no trigger sources in channel");
    }
    if (c->n_dst == 0) {
        return cs_report_error("no trigger destinations in channel");
    }

    /* Unlock all the CTIs directly involved */
    for (i = 0; i < c->n_cti; ++i) {
        _cs_unlock(DEV(c->ctis[i]));
    }

    is_local = cs_ect_is_local(chandesc);

    if (is_local) {
        struct cs_device *cti = DEV(c->sources[0].cti);
        unsigned int chans;

        assert(cti == DEV(c->dests[0].cti));
        /* Allocate a currently unused channel within the CTI */
        chans = cs_cti_unused_channels(DEVDESC(cti));
        if (chans == 0) {
            return cs_report_error("all channels are in use");
        }
        /* Find the lowest-numbered channel not used by this CTI.  Use elsewhere
           in the cross-trigger fabric doesn't matter as we will gate the channel
           off at this CTI. */
        channo = chans & (0U - chans);
        /* Gate off the channel, to make it local to this CTI */
        _cs_clear(cti, CS_CTIGATE, channo);
    } else {
        /* Channel request spans multiple CTIs and will need to use the global
           cross-trigger matrix.  We need to find a channel number that is not
           already in use as a global channel.  We must avoid using any channel
           number that is

           - in use by any CTI anywhere in the cross-trigger fabric and not gated

           - in use by any CTI involved in this request, even if gated

           We could look for channel numbers that are used in one CTI (other
           than gated ones) and gate them off here to allow their use globally,
           but instead we rely on that being done when the channels are first
           allocated as local channels - i.e. the single-CTI case we handle
           above.
           TBD: what about power-down? disabled CTIs?
        */
        struct cs_device *d;
        unsigned int chans = CTI_CHANNEL_MASK;

        for (i = 0; i < c->n_cti; ++i) {
            chans &= cs_cti_unused_channels(DEVDESC(c->ctis[i]));
        }
        if (chans == 0) {
            return
                cs_report_error("all channels are in use by these CTIs");
        }
        /* Scan all CTIs in the system */
        for (d = G.device_top; d != NULL; d = d->next) {
            if (d->type != DEV_CTI)
                continue;
            chans &= ~cs_cti_used_global_channels(DEVDESC(d));
        }
        if (chans == 0) {
            return cs_report_error("no channels available");
        }
        channo = chans & (0U - chans);
    }

    /* Program the requested sources and destinations */
    for (i = 0; i < c->n_src; ++i) {
        _cs_set(DEV(c->sources[i].cti), CS_CTIINEN(c->sources[i].ctiport),
                channo);
    }
    for (i = 0; i < c->n_dst; ++i) {
        _cs_set(DEV(c->dests[i].cti), CS_CTIOUTEN(c->dests[i].ctiport),
                channo);
    }
    for (i = 0; i < c->n_cti; ++i) {
        cs_cti_enable(DEVDESC(c->ctis[i]));
    }
    return 0;
}

int cs_ect_reset(void)
{
    int rc = 0;
    struct cs_device *d;
    for (d = G.device_top; d != NULL; d = d->next) {
        if (d->type != DEV_CTI)
            continue;
        rc = cs_cti_reset(DEVDESC(d));
        if (rc != 0)
            break;
    }
    return rc;
}

/* end of  cs_cti_ect.h */
