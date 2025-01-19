/*
  Coresight Access Library - API - programming and extraction of data from trace sinks

  Copyright (C) ARM Limited, 2014-2016. All rights reserved.

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
#include "cs_trace_sink.h"
#include "cs_topology.h"

/* ---------- Local functions ------------- */


/* ========== API functions ================ */
int cs_sink_is_enabled(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    assert(cs_device_has_class(dev, CS_DEVCLASS_SINK));
    if (d->type == DEV_ETB || d->type == DEV_ETF) {
        return _cs_isset(d, CS_ETB_CTRL, CS_ETB_CTRL_TraceCaptEn);
    } else {
        return 0;
    }
}

int cs_sink_enable(cs_device_t dev)
{
    int rc;
    struct cs_device *d = DEV(dev);
    assert(cs_device_has_class(dev, CS_DEVCLASS_SINK));

    _cs_unlock(d);
    if (d->type == DEV_ETB || d->type == DEV_ETF) {
        unsigned int flfmt;
        d->v.etb.currently_reading = 0;
        if (_cs_isset(d, CS_ETB_CTRL, CS_ETB_CTRL_TraceCaptEn)) {
            return 0;
        }
        /* "The RAM Write Pointer Register must be programmed before trace
           capture is enabled." */
        rc = cs_empty_trace_buffer(dev);
        if (rc != 0) {
            return rc;
        }
        /* Set up flushing and formatting controls.
           CS_ETB_FLFMT_CTRL_EnFTC: enable formatting into 16-byte frames,
           in case there are multiple trace sources.
           CS_ETB_FLFMT_CTRL_EnFCont: enable continuous formatting (ETB)
           or enable insertion of triggers (TMC)
        */
        flfmt = CS_ETB_FLFMT_CTRL_EnFTC | CS_ETB_FLFMT_CTRL_EnFCont;
        if (d->v.etb.is_tmc_device) {
            /* Stop on a Flush operation.  For a TMC ETB we don't want to go straight
               from Running to Disabled, instead we want to Stop the ETB first,
               then read the data, then disable for reprogramming. */
            flfmt |= CS_ETB_FLFMT_CTRL_StopFl;
        }
        _cs_set(d, CS_ETB_FLFMT_CTRL, flfmt);
        return _cs_write(d, CS_ETB_CTRL, CS_ETB_CTRL_TraceCaptEn);
    } else {
        /* The only other sinks would be trace ports, and currently this
           library doesn't support use cases which have an external
           trace capture device */
        return -1;
    }
}


int cs_sink_disable(cs_device_t dev)
{
    int rc;
    struct cs_device *d = DEV(dev);

    assert(cs_device_has_class(dev, CS_DEVCLASS_SINK));

    _cs_unlock(d);
    if (d->type == DEV_TPIU) {
        /* TPIU */
        _cs_set(d, CS_TPIU_FLFMT_CTRL, CS_TPIU_FLFMT_CTRL_StopFl);	/* Stop flush */
        /* When we request a flush via FOnMan, the FOnMan reads back as 1 while the
           flush is in progress, then goes to 0.  So don't try to read back. */
        _cs_set_wo(d, CS_TPIU_FLFMT_CTRL, CS_TPIU_FLFMT_CTRL_FOnMan);
        /* This is the indicator that the flush sequence has completed. */
        return _cs_wait(d, CS_TPIU_FLFMT_STATUS,
                        CS_TPIU_FLFMT_STATUS_FtStopped);
    } else if (d->type == DEV_SWO) {
        /* SWO */
        /* Stopping and flushing the SWO is not supported */
        return -1;
    } else if (d->type == DEV_ETB || d->type == DEV_ETF) {
        /* ETB or TMC */
        if (d->v.etb.is_tmc_device &&
            _cs_isset(d, CS_ETB_CTRL, CS_ETB_CTRL_TraceCaptEn)) {
            /* Manual Flush to go via Stopping to Stopped */
            _cs_set_wo(d, CS_ETB_FLFMT_CTRL, CS_ETB_FLFMT_CTRL_FOnMan);
            /* Now in Stopping */
            /* [TMC 2.2.2] "6. Wait until TMCReady is equal to one.  This indicates
               that the trace session is over." */
            _cs_wait(d, CS_ETB_STATUS, CS_TMC_STATUS_TMCReady);
            /* Now in Stopped. */
            /* The TMC is still enabled, i.e. TraceCaptEn is set.
               It will be disabled when we complete read-out. */
            return 0;
        }
        /* "Disable trace capture" by unsetting TraceCaptEn */
        rc = _cs_write(d, CS_ETB_CTRL, 0x0);
        if (rc)
            return rc;
        /* Wait for formatter to flush */
        rc = _cs_wait(d, CS_ETB_STATUS, CS_ETB_STATUS_FtEmpty);
        if (rc)
            return rc;
        /* After FtEmpty: "Formatter pipeline is empty. All data is stored to RAM." */
        /* "Capture is fully disabled, or complete, when FtStopped goes high" */
        rc = _cs_wait(d, CS_ETB_FLFMT_STATUS,
                      CS_ETB_FLFMT_STATUS_FtStopped);
        return rc;
    } else {
        return -1;
    }
}

int cs_disable_tpiu(void)
{
    int rc = 0;
    struct cs_device *d;

    for (d = G.device_top; d != NULL; d = d->next) {
        if (d->type == DEV_TPIU) {
            rc = cs_sink_disable(DEVDESC(d));
            if (rc != 0)
                break;
        }
        /* Note that we don't disable SWOs (because we can't) */
    }
    return rc;
}

int cs_get_buffer_size_bytes(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    assert(cs_device_has_class(dev, CS_DEVCLASS_BUFFER));
    return d->v.etb.buffer_size_bytes;
}

int cs_set_buffer_trigger_counter(cs_device_t dev, unsigned int bytes)
{
    struct cs_device *d = DEV(dev);
    assert(cs_device_has_class(dev, CS_DEVCLASS_SINK));

    assert((int)bytes <= cs_get_buffer_size_bytes(dev));
    _cs_unlock(d);
    /* For TMCs this is defined as a count of 32-bit words.  For CoreSight ETBs it's the same. */
    return _cs_write(d, CS_ETB_TRIGGER_COUNT,
                     bytes >> (d->v.etb.
                               is_tmc_device ? 2 : ETB_WIDTH_SCALE_SHIFT));
}

/*
  Check if the ETB buffer has wrapped around, by testing the Full flag.
  This flag is set on wraparound and reset when FtStopped changes from 1 to 0.
*/
int cs_buffer_has_wrapped(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    assert(cs_device_has_class(dev, CS_DEVCLASS_BUFFER));
    return _cs_isset(d, CS_ETB_STATUS, CS_ETB_STATUS_Full);
}


int cs_get_buffer_unread_bytes(cs_device_t dev)
{
    int unread;
    struct cs_device *d = DEV(dev);

    assert(cs_device_has_class(dev, CS_DEVCLASS_BUFFER));
    if (d->v.etb.finished_reading) {
        unread = 0;
    } else if (!d->v.etb.currently_reading && cs_buffer_has_wrapped(d)) {
        /* When the buffer is in a wrapped state, we will start the read by
           setting the read pointer equal to the write pointer, and be able
           to read the full buffer contents
        */
        unread = d->v.etb.buffer_size_bytes;
    } else {
        /* Either the trace never wrapped, or we're in the middle of reading */
        unsigned int const shift = d->v.etb.pointer_scale_shift;
        unsigned int rdptr = _cs_read(d, CS_ETB_RAM_RD_PTR);
        unsigned int wrptr = _cs_read(d, CS_ETB_RAM_WR_PTR);
        if (rdptr <= wrptr) {
            unread = (wrptr - rdptr) << shift;
        } else {
            unread = d->v.etb.buffer_size_bytes -
                (rdptr << shift) + (wrptr << shift);
        }
    }
    return unread;
}

int cs_get_trace_data(cs_device_t dev, void *buf, unsigned int size)
{
    struct cs_device *d = DEV(dev);
    unsigned int *op;
    int bytes_read = 0;
    int unread;
    uint32_t volatile *etb_read_reg;
    unsigned int to_read, words_left_to_read;

    assert(cs_device_has_class(dev, CS_DEVCLASS_BUFFER));

    /* The buffer into which the user wants to read trace, must be 8-byte aligned. */
    assert(((unsigned long) buf & 3) == 0);

    _cs_unlock(d);
    /* Put the buffer into a state where the read-pointer is the correct
       place to read from.  Note that the state when readpointer = writepointer
       is ambiguous - it could mean we have read all the data or it could mean
       we have a whole buffer to read.  We should only get in that state if
       we set the read-pointer to the write-pointer at the start of a read
       of wrapped data, and then fail to read any data.  So just don't clear
       the Full bit if we aren't going to read any data.
    */
    if (!d->v.etb.currently_reading && cs_buffer_has_wrapped(dev)) {
        /* When the buffer has wrapped, the best we can do is start reading
           from the last unwritten byte... */
        _cs_write(d, CS_ETB_RAM_RD_PTR, _cs_read(d, CS_ETB_RAM_WR_PTR));
        unread = cs_get_buffer_size_bytes(dev);
    } else {
        unread = cs_get_buffer_unread_bytes(dev);
        /* We now need to write the RAM read pointer in order to trigger a
           RAM access cycle and load the data into the RAM read register. */
        if (_cs_read(d, CS_ETB_RAM_RD_PTR) == 0) {
            _cs_write(d, CS_ETB_RAM_RD_PTR, 0);
        }
    }
    d->v.etb.currently_reading = 1;

    /* Read data into the user's buffer */
    op = (unsigned int *) buf;
    if (DTRACE(d)) {
        diagf
            ("!ctrl=%08X status=%08X flstatus=%08X readptr=%08X writeptr=%08X unread=%04X\n",
             _cs_read(d, CS_ETB_CTRL), _cs_read(d, CS_ETB_STATUS),
             _cs_read(d, CS_ETB_FLFMT_STATUS), _cs_read(d,
                                                        CS_ETB_RAM_RD_PTR),
             _cs_read(d, CS_ETB_RAM_WR_PTR), unread);
    }

    /* Work out a total amount to read in this call.
       It should be:
       - no more than the amount of unread data currently in the ETB
       - no more than the buffer size provided by the user
       - rounded down to a multiple of the ETB memory width (see note about TMC below)
       - (perhaps) rounded down to a multiple of CoreSight formatted frames
    */
    to_read = unread;
    if (to_read > size) {
        to_read = size;
    }
    /* Round down to ETB/TMC memory size */
    if (d->v.etb.is_tmc_device) {
        to_read &= ~((1U << d->v.etb.tmc.memory_width) - 1);
    } else {
        to_read &= ~3;		/* round down to 32-bit words */
    }

    words_left_to_read = to_read >> 2;

    /* For speed, we get the memory-mapped address of the RAM Read Data Register,
       and repeatedly read directly from that location. */
    /* [TMC] 3.3.3: "When the memory width given in the DEVID register is greater than
       32 bits, multiple reads to this register must be performed together to read a
       full memory width of data. For example, if the memory width is 128 bits,
       then reads from this register must be performed four at a time.
       When a full memory width of data has been read, the RAM Read Pointer is
       incremented to the next memory word." */

    /* As an optimization, to speed up the read loop below, we attempt to get the
       local address of the ETB's data transfer register. This might not be possible. */
    etb_read_reg = _cs_get_register_address(d, CS_ETB_RAM_DATA);
    if (0) {
        fprintf(stderr,
                "TraceCaptEn=%u TMCReady=%u Empty=%u CBUFLEVEL=0x%" PRIx32 "\n",
                _cs_isset(d, CS_ETB_CTRL, CS_ETB_CTRL_TraceCaptEn),
                _cs_isset(d, CS_ETB_STATUS, CS_TMC_STATUS_TMCReady),
                _cs_isset(d, CS_ETB_STATUS, CS_TMC_STATUS_Empty),
                _cs_read(d, CS_TMC_CBUFLEVEL));
    }
    while (words_left_to_read > 0) {
        unsigned int data = etb_read_reg ? *etb_read_reg : _cs_read(d, CS_ETB_RAM_DATA);
        if (0) {
            printf("read %08x, read ptr now %08x\n", data, _cs_read(d, CS_ETB_RAM_RD_PTR));
        }
        if (data != 0xFFFFFFFF) {
            *op++ = data;
        } else {
            /* "3.11.3... "A constant output of 1s corresponds to a synchronization
               output in the formatter protocol that is not applicable to the ETB,
               and so can be used to indicate a read error, when formatting is enabled."
               Our code at note #1 above fixes one case where we saw this; we now
               don't expect to ever see it.
            */
            if (DTRACE(d)) {
                diagf("  read all 1s (%08X): readptr=%08X\n", data,
                      _cs_read(d, CS_ETB_RAM_RD_PTR));
            }
            *op++ = data;     /* Write the 0xFFFFFFFF to the output buffer. */
        }
        /* Reading the RAM data register will have triggered a RAM access cycle
           so we don't need to write the RAM read pointer register again here. */
        --words_left_to_read;
    }
    bytes_read += to_read;
    unread -= to_read;
    if (unread == 0) {
        d->v.etb.finished_reading = 1;
        if (d->v.etb.is_tmc_device) {
            /* The TMC spec says that once we've read all the data in the buffer,
               subsequent reads will read 0xFFFFFFFF. */
            unsigned int checkff = *etb_read_reg;
            if (checkff != 0xFFFFFFFF) {
                diagf("  TMC ETB read 0x%08X, expected 0xFFFFFFFF\n",
                      checkff);
            }
            /* Now we can move from Stopped to Disabled. */
            _cs_clear(d, CS_ETB_CTRL, CS_ETB_CTRL_TraceCaptEn);
        }
    }
    return bytes_read;
}


/*
  Set the trace buffer to "ready to capture" state - with the write
  pointer at the start of the buffer, and not marked as wrapped.
  This could be done before the first capture, or after retrieving
  data from the buffer.
*/
int cs_empty_trace_buffer(cs_device_t dev)
{
    int rc;
    struct cs_device *d = DEV(dev);
    assert(cs_device_has_class(dev, CS_DEVCLASS_BUFFER));

    _cs_unlock(d);

    /* The buffer must not currently be capturing. */
    if (!d->v.etb.is_tmc_device) {
        assert(!_cs_isset(d, CS_ETB_CTRL, CS_ETB_CTRL_TraceCaptEn));
    } else {
        /* TMC might be in Stopped state - if so, disable it. */
        if (_cs_isset(d, CS_ETB_CTRL, CS_ETB_CTRL_TraceCaptEn)) {
            assert(_cs_isset(d, CS_ETB_STATUS, CS_TMC_STATUS_TMCReady));
            _cs_clear(d, CS_ETB_CTRL, CS_ETB_CTRL_TraceCaptEn);
        }
    }

    if (cs_buffer_has_wrapped(dev)) {
        /* There appears to be no direct way of resetting the Full (wrapped) flag.
           The only way to reset it is as a side-effect of enabling trace
           capture.  Even if we try to do that briefly, we risk wrapping
           again if the process is pre-empted at an inopportune time, so we
           may need to take more than one attempt. */
        unsigned int retries = 0;
        /* We've observed that when StopTrig is enabled, the action of briefly
           enabling trace doesn't result in the Full (wrapped) indicator being reset.
           So, temporarily disable StopTrig. */
        unsigned int flc = _cs_read(d, CS_ETB_FLFMT_CTRL);
        if (flc & (CS_ETB_FLFMT_CTRL_StopTrig | CS_ETB_FLFMT_CTRL_StopFl)) {
            _cs_write(d, CS_ETB_FLFMT_CTRL,
                      flc & ~(CS_ETB_FLFMT_CTRL_StopTrig |
                              CS_ETB_FLFMT_CTRL_StopFl));
        }
        do {
            ++retries;
            if (retries > 3) {
                unsigned int status = _cs_read(d, CS_ETB_STATUS);
                unsigned int flstat = _cs_read(d, CS_ETB_FLFMT_STATUS);
                return cs_report_device_error(d,
                                              "can't reset the wrapped flag, status=%08X, fl.status=%08X",
                                              status, flstat);
            }
            /* Set the write pointer to the start as we don't want to wrap again */
            _cs_write(d, CS_ETB_RAM_WR_PTR, 0x00000000);
            _cs_set(d, CS_ETB_CTRL, CS_ETB_CTRL_TraceCaptEn);
            /* We're now capturing trace, hopefully briefly. */
            _cs_clear(d, CS_ETB_CTRL, CS_ETB_CTRL_TraceCaptEn);
            /* We may have moved the write pointer a little bit.  We'd be very
               unlucky to have wrapped again, unless we were suspended while
               the trace was enabled. */
        } while (cs_buffer_has_wrapped(dev));
        if (flc & CS_ETB_FLFMT_CTRL_StopTrig) {
            _cs_write(d, CS_ETB_FLFMT_CTRL, flc);
        }
    }
    _cs_write(d, CS_ETB_RAM_WR_PTR, 0x00000000);
    /* We might as well program the read pointer here as an indicator that
       we aren't part-way through a buffer read.  But when we do read out,
       we need to write the read pointer again to trigger a RAM access. */
    rc = _cs_write(d, CS_ETB_RAM_RD_PTR, 0x00000000);
    assert(cs_get_buffer_unread_bytes(dev) == 0);
    /* Buffer is empty so we're not reading anything. */
    d->v.etb.finished_reading = 0;
    return rc;
}

int cs_clear_trace_buffer(cs_device_t dev, unsigned int data)
{
    int rc;
    unsigned int i;
    struct cs_device *d = DEV(dev);
    unsigned int size_words;

    assert(cs_device_has_class(dev, CS_DEVCLASS_BUFFER));
    _cs_unlock(d);
    rc = _cs_write(d, CS_ETB_RAM_WR_PTR, 0);
    if (rc != 0) {
        return rc;
    }
    size_words = d->v.etb.buffer_size_bytes >> 2;
    for (i = 0; i < size_words; ++i) {
        _cs_write(d, CS_ETB_RAM_WRITE_DATA, data);
    }
    /* The write-pointer should have wrapped */
    assert(_cs_read(d, CS_ETB_RAM_WR_PTR) == 0);
    /* Now reset the counters so that the buffer appears as empty. */
    return cs_empty_trace_buffer(dev);
}

/* This is a back door into ETB - not normally expected to be used */
int cs_insert_trace_data(cs_device_t dev, void const *buf,
                         unsigned int size)
{
    struct cs_device *d = DEV(dev);
    unsigned int const *ip = (unsigned int const *) buf;
    unsigned int optr, nptr;

    assert(cs_device_has_class(dev, CS_DEVCLASS_BUFFER));
    assert(((unsigned long) buf & 3) == 0);
    assert((size & 3) == 0);

    _cs_unlock(d);
    if (DTRACE(d)) {
        diagf("  ctrl=%08X status=%08X flstatus=%08X writeptr=%08X\n",
              _cs_read(d, CS_ETB_CTRL),
              _cs_read(d, CS_ETB_STATUS),
              _cs_read(d, CS_ETB_FLFMT_STATUS),
              _cs_read(d, CS_ETB_RAM_WR_PTR));
    }
    optr = _cs_read(d, CS_ETB_RAM_WR_PTR);
    while (size > 0) {
        unsigned int data = *ip++;
        _cs_write(d, CS_ETB_RAM_WRITE_DATA, data);
        size -= 4;
        /* As a diagnostic check, check that the write-pointer has incremented */
        if (0) {
            nptr = _cs_read(d, CS_ETB_RAM_WR_PTR);
            if (optr == nptr) {
                return cs_report_device_error(d,
                                              "failed to increment write-pointer");
            }
        }
    }
    return 0;
}

/* end of cs_trace_sink.c */
