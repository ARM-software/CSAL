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
#include "cs_reg_access.h"


unsigned int cs_device_read(cs_device_t dev, unsigned int off)
{
    return _cs_read(DEV(dev), off);
}

int cs_device_write(cs_device_t dev, unsigned int off, unsigned int data)
{
    /* Unlock the device if it is locked */
    _cs_unlock(DEV(dev));
    return _cs_write(DEV(dev), off, data);
}

int cs_device_write_only(cs_device_t dev, unsigned int off,
                         unsigned int data)
{
    /* Unlock the device if it is locked */
    _cs_unlock(DEV(dev));
    return _cs_write_wo(DEV(dev), off, data);
}

int cs_device_write_masked(cs_device_t dev, unsigned int offset,
                           unsigned int data, unsigned int bitmask)
{
/* Unlock the device if it is locked */
    _cs_unlock(DEV(dev));
    return _cs_write_mask(DEV(dev), offset, bitmask, data);
}


int cs_device_set(cs_device_t dev, unsigned int off, unsigned int bits)
{
    _cs_unlock(DEV(dev));
    return _cs_set(DEV(dev), off, bits);
}

int cs_device_clear(cs_device_t dev, unsigned int off, unsigned int bits)
{
    _cs_unlock(DEV(dev));
    return _cs_clear(DEV(dev), off, bits);
}

int cs_device_wait(cs_device_t dev, unsigned int offset,
                   unsigned int bit_mask, cs_reg_waitbits_op_t operation,
                   unsigned int pattern, unsigned int *p_last_val)
{
    assert((operation >= CS_REG_WAITBITS_ALL_1)
           && (operation < CS_REG_WAITBITS_END));
    _cs_unlock(DEV(dev));

    return _cs_waitbits(DEV(dev), offset, bit_mask, operation, pattern,
                        p_last_val);
}

void cs_device_set_wait_repeats(int n_wait_repeat_count)
{
    assert(n_wait_repeat_count >= 1);
    _cs_set_wait_iterations(n_wait_repeat_count);
}

cs_physaddr_t cs_device_address(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    return d->phys_addr;
}

unsigned short cs_device_part_number(cs_device_t dev)
{
    struct cs_device *d = DEV(dev);
    return d->part_number;
}

/* end of cs_reg_access.c */
