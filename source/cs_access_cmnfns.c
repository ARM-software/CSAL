/*
  Coresight Access Library - common internal functions

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

/* Declare the global library information structure */
struct global G;

/* iterations for waiting for bits */
static int wait_iterations = 32;

#ifdef DIAG
/*
  Write a diagnostic message.

  A recognizable prefix can be added by prefixing the format string with "!".

  Caller is expected to supply newline.
*/

void _diagf(char const *s, ...)
{
    va_list args;
    va_start(args, s);
    if (s[0] == '!') {
	fprintf(stderr, "** ");
	++s;
    }
    vfprintf(stderr, s, args);
    va_end(args);
    fflush(stderr);
}
#endif				/* DIAG */

int cs_device_is_non_mmio(struct cs_device *d)
{
    return d->phys_addr == CS_NO_PHYS_ADDR;
}

int cs_device_is_funnel(struct cs_device *d)
{
    return d->n_in_ports > 1;
}

int cs_device_is_replicator(struct cs_device *d)
{
    return (d->devclass & CS_DEVCLASS_LINK) != 0 && d->n_out_ports > 1;
}

char const *cs_device_type_name(struct cs_device *d)
{
    switch (d->type) {
    case DEV_ETM:
	return "ETM";
    case DEV_ITM:
	return "ITM";
    case DEV_STM:
	return "STM";
    case DEV_FUNNEL:
	return "funnel";
    case DEV_REPLICATOR:
	return "replicator";
    case DEV_ETF:
	return "ETF";
    case DEV_ETB:
	return "ETB";
    case DEV_TPIU:
	return "TPIU";
    case DEV_SWO:
	return "SWO";
    case DEV_CTI:
	return "CTI";
    case DEV_CPU_DEBUG:
	return "CPU";
    case DEV_CPU_PMU:
	return "CPU-PMU";
    case DEV_TS:
	return "TS";
    default:
	return "?";
    }
}

int cs_report_error(char const *fmt, ...)
{
    va_list args;
    char err_mesg[100];
    ++G.n_api_errors;
    va_start(args, fmt);
    vsprintf(err_mesg, fmt, args);
    va_end(args);
#ifdef UNIX_KERNEL
    printk("** csaccess: %s\n", err_mesg);
#else
    fprintf(stderr, "** csaccess: ERROR: %s\n", err_mesg);
#endif
#ifndef UNIX_KERNEL
    fflush(stderr);
#endif
    return -1;
}

int cs_report_device_error(struct cs_device *d, char const *fmt, ...)
{
    va_list args;
    char err_mesg[100];
    ++d->n_api_errors;
    ++G.n_api_errors;
    va_start(args, fmt);
    vsprintf(err_mesg, fmt, args);
    va_end(args);
#ifdef UNIX_KERNEL
    printk("** csaccess(%" CS_PHYSFMT "): %s\n", d->phys_addr, err_mesg);
#else
    fprintf(stderr, "** csaccess(%" CS_PHYSFMT "): ERROR: %s\n",
	    d->phys_addr, err_mesg);
#endif
#ifndef UNIX_KERNEL
    fflush(stderr);
#endif
    return -1;
}

struct cs_device *cs_get_device_struct(cs_device_t dev)
{
    assert(dev != ERRDESC);
    return (struct cs_device *) (dev);
}

struct cs_device *cs_device_new(cs_physaddr_t addr,
				void volatile *local_addr)
{
    struct cs_device *d =
	(struct cs_device *) malloc(sizeof(struct cs_device));
    memset(d, 0, sizeof(struct cs_device));
    /* N.b. phys addr may be CS_NO_PHYS_ADDR, e.g. for non-programmable replicators */
    d->phys_addr = addr;
    d->local_addr = local_addr;
    d->affine_cpu = CS_CPU_UNKNOWN;
    d->power_domain = G.power_domain_default;
#ifdef DIAG
    d->diag_tracing = G.diag_tracing_default;
#endif				/* DIAG */
    d->next = G.device_top;
    G.device_top = d;
    ++G.n_devices;
    return d;
}


unsigned int volatile *_cs_get_register_address(struct cs_device *d,
						unsigned int off)
{
    assert(d->local_addr != NULL);
    assert((off & 3) == 0);	/* For 64-bit registers this check should be stronger */
    assert(off < 4096);
    return (unsigned int volatile *) (d->local_addr + off);
}


unsigned int _cs_read(struct cs_device *d, unsigned int off)
{
    assert(d->local_addr != NULL);
    assert((off & 3) == 0);
    assert(off < 4096);
    return *(unsigned int volatile const *) (d->local_addr + off);
}

unsigned long long _cs_read64(struct cs_device *d, unsigned int off)
{
    assert(d->local_addr != NULL);
    assert((off & 7) == 0);
    assert(off < 4096);
    return *(unsigned long long volatile const *) (d->local_addr + off);
}


/*
  Low-level write, with no read-back.

  Example uses:
  - as part of the implementation of checking writes
  - writing key to lock-registers when locked
  - S/W stimulus ports (usable when device locked)
*/
int _cs_write_wo(struct cs_device *d, unsigned int off, unsigned int data)
{
    assert(d->local_addr != NULL);
    assert((off & 3) == 0);
    assert(off < 4096);
    *(unsigned int volatile *) (d->local_addr + off) = data;
    return 0;
}

int _cs_write64_wo(struct cs_device *d, unsigned int off,
		   unsigned long long data)
{
    assert(d->local_addr != NULL);
    assert((off & 7) == 0);
    assert(off < 4096);
    *(unsigned long long volatile *) (d->local_addr + off) = data;
    return 0;
}

int _cs_write_traced(struct cs_device *d, unsigned int off,
		     unsigned int data, char const *oname)
{
    unsigned int ndata;
    if (DTRACE(d)) {
	diagf("!%" CS_PHYSFMT ": write %03X (%s) = %08X\n",
	      d->phys_addr, off, oname, data);
    }
    if (DCHECK(d)) {
	if (off != CS_LAR && !d->is_unlocked) {
	    diagf("!%" CS_PHYSFMT ": write to %03X (%s) when locked\n",
		  d->phys_addr, off, oname);
	}
    }
    _cs_write_wo(d, off, data);
    if (DCHECK(d)) {
	/* Read the data back */
	ndata = *(unsigned int volatile *) (d->local_addr + off);
	if (ndata != data) {
	    diagf("!%" CS_PHYSFMT ": write %03X (%s) = %08X now %08X\n",
		  d->phys_addr, off, oname, data, ndata);
	}
    }
#if defined(__arm__) || defined(__aarch64__)
    __asm__ __volatile__("dmb sy");
#endif
    return 0;
}

int _cs_write64_traced(struct cs_device *d, unsigned int off,
		       unsigned long long data, char const *oname)
{
    unsigned long long ndata;
    if (DTRACE(d)) {
	diagf("!%" CS_PHYSFMT ": write %03X (%s) = %016llX\n",
	      d->phys_addr, off, oname, data);
    }
    if (DCHECK(d)) {
	if (off != CS_LAR && !d->is_unlocked) {
	    diagf("!%" CS_PHYSFMT ": write to %03X (%s) when locked\n",
		  d->phys_addr, off, oname);
	}
    }
    _cs_write64_wo(d, off, data);
    if (DCHECK(d)) {
	/* Read the data back */
	ndata = *(unsigned long long volatile *) (d->local_addr + off);
	if (ndata != data) {
	    diagf("!%" CS_PHYSFMT
		  ": write %03X (%s) = %016llX now %016llX\n",
		  d->phys_addr, off, oname, data, ndata);
	}
    }
#if defined(__arm__) || defined(__aarch64__)
    __asm__ __volatile__("dmb sy");
#endif
    return 0;
}

int _cs_set_mask(struct cs_device *d, unsigned int off,
		 unsigned int mask, unsigned int data)
{
    unsigned int nword;
    unsigned int const word = _cs_read(d, off);
    /* Check caller is not trying to set any bits outside their mask */
    assert((data & ~mask) == 0);
    nword = (word & ~mask) | data;
    if (G.force_writes || nword != word) {
	return _cs_write(d, off, nword);
    } else {
	if (DTRACE(d)) {
	    diagf("!%" CS_PHYSFMT
		  ": bit set %03X.%08X := %08X suppressed\n", d->phys_addr,
		  off, mask, data);
	}
	return 0;		/* No change needed */
    }
}

int _cs_write_mask(struct cs_device *d, unsigned int off,
		   unsigned int mask, unsigned int data)
{
    unsigned int nword;
    unsigned int const word = _cs_read(d, off);
    nword = (word & ~mask) | (data & mask);
    return _cs_write(d, off, nword);
}

int _cs_set_bit(struct cs_device *d, unsigned int off, unsigned int mask,
		int value)
{
    return _cs_set_mask(d, off, mask, value ? mask : 0);
}

int _cs_set(struct cs_device *d, unsigned int off, unsigned int bits)
{
    return _cs_set_mask(d, off, bits, bits);
}

int _cs_set_wo(struct cs_device *d, unsigned int off, unsigned int bits)
{
    return _cs_write_wo(d, off, (_cs_read(d, off) | bits));
}

int _cs_clear(struct cs_device *d, unsigned int off, unsigned int bits)
{
    return _cs_set_mask(d, off, bits, 0);
}

int _cs_isset(struct cs_device *d, unsigned int off, unsigned int bits)
{
    return (_cs_read(d, off) & bits) == bits;
}

int _cs_wait(struct cs_device *d, unsigned int off, unsigned int bit)
{
    int i;
    for (i = 0; i < wait_iterations; ++i) {
	if (_cs_isset(d, off, bit)) {
	    if (DTRACE(d)) {
		diagf("!%" CS_PHYSFMT
		      ": bit %03X.%08X set after %d iterations\n",
		      d->phys_addr, off, bit, i);
	    }
	    return 0;
	}
    }
    return cs_report_device_error(d, "bit %03X.%08X did not set",
				  off, bit);
}

int _cs_waitnot(struct cs_device *d, unsigned int off, unsigned int bit)
{
    int i;
    for (i = 0; i < wait_iterations; ++i) {
	if (!_cs_isset(d, off, bit)) {
	    if (DTRACE(d)) {
		diagf("!%" CS_PHYSFMT
		      ": bit %03X.%08X clear after %d iterations\n",
		      d->phys_addr, off, bit, i);
	    }
	    return 0;
	}
    }
    return cs_report_device_error(d, "bit %03X.%08X did not clear",
				  off, bit);
}

void _cs_set_wait_iterations(int iterations)
{
    wait_iterations = iterations;
}

int _cs_waitbits(struct cs_device *d, unsigned int off, unsigned int bits,
		 cs_reg_waitbits_op_t operation, unsigned int pattern,
		 unsigned int *p_last_val)
{
    unsigned int regval = 0;
    int ret = -1, i;

    static char *err_msgs[] = {
	"waitbits(CS_REG_WAITBITS_ALL_1): all bits %03X.%08X failed to be set\n",
	"waitbits(CS_REG_WAITBITS_ANY_1): none of bits %03X.%08X set\n",
	"waitbits(CS_REG_WAITBITS_ALL_0): all bits %03X.%08X failed to clear\n",
	"waitbits(CS_REG_WAITBITS_ANY_0): none of bits %03X.%08X cleared\n",
	"waitbits(CS_REG_WAITBITS_PTTRN): bits %03X.%08X failed to match pattern %08X\n"
    };

    for (i = 0; i < wait_iterations; ++i) {
	regval = _cs_read(d, off);
	switch (operation) {
	case CS_REG_WAITBITS_ALL_1:
	    if ((regval & bits) == bits) {
		if (DTRACE(d)) {
		    diagf("!%" CS_PHYSFMT
			  ": bits %03X.%08X set after %d iterations\n",
			  d->phys_addr, off, bits, i);
		}
		ret = 0;
	    }
	    break;

	case CS_REG_WAITBITS_ANY_1:
	    /* any bits set */
	    if ((regval & bits) != 0) {
		if (DTRACE(d)) {
		    diagf("!%" CS_PHYSFMT
			  ": bits %03X.%08X any set after %d iterations\n",
			  d->phys_addr, off, bits, i);
		}
		ret = 0;
	    }
	    break;

	case CS_REG_WAITBITS_ALL_0:
	    /* all bits clear */
	    if ((regval & bits) == 0) {
		if (DTRACE(d)) {
		    diagf("!%" CS_PHYSFMT
			  ": bits %03X.%08X clear after %d iterations\n",
			  d->phys_addr, off, bits, i);
		}
		ret = 0;
	    }
	    break;

	case CS_REG_WAITBITS_ANY_0:
	    /* any bits clear */
	    if ((regval & bits) != bits) {
		if (DTRACE(d)) {
		    diagf("!%" CS_PHYSFMT
			  ": bits %03X.%08X any clear after %d iterations\n",
			  d->phys_addr, off, bits, i);
		}
		ret = 0;
		break;
	    }

	case CS_REG_WAITBITS_PTTRN:
	    /* any bits clear */
	    if ((regval & bits) == (pattern & bits)) {
		if (DTRACE(d)) {
		    diagf("!%" CS_PHYSFMT
			  ": bits %03X.%08X matched pattern %08X after %d iterations\n",
			  d->phys_addr, off, bits, pattern, i);
		}
		ret = 0;
		break;
	    }
	}

	if (ret == 0)
	    break;

    }

    /* return last value if required */
    if (p_last_val)
	*p_last_val = regval;

    /* if we didn't find a match need to report this */
    if (ret != 0) {
	if (operation == CS_REG_WAITBITS_PTTRN)
	    cs_report_device_error(d, err_msgs[operation - 1], off, bits,
				   pattern);
	else
	    cs_report_device_error(d, err_msgs[operation - 1], off, bits);
    }
    return ret;
}

int _cs_claim(struct cs_device *d, unsigned int bit)
{
    return _cs_write_wo(d, CS_CLAIMSET, bit);
}

int _cs_unclaim(struct cs_device *d, unsigned int bit)
{
    return _cs_write_wo(d, CS_CLAIMCLR, bit);
}

/*
  To read the current settings of the claim bits, use the CLAIMCLR register.
  (Reading the CLAIMSET register indicates which claim bits are implemented.)
*/
int _cs_isclaimed(struct cs_device *d, unsigned int bit)
{
    return _cs_isset(d, CS_CLAIMCLR, bit);
}


/* Return true if a device is unlocked (where the lock is implemented) */
int _cs_isunlocked(struct cs_device *d)
{
    return (_cs_read(d, CS_LSR) & 3) == 1;
}


void _cs_unlock(struct cs_device *d)
{
    if (!d->is_unlocked) {
	_cs_write_wo(d, CS_LAR, CS_KEY);
	d->is_unlocked = 1;
    }
    if (DCHECK(d)) {
	unsigned int lsr = _cs_read(d, CS_LSR);
	if ((lsr & 3) == 3) {
	    /* Implemented (bit 0) and still locked (bit 1) */
	    diagf("!%" CS_PHYSFMT ": after unlock, LSR=%08X\n",
		  d->phys_addr, lsr);
	}
    }
}


void _cs_lock(struct cs_device *d)
{
    if (d->is_unlocked) {
	_cs_write_wo(d, CS_LAR, 0);
	d->is_unlocked = 0;
    }
    if (DCHECK(d)) {
	unsigned int lsr = _cs_read(d, CS_LSR);
	if ((lsr & 3) == 1) {
	    /* Implemented (bit 0) but not locked (bit 1) */
	    diagf("!%" CS_PHYSFMT ": after lock, LSR=%08X\n",
		  d->phys_addr, lsr);
	}
    }
}


/*
  Map a region (generally 4K) of physical memory.
  Return NULL if unsuccessful.
*/
void *io_map(cs_physaddr_t addr, unsigned int size, int writable)
{
    void *localv;
    cs_physaddr_t addr_to_map = addr;	/* may be rounded down to phys page size */
    assert(size > 0);
    assert((addr % 4096) == 0);
#ifdef UNIX_USERSPACE
    {
	unsigned int pagesize = sysconf(_SC_PAGESIZE);
	if (size < pagesize) {
	    size = pagesize;
	}
	if ((addr % pagesize) != 0) {
	    addr_to_map -= (addr % pagesize);
	}
    }
    localv =
	mmap(0, size, (writable ? (PROT_READ | PROT_WRITE) : PROT_READ),
	     MAP_SHARED, G.mem_fd, addr_to_map);
    if (localv == MAP_FAILED) {
	return NULL;
    }
    localv = (unsigned char *) localv + (addr - addr_to_map);
#elif defined(UNIX_KERNEL)
    localv = ioremap(addr, size);
#else
    localv = (void *) addr_to_map;
#endif
    return localv;
}


void io_unmap(void *addr, unsigned int size)
{
#ifdef UNIX_USERSPACE

    (void) munmap(addr, size);
#elif defined(UNIX_KERNEL)
    iounmap(addr);
#else
    /* do nothing */
#endif
}

/* end of cs_access_cmnfns.c */
