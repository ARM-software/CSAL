/*
 * Protocol formats and constants for the devmemd daemon.
 */


/*
Copyright (C) ARM Ltd. 2021.  All rights reserved.

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

#ifndef __included_devmemd_h
#define __included_devmemd_h

#include <stdint.h>

typedef uint64_t physaddr_t;

/* Request packet, 24 bytes */
typedef struct {
    uint16_t seq;              /* Arbitrary number, copied to response */
    unsigned char pkt_len;     /* Packet length, 24 */
    unsigned char req;         /* Request type, see REQ_xxx */
    unsigned char size;        /* Read or write size */
    uint64_t phys_addr;        /* The physical address, naturally aligned */
    uint64_t data;             /* Data, for a write */
} devmemd_request_t;

#define DEVMEMD_REQ_NOP    0    /* do nothing */
#define DEVMEMD_REQ_READ   1    /* read 1/2/4/8 bytes from /dev/mem */
#define DEVMEMD_REQ_WRITE  2    /* write 1/2/4/8 bytes to /dev/mem */
#define DEVMEMD_REQ_CLOSE  3    /* close connection */
#define DEVMEMD_REQ_NOISE  4    /* increase verbosity level */
#define DEVMEMD_REQ_RESET  5    /* reset settings to default */
#define DEVMEMD_REQ_PAGE   6    /* get page size */
#define DEVMEMD_REQ_WPROT  7    /* write-protect from now on */

/* Response packet, 16 bytes */
typedef struct {
    uint16_t seq;              /* Number copied from request */
    unsigned char pkt_len;     /* Packet length, 16 */
    unsigned char status;      /* Status, see ERR_xxx */
    uint64_t data;             /* e.g. data read from /dev/mem */
} devmemd_response_t;

#define DEVMEMD_ERR_OK     0   /* no error */
#define DEVMEMD_ERR_MMAP   1   /* failed to mmap() /dev/mem */
#define DEVMEMD_ERR_ALIGN  2   /* physical address not aligned for data */
#define DEVMEMD_ERR_BADREQ 3   /* unknown request code */
#define DEVMEMD_ERR_BUS    4   /* bus error */
#define DEVMEMD_ERR_WPROT  5   /* write when daemon is in write-protect mode */

#endif /* included */

/* end of devmemd.h */
