/*
 * Simple daemon to listen on a socket and forward read/write
 * requests to /dev/mem. This provides a way for a remote tool
 * to access physical memory on this device.
 *
 * This is designed for diagnostic use only, and consequently
 * is single-threaded and pretty basic, e.g. no endian swapping.
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

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>

#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "devmemd.h"

static int verbosity;


struct page {
    struct page *next;         /* Next page in bucket */
    physaddr_t phys_addr;      /* Base physical address of page */
    unsigned char *virt_addr;  /* Base virtual address of our mapping */
};

/* Single linked list (currently) of page mappings */
static struct page *pages;

/* File handle opened on /dev/mem */
static int devmem_fd;

/* Daemon is in read-only mode */
static int o_readonly = 0;

/* New mappings on demand are enabled */
static int mmap_enabled = 1;

/* Memory limits */
static physaddr_t lomem = 0x0000;
static physaddr_t himem = (physaddr_t)(-1);

/* mmap flags - device access requires MAP_SHARED */
static int mmap_flags = MAP_SHARED;

/* System page size (e.g. 4K, 64K) - discovered at startup */
static unsigned long page_size;

/* Jump buffer for recovering from SIGBUF */
static sigjmp_buf bussig;


static int is_aligned(physaddr_t addr, unsigned int size)
{
    return (addr & (size-1)) == 0;
}


/*
 * Get the page structure for a physical address.
 * Always returns non-NULL.
 */
static struct page *devmem_page(physaddr_t addr)
{
    physaddr_t const page_base = (addr & -page_size);
    struct page **page_head = &pages;
    struct page *page;
    assert(is_aligned(page_base, page_size));
    for (page = *page_head; page != NULL; page = page->next) {
        if (page->phys_addr == page_base) {
            break;
        }
    }
    if (!page) {
        page = (struct page *)malloc(sizeof *page);
        page->phys_addr = page_base;
        page->virt_addr = NULL;
        page->next = *page_head;
        *page_head = page;
    }
    return page;
}


/*
 * mmap() a page, if not already mapped.
 */
static void *devmem_map_page(struct page *p)
{
    if (!p->virt_addr) {
        unsigned int mmap_prot = (o_readonly ? PROT_READ : (PROT_READ|PROT_WRITE));
        void *res = mmap(NULL, page_size, mmap_prot, mmap_flags, devmem_fd, p->phys_addr);
        if (res == MAP_FAILED) {
            int save = errno;
            perror("mmap");
            fprintf(stderr, "failed to map 0x%lx\n", p->phys_addr);
            errno = save;
            return NULL;
        }
        p->virt_addr = (unsigned char *)res;
        if (verbosity >= 1) {
            printf("devmemd: mapped 0x%lx at %p size 0x%lx\n", p->phys_addr, p->virt_addr, page_size);
        }
    }
    return p->virt_addr;
}


/*
 * Get a virtual address for a physical address
 */
static unsigned char *devmem_loc(physaddr_t addr)
{
    struct page *p = devmem_page(addr);
    if (!p->virt_addr) {
        if (!mmap_enabled) {
            return NULL;
        }
        if (addr < lomem || addr >= himem) {
            return NULL;
        }
        if (!devmem_map_page(p)) {
            return NULL;
        }
    }
    /* VA result is the base VA of the mapping plus the offset between the
       requested physical address and the base physical address of the page. */
    return p->virt_addr + (addr - p->phys_addr);
}


static int devmem_read(physaddr_t addr, uint64_t *data, unsigned int size)
{
    void *p = devmem_loc(addr);
    if (!p) {
        *data = (uint64_t)errno;
        return DEVMEMD_ERR_MMAP;
    }
    if (!is_aligned(addr, size)) {
        return DEVMEMD_ERR_ALIGN;
    }
    if (sigsetjmp(bussig, 1)) {
        printf("devmemd: bus error: %u-byte read from 0x%lx\n", size, addr);
        *data = 0xCDCDCDCDCDCDCDCDUL;
        return DEVMEMD_ERR_BUS;
    } 
    switch (size) {
    case 1:
        *data = *(uint8_t *)p;
        break;
    case 2:
        *data = *(uint16_t *)p;
        break;
    case 4:
        *data = *(uint32_t *)p;
        break;
    case 8:
        *data = *(uint64_t *)p;
        break;
    default:
        assert(0);
    }
    if (verbosity >= 2) {
        printf("devmemd: 0x%lx -> %p -[%u]> 0x%" PRIx64 "\n", addr, p, size, *data);
    }
    return DEVMEMD_ERR_OK;
}


static int devmem_write(physaddr_t addr, uint64_t data, unsigned int size)
{
    void *p = devmem_loc(addr);
    if (!p) {
        return DEVMEMD_ERR_MMAP;
    }
    if (!is_aligned(addr, size)) {
        return DEVMEMD_ERR_ALIGN;
    }
    if (sigsetjmp(bussig, 1)) {
        printf("devmemd: bus error: %u-byte write to 0x%lx\n", size, addr);
        return DEVMEMD_ERR_BUS;
    }
    if (verbosity >= 2) {
        printf("devmemd: 0x%lx -> %p <[%u]- 0x%" PRIx64 "\n", addr, p, size, data);
    }
    switch (size) {
    case 1:
        *(uint8_t volatile *)p = (uint8_t)data;
        break;
    case 2:
        *(uint16_t volatile *)p = (uint16_t)data;
        break;
    case 4:
        *(uint32_t volatile *)p = (uint32_t)data;
        break;
    case 8:
        *(uint64_t volatile *)p = (uint64_t)data;
        break;
    default:
        assert(0);
    }
    return DEVMEMD_ERR_OK;
}


static void sigbus_handler(int sig)
{
    signal(sig, sigbus_handler);
    siglongjmp(bussig, 1);
}


/* Options for getopt_long() */
static struct option const long_options[] = {
    { "help", no_argument, NULL, 'h' },
    { "himem", required_argument, NULL, 'H' },
    { "lomem", required_argument, NULL, 'L' },
    { "map", required_argument, NULL, 'm' },
    { "nomap", no_argument, NULL, 'n' },
    { "port", required_argument, NULL, 'p' },
    { "private", no_argument, NULL, 'P' },
    { "readonly", no_argument, NULL, 'r' },
    { "verbose", no_argument, NULL, 'v' },
    { 0, 0, 0, 0 }
};


static void help(void)
{
    printf(
"Usage: devmemd [OPTION]...\n"
"  --himem=<addr>   set upper bound for physical memory\n"
"  --lomem=<addr>   set lower bound for physical memory\n"
"  --map=<addr>     pre-map this physical address\n"
"  --nomap          no on-demand mappings\n"
"  --port=<n>       listen on TCP port <n> (default is random)\n"
"  --private        use MAP_PRIVATE mapping (won't update devices)\n"
"  --readonly       reject write requests\n"
"  --verbose        increase verbosity level\n"
    );
}


int main(int argc, char **argv)
{
    char const *devmem_fn = "/dev/mem";
    int rc;
    int slis, schn;
    int o_port = 0;    /* by default, system will choose */
    struct sockaddr_in local, remote;
    socklen_t alen = sizeof(struct sockaddr_in);
    assert(sizeof(devmemd_request_t) == 24);
    assert(sizeof(devmemd_response_t) == 16);
    page_size = sysconf(_SC_PAGE_SIZE);
    signal(SIGBUS, sigbus_handler);
    while (1) {
        int option_index = 0;
        int c = getopt_long(argc, argv, "v", long_options, &option_index);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 0:
            break;
        case 'h':
            help();
            exit(EXIT_SUCCESS);
        case 'H':
            sscanf(optarg, "%lx", &himem);
            break;
        case 'L':
            sscanf(optarg, "%lx", &lomem);
            break;
        case 'm':
            {
                physaddr_t phys_addr;
                sscanf(optarg, "%lx", &phys_addr);
                printf("devmemd: will pre-map 0x%lx...\n", phys_addr);
                /* Creating the page record will cause it to be mmap'ed later */
                (void)devmem_page(phys_addr);
            }
            break;
        case 'n':
            mmap_enabled = 0;
            break;
        case 'p':
            o_port = atoi(optarg);
            if (o_port >= 0x10000) {
                fprintf(stderr, "devmemd: port number out of range\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'P':
            mmap_flags = MAP_PRIVATE;
            break;
        case 'r':
            o_readonly = 1;
            break;
        case 'v':
            ++verbosity;
            break;
        case '?':
            /* getopt_long has already printed "unrecognized option" */
            exit(EXIT_FAILURE);
        default:
            assert(0);
        }
    }   
    if (1) {
        devmem_fd = open(devmem_fn, O_RDWR|O_SYNC);
        if (devmem_fd < 0) {
            /* Likely either permission denied, or /dev/mem not provided */
            perror(devmem_fn);
            return EXIT_FAILURE;
        }
    }
    printf("devmemd: opened fd=%d on %s, page size 0x%lx, 0x%lx..0x%lx\n",
        devmem_fd, devmem_fn, page_size, lomem, himem);
    /* Map any preload pages */
    {
        struct page *p;
        for (p = pages; p != NULL; p = p->next) {
            printf("devmemd: pre-mapping 0x%lx\n", p->phys_addr);
            if (!devmem_map_page(p)) {
                exit(EXIT_FAILURE);
            }
        }
    }
    /* Now listen on a network socket */
    slis = socket(AF_INET, SOCK_STREAM, 0);
    if (slis < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }
    memset(&local, 0, sizeof local);
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(o_port);
    rc = bind(slis, (struct sockaddr const *)&local, alen);
    if (rc < 0) {
        perror("bind");
        return EXIT_FAILURE;
    }
    rc = listen(slis, 1);
    if (rc < 0) {
        perror("listen");
        return EXIT_FAILURE;
    }
    rc = getsockname(slis, (struct sockaddr *)&local, &alen);
    if (rc < 0) {
        perror("getsockname");
        return EXIT_FAILURE;
    }
listen_for_new_connection:
    printf("devmemd: listening on port %d\n", ntohs(local.sin_port));
    schn = accept(slis, (struct sockaddr *)&remote, &alen);
    if (rc < 0) {
        perror("accept");
        return EXIT_FAILURE;
    }
    printf("devmemd: accepted fd=%d from %s:%u\n",
        schn, inet_ntoa(remote.sin_addr), (unsigned int)ntohs(remote.sin_port));
    for (;;) {
        devmemd_request_t req;
        devmemd_response_t rsp;
        int n = recv(schn, &req, sizeof req, 0);
        if (n == 0) {
            /* Remote end has closed the connection */
            break;
        }
        if (n < 0) {
            perror("recv");
            break;
        }
        if (n != sizeof req) {
            printf("devmemd: received %d bytes, req=%u\n", n, req.req);
        }
        memset(&rsp, 0, sizeof rsp);
        rsp.pkt_len = sizeof rsp;
        rsp.status = DEVMEMD_ERR_OK;
        rsp.seq = req.seq;
        switch (req.req) {
        case DEVMEMD_REQ_NOP:
            break;
        case DEVMEMD_REQ_READ:
            rsp.status = devmem_read(req.phys_addr, &rsp.data, req.size);
            break;
        case DEVMEMD_REQ_WRITE:
            if (!o_readonly) {
                rsp.status = devmem_write(req.phys_addr, req.data, req.size);
                if (rsp.status == DEVMEMD_ERR_MMAP) {
                    rsp.data = (uint64_t)errno;
                }
            } else {
                rsp.status = DEVMEMD_ERR_WPROT;
            }
            break;
        case DEVMEMD_REQ_CLOSE:
            /* response as for NOP, but then break out of the loop */
            break;
        case DEVMEMD_REQ_NOISE:
            ++verbosity;
            break;
        case DEVMEMD_REQ_RESET:
            verbosity = 0;
            break;
        case DEVMEMD_REQ_PAGE:
            rsp.data = page_size;
            break;
        case DEVMEMD_REQ_WPROT:
            o_readonly = 1;
            break;
        case DEVMEMD_REQ_USER+0:
            /* daemon can be extended here */
        default:
            rsp.status = DEVMEMD_ERR_BADREQ;
            break;
        }
        n = send(schn, &rsp, sizeof rsp, 0);
        if (req.req == DEVMEMD_REQ_CLOSE) {
            /* we've sent the final response, now exit and close the socket */
            break;
        }
    }
    printf("devmemd: closing fd=%d\n", schn);
    close(schn);
    goto listen_for_new_connection;
    return EXIT_SUCCESS;
}

/* end of devmemd.c */
