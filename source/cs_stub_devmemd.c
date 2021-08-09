/*!
 * \file       cs_stub_devmemd.c
 * \brief      Stub API for remote access via devmemd
 *
 * \copyright  Copyright (C) ARM Limited, 2021. All rights reserved.
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

#ifdef USE_DEVMEMD

#include "cs_stub_devmemd.h"

#include "../devmemd/devmemd.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int devmemd_fd = -1;

static void devmemd_req(devmemd_request_t *req, devmemd_response_t *rsp)
{
    static int seq;
    int rc;
    devmemd_response_t lrsp;
    assert(req != NULL);
    if (!rsp) {
        rsp = &lrsp;
        memset(rsp, 0, sizeof *rsp);
    }
    req->seq = ++seq;
    req->pkt_len = sizeof *req;
    rc = send(devmemd_fd, req, sizeof *req, 0);
    rc = recv(devmemd_fd, rsp, sizeof *rsp, 0);
    if (rc != sizeof *rsp) {
        fprintf(stderr, "** csaccess: only %d bytes returned from devmemd\n", rc);
        exit(EXIT_FAILURE);
    }
    if (rsp->status != DEVMEMD_ERR_OK || rsp->seq != req->seq) {
        fprintf(stderr, "** csaccess: devmemd failed (req=%d, addr=0x%lx), rc=%d\n",
            req->req, req->phys_addr, rsp->status);
        exit(EXIT_FAILURE);
    }
}

void devmemd_verbose(int n)
{
    devmemd_request_t req;
    memset(&req, 0, sizeof req);
    req.req = DEVMEMD_REQ_NOISE;
    req.data = n;
    devmemd_req(&req, NULL);
}

static void devmemd_reset(void)
{
    devmemd_request_t req;
    memset(&req, 0, sizeof req);
    req.req = DEVMEMD_REQ_RESET;
    devmemd_req(&req, NULL);
}

unsigned long devmemd_pagesize(void)
{
    devmemd_request_t req;
    devmemd_response_t rsp;
    memset(&req, 0, sizeof req);
    req.req = DEVMEMD_REQ_PAGE;
    devmemd_req(&req, &rsp);
    return rsp.data;
}

void devmemd_init(void)
{
    int rc;
    struct addrinfo *ainfo;
    struct sockaddr_in remote;
    int port;
    char *devmemd = getenv("DEVMEMD");
    char *ix;
    if (!devmemd) {
        fprintf(stderr, "** csaccess: built with USE_DEVMEMD, but DEVMEMD environment variable not set\n");
        exit(EXIT_FAILURE);
    }
    ix = strchr(devmemd, ':');
    if (!ix) {
badaddr:
        fprintf(stderr, "** csaccess: DEVMEMD must be <addr>:<port>: %s\n", devmemd);
        exit(EXIT_FAILURE);
    }
    memset(&remote, 0, sizeof remote);
    port = atoi(ix+1);
    if (port <= 0 || port > 0xffff) {
        goto badaddr;
    }
    *ix = '\0';
    rc = getaddrinfo(devmemd, NULL, NULL, &ainfo);
    if (rc != 0) {
        fprintf(stderr, "** csaccess: '%s': %s\n", devmemd, gai_strerror(rc));
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in *rp = (struct sockaddr_in *)ainfo->ai_addr;
    fprintf(stderr, "** csaccess: opening connection to %s (%s) port %d\n",
        devmemd, inet_ntoa(rp->sin_addr), port);
    assert(rp->sin_family == AF_INET);
    rp->sin_port = htons(port);
    devmemd_fd = socket(ainfo->ai_family, ainfo->ai_socktype, 0);
    rc = connect(devmemd_fd, ainfo->ai_addr, sizeof(*ainfo->ai_addr));
    if (rc < 0) {
        fprintf(stderr, "** csaccess: can't connect to devmemd at %s: %s:%u\n",
            devmemd, inet_ntoa(rp->sin_addr), ntohs(rp->sin_port));
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(ainfo);
    devmemd_reset();
    //devmemd_verbose(3);
    //fprintf(stderr, "** csaccess: remote page size = 0x%lx\n", devmemd_pagesize());
}

void devmemd_close(void)
{
    if (devmemd_fd != -1) {
        close(devmemd_fd);
        devmemd_fd = -1;
    }
}


uint32_t devmemd_read32(unsigned long addr)
{
    devmemd_request_t req;
    devmemd_response_t rsp;
    memset(&req, 0, sizeof req);
    req.req = DEVMEMD_REQ_READ;
    req.size = 4;
    req.phys_addr = addr;
    devmemd_req(&req, &rsp);
#if 0 
    fprintf(stderr, "  0x%08lx (%u) -> 0x%lx\n", addr, req.size, rsp.data);
#endif
    return (uint32_t)rsp.data;
}

uint64_t devmemd_read64(unsigned long addr)
{
    devmemd_request_t req;
    devmemd_response_t rsp;
    memset(&req, 0, sizeof req);
    req.req = DEVMEMD_REQ_READ;
    req.size = 8;
    req.phys_addr = addr;
    devmemd_req(&req, &rsp);
    return rsp.data;
}

void devmemd_write32(unsigned long addr, uint32_t data)
{
    devmemd_request_t req;
    memset(&req, 0, sizeof req);
    req.req = DEVMEMD_REQ_WRITE;
    req.size = 4;
    req.phys_addr = addr;
    req.data = data;
    devmemd_req(&req, NULL);
}

void devmemd_write64(unsigned long addr, uint64_t data)
{
    devmemd_request_t req;
    memset(&req, 0, sizeof req);
    req.req = DEVMEMD_REQ_WRITE;
    req.size = 8;
    req.phys_addr = addr;
    req.data = data;
    devmemd_req(&req, NULL);
}

#endif

/* end of cs_stub_devmemd.c */
