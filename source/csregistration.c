/*
  CoreSight board registration
  Provides an abstract interface to registering boards with the library 

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

#define _GNU_SOURCE

#include "csaccess.h"
#include "csregistration.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
  This has the CPU type identifier for each core, indexed by Linux core number.
*/
unsigned int cpu_id[LIB_MAX_CPU_DEVICES];

int registration_verbose = 1;

#ifndef BAREMETAL
static const struct board *do_probe_board(const struct board *board_list)
{
    const struct board *board = NULL;
    FILE *fl = fopen("/proc/cpuinfo", "r");
    char *line = NULL;
    size_t size = 0;
    ssize_t len;
    int cpu_number = -1;

    if (!fl) {
        if (registration_verbose)
            printf
                ("CSREG: Failed to open /proc/cpuinfo - cannot detect the board\n");
        return NULL;
    }

    while ((len = getline(&line, &size, fl)) >= 0) {
        if (strncmp(line, "Hardware\t: ", 11) == 0) {
            const struct board *b;
            unsigned int i;
            line[len - 1] = '\0';
            for (i = 1; i < len; ++i) {
                if (line[i] == '(') {
                    /* Convert "Myboard (test)" into "Myboard" etc. */
                    line[i - 1] = '\0';
                    break;
                }
            }
            for (b = board_list; b->do_registration; b++) {
                if (strcmp(line + 11, b->hardware) == 0) {
                    if (registration_verbose >= 2)
                        printf("CSREG: Detected '%s' board\n",
                               b->hardware);
                    board = b;
                    break;
                }
            }
            if (!board) {
                if (registration_verbose)
                    printf("CSREG: Board '%s' not known\n", line + 11);
            }
        } else if (strncmp(line, "processor\t: ", 12) == 0) {
            cpu_number = -1;
            sscanf(line + 12, "%d", &cpu_number);
        } else if (strncmp(line, "CPU part\t: ", 11) == 0) {
            unsigned int id;
            sscanf(line + 11, "%x", &id);
            if (cpu_number >= 0 && cpu_number < LIB_MAX_CPU_DEVICES) {
                cpu_id[cpu_number] = id;
            }
        }
    }

    free(line);
    fclose(fl);

    return board;
}
#endif

static int do_registration(const struct board *board,
                           struct cs_devices_t *devices)
{
    /* clear the devices structure */
    memset(devices, 0, sizeof(struct cs_devices_t));

    if (board->do_registration(devices) != 0) {
        if (registration_verbose)
            printf("CSREG: Failed to register board '%s'\n",
                   board->hardware);
        return -1;
    }

    /* No more registrations */
    if (cs_registration_complete() != 0) {
        if (registration_verbose)
            printf
                ("CSREG: Registration problems on cs_registration_complete()\n");
        return -1;
    }
    if (cs_error_count() > 0) {
        if (registration_verbose)
            printf("CSREG: Errors recorded during registration\n");
        return -1;
    }
    if (registration_verbose)
        printf("CSREG: Registration complete.\n");
    return 0;
}

static int initilise_board(const struct board **board,
                           struct cs_devices_t *devices)
{
    if (cs_init() < 0) {
        if (registration_verbose)
            printf("CSREG: Failed cs_init()\n");
        return -1;
    }

    if (do_registration(*board, devices) < 0) {
        if (registration_verbose)
            printf("CSREG: Registration failed in setup_board()\n");
        return -1;
    }
    return 0;
}

int setup_board(const struct board **board, struct cs_devices_t *devices,
                const struct board *board_list)
{
    if (!board || !devices || !board_list) {
        if (registration_verbose)
            printf("CSREG: Invalid parameters to setup_board()\n");
        return -1;
    }
#ifndef BAREMETAL
    *board = do_probe_board(board_list);
    if (!*board) {
        if (registration_verbose)
            printf("CSREG: Failed to detect the board!\n");
        return -1;
    }
#else
    *board = &board_list[0];
#endif

    return initilise_board(board, devices);
}

int setup_named_board(const char *board_name, const struct board **board,
                      struct cs_devices_t *devices,
                      const struct board *board_list)
{
    const struct board *b = NULL;

    if (!board || !devices || !board_list || !board_name) {
        if (registration_verbose)
            printf("CSREG: Invalid parameters to setup_board()\n");
        return -1;
    }

    *board = NULL;
    for (b = board_list; b->do_registration; b++) {
        if (strcmp(board_name, b->hardware) == 0) {
            if (registration_verbose >= 2)
                printf("CSREG: Selected '%s' board\n", b->hardware);
            *board = b;
            break;
        }
    }

    if (*board == NULL) {
        if (registration_verbose)
            printf
                ("CSREG: Unable to find name %s in setup_named_board()\n",
                 board_name);
        return -1;
    }

    return initilise_board(board, devices);
}
