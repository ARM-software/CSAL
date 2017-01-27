/*
  Prints out the config for each ETM/PTM for the specified board

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

#include "csaccess.h"
#include "cs_utility.h"
#include "cs_demo_known_boards.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

static struct cs_devices_t devices;
static bool init_etm = false;
#define BOARD_NAME_LEN 256
static char board_name[BOARD_NAME_LEN];

static int print_ptm_config(const struct board *board, int ptm_no)
{
    int i, end;

    printf("CS_ETM_DEMO: Printing out PTM/ETM config...\n");
    /* Ensure TPIU isn't generating back-pressure */
    cs_disable_tpiu();
    /* While programming, ensure we are not collecting trace */
    cs_sink_disable(devices.etb);
    for (i = 0; i < board->n_cpu; ++i) {
        printf
            ("CS_ETM_DEMO: Configuring trace source id for CPU #%d ETM/PTM...\n",
             i);
        devices.ptm[i] = cs_cpu_get_device(i, CS_DEVCLASS_SOURCE);
        if (cs_set_trace_source_id(devices.ptm[i], 0x10 + i) < 0) {
            return -1;
        }
    }

    /* Print out ETM/PTM configuration */
    if (ptm_no >= 0 && ptm_no < board->n_cpu) {
        i = ptm_no;
        end = ptm_no + 1;
    } else {
        i = 0;
        end = board->n_cpu;
    }

    for (; i < end; ++i) {
        cs_etm_config_t tconfig;	/* PTM/ETMv3 config */
        cs_etmv4_config_t t4config;	/* ETMv4 config */
        void *p_config = 0;

        if (init_etm)
            cs_etm_clean(devices.ptm[i]);

        if (CS_ETMVERSION_MAJOR(cs_etm_get_version(devices.ptm[i])) >=
            CS_ETMVERSION_ETMv4)
            p_config = &t4config;
        else
            p_config = &tconfig;

        printf("CS_ETM_DEMO: Printing out ETM config for CPU %d\n", i);
        cs_etm_config_init_ex(devices.ptm[i], p_config);
        tconfig.flags = CS_ETMC_ALL;
        t4config.flags = CS_ETMC_ALL;
        cs_etm_config_get_ex(devices.ptm[i], p_config);
        cs_etm_config_print_ex(devices.ptm[i], p_config);
    }

    return 0;
}

static int dump_ptm_config(const struct board *board, int ptm_no)
{
    FILE *fp;
    cs_device_t ptm = devices.ptm[ptm_no];
    printf("CS_ETM_DEMO: Dumping out PTM/ETM config for CPU #%d...\n",
           ptm_no);
    cs_disable_tpiu();
    cs_sink_disable(devices.etb);

    printf("CS_ETM_DEMO: Address for ETM #%d: %" CS_PHYSFMT "\n", ptm_no,
           cs_device_address(ptm));
    fp = fopen("etmdump.bin", "wb");
    if (!fp)
        return -1;

    int i = 0;
    unsigned int data = 0;
    for (; i < 0x1000; i += 0x4) {
        data = cs_device_read(ptm, i);
        fwrite(&data, sizeof(unsigned int), 1, fp);
    }

    printf
        ("CS_ETM_DEMO: ETM registers for CPU #%d dumped to: etmdump.bin\n",
         ptm_no);
    fclose(fp);
    return 0;
}

int main(int argc, char **argv)
{
    int ptm_no = -1;
    bool dump = false;
    board_name[0] = 0;    

    if (argc >= 2) {
        int i = 1;
        for (; i < argc; ++i) {
            if (strncmp(argv[i], "-c", 2) == 0) {
                if (i + 1 < argc) {
                    ptm_no = strtoul(argv[i + 1], NULL, 0);
                    printf("CS_ETM_DEMO: Selecting CPU #%d\n", ptm_no);
                }
            } else if (strncmp(argv[i], "-d", 2) == 0) {
                dump = true;
                printf("CS_ETM_DEMO: Dumping ETM to file.\n");
            } else if (strncmp(argv[i], "-i", 2) == 0) {
                init_etm = true;
                printf("CS_ETM_DEMO: Initialise ETMs before printing.\n");
            } else if (strcmp(argv[i], "-board-name") == 0) {
                if (i + 1 >= argc) {
                    printf("Missing value after -board-name option\n");
                    return EXIT_FAILURE;
                }
                ++i;
                strncpy(board_name, argv[i], BOARD_NAME_LEN - 1);
                board_name[BOARD_NAME_LEN - 1] = 0;
            } else {
                printf("Unknown option %s.\n", argv[i]);
                return EXIT_FAILURE;
            }
        }
    } else {
        printf("CS_ETM_DEMO: Showing ETMs for all CPUs\n");
    }
    const struct board *board = malloc(sizeof(struct board));
    if (!board)
        return EXIT_FAILURE;

    printf("CoreSight Demonstration - Print ETM/PTM config\n");

    if (strlen(board_name) > 0) {
        if (setup_known_board_by_name(board_name, &board, &devices) < 0) {
            printf("Failed to setup board named %s.\n",board_name);
            return EXIT_FAILURE;
        }
    } else {
        if (setup_known_board(&board, &devices) < 0) {
            return EXIT_FAILURE;
        }
    }

    printf("Board: %s\n", board->hardware);

    /* Print ETM/PTM config data */
    if (print_ptm_config(board, ptm_no) < 0) {
        return EXIT_FAILURE;
    }

    /* Dump ETM to file */
    if (dump && ptm_no >= 0 && ptm_no < board->n_cpu)
        if (dump_ptm_config(board, ptm_no) < 0) {
            return EXIT_FAILURE;
        }

    printf("CS_ETM_DEMO: shutdown...\n");
    cs_shutdown();
    return EXIT_SUCCESS;
}

/* end of cs_etm_config_demo.c */
