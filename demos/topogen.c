/*
CoreSight topology detection - command-line utility to print out topology.

Copyright (C) ARM Ltd. 2016.  All rights reserved.

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
#include "csregistration.h"
#include "cs_demo_known_boards.h"

#include "cs_topology_detect.h"
#include "cs_topology_print.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>


static int usage(char const *cmd_name)
{
    fprintf(stderr, "%s:\n", cmd_name);
    fprintf(stderr, "Generate topology description for CoreSight\n");
    fprintf(stderr, "  --capi        output format: C API calls (default)\n");
    fprintf(stderr, "  --dot         output format: dot/graphviz source\n");
    fprintf(stderr, "  --dts         output format: Linux device tree fragment\n");
    fprintf(stderr, "  --rom <addr>  specify ROM table address\n");
    fprintf(stderr, "  --detect      auto-detect ATB topology\n");
    fprintf(stderr, "  -o <fn>       output file\n");
    fprintf(stderr, "  --help        print this help\n");
    fprintf(stderr, "Set CSAL_BOARD environment variable to override board name\n");
    return EXIT_FAILURE; 
}


int main(int argc, char **argv)
{
    char const *cmd_name = argv[0];
    struct cs_devices_t devices;
    struct board const *board;
    int o_detect = 0;
    cs_topology_format_t o_fmt = CS_TOP_STDC;
    cs_physaddr_t romtable = 0;
    int o_verbose = 0;

    while (*++argv) {
        char const *arg = *argv;
        if (arg[0] == '-') {
            if (!strcmp(arg, "--help")) {
                return usage(cmd_name);
            } else if (!strcmp(arg, "--capi")) {
                o_fmt = CS_TOP_STDC;
            } else if (!strcmp(arg, "--dot")) {
                o_fmt = CS_TOP_DOT;
            } else if (!strcmp(arg, "--dts")) {
                o_fmt = CS_TOP_DTS;
            } else if (!strcmp(arg, "--rom")) {
                unsigned long long phaddr;
                arg = *++argv;
                if (!arg) {
                    return usage(cmd_name);
                }
                if (1 != sscanf(arg, "%llx", &phaddr)) {
                    return usage(cmd_name);
                }
                romtable = (cs_physaddr_t)phaddr;
                if ((romtable & 0xfff) != 0) {
                    fprintf(stderr, "%s: ROM table must be 4K aligned: %#llx\n", cmd_name, phaddr);
                    return EXIT_FAILURE;
                }
            } else if (!strcmp(arg, "--detect")) {
                o_detect = 1;
            } else if (!strcmp(arg, "-o") || !strcmp(arg, "--output")) {
                arg = *++argv;
                if (!arg) {
                    return usage(cmd_name);
                }
                if (!freopen(arg, "w", stdout)) {
                    perror(arg);
                    return EXIT_FAILURE;
                }
            } else if (!strcmp(arg, "-v") || !strcmp(arg, "--verbose")) {
                o_verbose++;
            } else {
                fprintf(stderr, "%s: unknown option \"%s\"\n", cmd_name, arg);
                return usage(cmd_name);
            }
        } else {
            return usage(cmd_name);
        }
    }

    registration_verbose = o_verbose;

    if (cs_init() < 0) {
        fprintf(stderr, "%s: CSAL initialization failed\n", cmd_name);
        return EXIT_FAILURE;
    }
    if (romtable) {
        cs_init();
        cs_register_romtable(romtable);
        if (o_verbose) {
            fprintf(stderr, "%s: ROM table scaned\n", cmd_name);
        }
    } else {
        if (setup_known_board(&board, &devices) < 0) {
            fprintf(stderr, "%s: failed to auto-detect and set up this board\n", cmd_name);
            cs_shutdown();
            return EXIT_FAILURE;
        }
        if (o_verbose) {
            fprintf(stderr, "%s: board registered\n", cmd_name);
        }
    }
    if (o_detect) {
        if (o_verbose) {
            fprintf(stderr, "%s: scanning topology...\n", cmd_name);
        }
        if (cs_detect_topology(1) < 0) {
            fprintf(stderr, "%s: topology detection failed\n", cmd_name);
            cs_shutdown();
            return EXIT_FAILURE;
        }
        if (o_verbose) {
            fprintf(stderr, "%s: topology detected\n", cmd_name);
        }
    }
    if (o_verbose) {
        fprintf(stderr, "%s: printing topology...\n", cmd_name);
    }
    if (cs_print_topology(stdout, o_fmt) < 0) {
        fprintf(stderr, "%s: failed to print topology\n", cmd_name);
    }
    cs_shutdown();
    return EXIT_SUCCESS;    
}

