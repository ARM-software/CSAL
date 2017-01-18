/*
CoreSight config listing utility

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    unsigned long romAddr = 0x10880000; /* arndale */
    int do_custom = 0;
    int argidx = 1;
    unsigned long exclude_lo, exclude_hi;

    printf("** CSLS: listing CoreSight config...\n");
    fflush(stdout);
    if (cs_init() != 0)
    {
        fprintf(stderr, "** CSLS: could not initialize CoreSight access\n");
        return EXIT_FAILURE;
    }

    if(argc > 1)
    {
        while(argidx < argc)
        {

            if(strcmp(argv[argidx],"-snowball") == 0)
            {
                romAddr = 0x801A0000;
                do_custom = 1;
                printf("** CSLS: using Snowball ROM address 0x%08lX\n", romAddr);
            }
            else if(strcmp(argv[argidx],"-romaddr") == 0)
            {
                if(argc > ++argidx)
                {
                    romAddr = strtoul(argv[argidx], NULL, 0);
                    do_custom = 1;
                    printf("** CSLS: Using custom ROM address 0x%08lX\n", romAddr);
                }
                else
                {
                    fprintf(stderr, "** CSLS::Error: -romaddr needs an address parameter\n");
                    return EXIT_FAILURE;
                }
            }
            else if(strcmp(argv[argidx],"-exclude") == 0)
            {
                if((argidx + 2) < argc)
                {
                    do_custom = 1;
                    argidx++;
                    exclude_lo = strtoul(argv[argidx], NULL, 0);
                    argidx++;
                    exclude_hi = strtoul(argv[argidx], NULL, 0);
                    if(exclude_lo < exclude_hi)
                    {
                        cs_exclude_range(exclude_lo, exclude_hi);
                        printf("**CSLS excluding range 0x%08lX to 0x%08lX\n",exclude_lo, exclude_hi);
                    }
                    else
                    {
                        fprintf(stderr, "** CSLS::Error: -exclude range 0x%08lX to 0x%08lX invalid\n",exclude_lo, exclude_hi);
                        return EXIT_FAILURE;
                    }
                }
                else
                {
                    fprintf(stderr, "** CSLS::Error: -exclude needs two address parameters\n");
                    return EXIT_FAILURE;
                }
            }
            else if((strcmp(argv[argidx],"--help") == 0) || (strcmp(argv[argidx],"-help") == 0))
            {
                printf("** CSLS: Usage\n   csls [{-snowball} | {-romaddr 0xNNNNNNNN {-exclude <addr_lo> <addr_hi>}*}]\n   No options uses default romaddress 0x10880000 for Arndale platform\n");
                printf("    -snowball - uses snowball rom address - standalone option\n    -romaddr 0xNNNNNNNN uses 0xNNNNNNNN as ROM Address\n");
                printf("    -exclude <addr_low> <addr_hi>  - exclude range from logging. Can be used multiple times with -romaddr. <addr> in 0xNNNNNNNN format\n\n");
                return EXIT_SUCCESS;
            }
            else
            {
                fprintf(stderr,"**CSLS Error: unknown option '%s'\n",argv[argidx]);
                return EXIT_FAILURE;
            }
            argidx++;
        }
    }
    else
    {
        printf("** CSLS: Using default ROM address 0x%08lX\n", romAddr);
    }

    if(do_custom)
    {
        /* custom platform */
        cs_register_romtable(romAddr);
    }
    else {
        /* Arndale : Exclude the Cortex-A5s */
        cs_exclude_range(0x108A0000, 0x108C0000);
        cs_register_romtable(0x10880000);
    }
    printf("** CSLS: done listing CoreSight config\n");
    cs_shutdown();
    return EXIT_SUCCESS;
}

