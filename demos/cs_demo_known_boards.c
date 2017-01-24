/*
  CoreSight known board registration for demos
  Provides an abstract interface to registering boards with the library (for multiple demos)

  Copyright (C) ARM Limited, 2013-2016. All rights reserved.

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


#include "cs_demo_known_boards.h"

#include <stdio.h>
#include <stdlib.h>


static int do_registration_snowball(struct cs_devices_t *devices)
{
    enum { A9_0, A9_1 };

    cs_device_t funnel, rep;
    int i;

    if (registration_verbose)
        printf("CSDEMO: Registering Snowball CoreSight devices...\n");
    cs_register_romtable(0x801A0000);

    if (registration_verbose)
        printf("CSDEMO: Registering CPU affinities...\n");
    /* PTMs */
    cs_device_set_affinity(cs_device_register(0x801AE000), A9_0);
    cs_device_set_affinity(cs_device_register(0x801AF000), A9_1);
    /* CTIs */
    cs_device_set_affinity(cs_device_register(0x801AC000), A9_0);
    cs_device_set_affinity(cs_device_register(0x801AD000), A9_1);

    if (registration_verbose)
        printf("CSDEMO: Registering trace-bus connections...\n");
    funnel = cs_device_get(0x801A6000);
    cs_atb_register(cs_cpu_get_device(A9_0, CS_DEVCLASS_SOURCE), 0, funnel,
                    0);
    cs_atb_register(cs_cpu_get_device(A9_1, CS_DEVCLASS_SOURCE), 0, funnel,
                    1);

    rep = cs_atb_add_replicator(2);
    cs_atb_register(funnel, 0, rep, 0);

    devices->etb = cs_device_get(0x801A4000);
    cs_atb_register(rep, 0, devices->etb, 0);

    /* Snowball has a single CPU Part entry to cover both cores so cannot use the
     * probe board results. */
    for (i = 0; i < 2; ++i)
        devices->cpu_id[i] = 0xC09;

    return 0;
}

static int do_registration_arndale(struct cs_devices_t *devices)
{
    enum { A15_0, A15_1 };
    cs_device_t rep_main, rep_itm, funnel, tpiu;
    int i;

    if (registration_verbose)
        printf("CSDEMO: Registering Arndale CoreSight devices...\n");
    cs_exclude_range(0x108A0000, 0x108C0000);	/* exclude the Cortex-A5s */
    cs_register_romtable(0x10880000);

    if (registration_verbose)
        printf("CSDEMO: Registering CPU affinities...\n");
    cs_device_set_affinity(cs_device_register(0x1089C000), A15_0);
    cs_device_set_affinity(cs_device_register(0x1089D000), A15_1);
    cs_device_set_affinity(cs_device_register(0x10898000), A15_0);
    cs_device_set_affinity(cs_device_register(0x10899000), A15_1);

    if (registration_verbose)
        printf("CSDEMO: Registering trace-bus connections...\n");
    /* Connect the devices */
    funnel = cs_device_get(0x10884000);
    cs_atb_register(cs_cpu_get_device(A15_0, CS_DEVCLASS_SOURCE), 0,
                    funnel, 0);
    cs_atb_register(cs_cpu_get_device(A15_1, CS_DEVCLASS_SOURCE), 0,
                    funnel, 1);

    rep_main = cs_atb_add_replicator(2);
    cs_atb_register(funnel, 0, rep_main, 0);
    devices->etb = cs_device_get(0x10881000);
    tpiu = cs_device_get(0x10883000);
    cs_atb_register(rep_main, 0, devices->etb, 0);
    cs_atb_register(rep_main, 1, tpiu, 0);

    devices->itm = cs_device_register(0x10885000);
    rep_itm = cs_atb_add_replicator(2);
    cs_atb_register(devices->itm, 0, rep_itm, 0);
    cs_atb_register(rep_itm, 0, funnel, 3);

    for (i = 0; i < 2; ++i) {
#ifndef BAREMETAL
        devices->cpu_id[i] = cpu_id[i];
#else
        devices->cpu_id[i] = 0xC0F;    
#endif
    }
    return 0;
}

static int do_registration_tc2(struct cs_devices_t *devices)
{
    int A15_0 = -1, A15_1 = -1, A7_0 = -1, A7_1 = -1, A7_2 = -1;
    cs_device_t rep_main, rep_itm, cscti, funnel, tpiu;
    int i;

    if (registration_verbose)
        printf("CSDEMO: Registering TC2 CoreSight devices...\n");

#ifndef BAREMETAL
    if (cpu_id[0] == 0xC0F && cpu_id[2] == 0xC07) {
        A15_0 = 0;
        A15_1 = 1;
        A7_0 = 2;
        A7_1 = 3;
        A7_2 = 4;
    } else if (cpu_id[0] == 0xC07 && cpu_id[3] == 0xC0F) {
        A7_0 = 0;
        A7_1 = 1;
        A7_2 = 2;
        A15_0 = 3;
        A15_1 = 4;
    } else {
        fprintf(stderr, "Can't recognize CPU order: CPU[0] is %03X\n",
                cpu_id[0]);
        return -1;
    }
#else
    /* choose a default assignment for baremetal */
    A15_0 = 0;
    A15_1 = 1;
    A7_0 = 2;
    A7_1 = 3;
    A7_2 = 4;
    cpu_id[A15_0] = 0xC0F;
    cpu_id[A15_1] = 0xC0F;
    cpu_id[A7_0] = 0xC07;
    cpu_id[A7_1] = 0xC07;
    cpu_id[A7_2] = 0xC07;
#endif

    cs_register_romtable(0x20000000);

    /* Set the PTM affinities */
    cs_device_set_affinity(cs_device_register(0x2201C000), A15_0);
    cs_device_set_affinity(cs_device_register(0x2201D000), A15_1);
    cs_device_set_affinity(cs_device_register(0x2203C000), A7_0);
    cs_device_set_affinity(cs_device_register(0x2203D000), A7_1);
    cs_device_set_affinity(cs_device_register(0x2203E000), A7_2);
    /* Set the CTI affinities */
    cs_device_set_affinity(cs_device_register(0x22018000), A15_0);
    cs_device_set_affinity(cs_device_register(0x22019000), A15_1);
    cs_device_set_affinity(cs_device_register(0x22038000), A7_0);
    cs_device_set_affinity(cs_device_register(0x22039000), A7_1);
    cs_device_set_affinity(cs_device_register(0x2203A000), A7_2);
    /* Set the PMU affinities */
    cs_device_set_affinity(cs_device_register(0x22011000), A15_0);
    cs_device_set_affinity(cs_device_register(0x22013000), A15_1);
    cs_device_set_affinity(cs_device_register(0x22031000), A7_0);
    cs_device_set_affinity(cs_device_register(0x22033000), A7_1);
    cs_device_set_affinity(cs_device_register(0x22035000), A7_2);
    /* Set the debug affinities */
    cs_device_set_affinity(cs_device_register(0x22010000), A15_0);
    cs_device_set_affinity(cs_device_register(0x22012000), A15_1);
    cs_device_set_affinity(cs_device_register(0x22030000), A7_0);
    cs_device_set_affinity(cs_device_register(0x22032000), A7_1);
    cs_device_set_affinity(cs_device_register(0x22034000), A7_2);

    if (registration_verbose)
        printf("CSDEMO: Registering trace-bus connections...\n");
    /* Connect the devices */
    funnel = cs_device_get(0x20040000);
    /* TC2 TRM Table 2.12 Test chip Trace connection addresses */
    cs_atb_register(cs_cpu_get_device(A15_0, CS_DEVCLASS_SOURCE), 0,
                    funnel, 0);
    cs_atb_register(cs_cpu_get_device(A15_1, CS_DEVCLASS_SOURCE), 0,
                    funnel, 1);
    cs_atb_register(cs_cpu_get_device(A7_0, CS_DEVCLASS_SOURCE), 0, funnel,
                    2);
    /* 3 is the ITM (or one of its replicator outputs) */
    cs_atb_register(cs_cpu_get_device(A7_1, CS_DEVCLASS_SOURCE), 0, funnel,
                    4);
    cs_atb_register(cs_cpu_get_device(A7_2, CS_DEVCLASS_SOURCE), 0, funnel,
                    5);

    rep_main = cs_atb_add_replicator(2);
    cs_atb_register(funnel, 0, rep_main, 0);
    devices->etb = cs_device_get(0x20010000);
    tpiu = cs_device_get(0x20030000);
    cs_atb_register(rep_main, 0, devices->etb, 0);
    cs_atb_register(rep_main, 1, tpiu, 0);

    devices->itm = cs_device_register(0x20050000);
    rep_itm = cs_atb_add_replicator(2);
    cs_atb_register(devices->itm, 0, rep_itm, 0);
    cs_atb_register(rep_itm, 0, funnel, 3);

    cscti = cs_device_register(0x20020000);
    cs_cti_connect_trigsrc(devices->etb, CS_TRIGOUT_ETB_FULL,
                           cs_cti_trigsrc(cscti, 2));
    cs_cti_connect_trigsrc(devices->etb, CS_TRIGOUT_ETB_ACQCOMP,
                           cs_cti_trigsrc(cscti, 3));
    cs_cti_connect_trigdst(cs_cti_trigdst(cscti, 0), devices->etb,
                           CS_TRIGIN_ETB_FLUSHIN);
    cs_cti_connect_trigdst(cs_cti_trigdst(cscti, 1), devices->etb,
                           CS_TRIGIN_ETB_TRIGIN);
    /* CSCTI trigouts #2/#3 are connected to TPIU FLUSHIN/TRIGIN */

    for (i = 0; i < 5; ++i)
        devices->cpu_id[i] = cpu_id[i];

    return 0;
}

static int do_registration_juno(struct cs_devices_t *devices)
{
    enum { A53_0, A53_1, A53_2, A53_3, A57_0, A57_1 };
    cs_device_t rep, etr, etf, fun_main, fun_a53, fun_a57, stm, tpiu,
        sys_cti;
    cs_device_t r1_fun_scp, r1_fun_common, r1_etf_scp;
#ifdef LIB_DEVICE_UNSUPPORTED
    cs_device_t r1_cti_2, ela_a53, ela_a57;
#endif
    int i;

    if (registration_verbose)
        printf("CSDEMO: Registering CoreSight devices...\n");
    cs_register_romtable(0x20000000);

    if (registration_verbose)
        printf("CSDEMO: Registering CPU affinities...\n");

    /* CTI affinities */
    cs_device_set_affinity(cs_device_register(0x22020000), A57_0);
    cs_device_set_affinity(cs_device_register(0x22120000), A57_1);
    cs_device_set_affinity(cs_device_register(0x23020000), A53_0);
    cs_device_set_affinity(cs_device_register(0x23120000), A53_1);
    cs_device_set_affinity(cs_device_register(0x23220000), A53_2);
    cs_device_set_affinity(cs_device_register(0x23320000), A53_3);

    /* PMU affinities */
    cs_device_set_affinity(cs_device_register(0x22030000), A57_0);
    cs_device_set_affinity(cs_device_register(0x22130000), A57_1);
    cs_device_set_affinity(cs_device_register(0x23030000), A53_0);
    cs_device_set_affinity(cs_device_register(0x23130000), A53_1);
    cs_device_set_affinity(cs_device_register(0x23230000), A53_2);
    cs_device_set_affinity(cs_device_register(0x23330000), A53_3);

    /* ETMv4 affinities */
    cs_device_set_affinity(cs_device_register(0x22040000), A57_0);
    cs_device_set_affinity(cs_device_register(0x22140000), A57_1);
    cs_device_set_affinity(cs_device_register(0x23040000), A53_0);
    cs_device_set_affinity(cs_device_register(0x23140000), A53_1);
    cs_device_set_affinity(cs_device_register(0x23240000), A53_2);
    cs_device_set_affinity(cs_device_register(0x23340000), A53_3);

    if (registration_verbose)
        printf("CSDEMO: Registering trace-bus connections...\n");

    /* funnels in clusters */
    fun_a57 = cs_device_get(0x220C0000);
    cs_atb_register(cs_cpu_get_device(A57_0, CS_DEVCLASS_SOURCE), 0,
                    fun_a57, 0);
    cs_atb_register(cs_cpu_get_device(A57_1, CS_DEVCLASS_SOURCE), 0,
                    fun_a57, 1);

    fun_a53 = cs_device_get(0x230C0000);
    cs_atb_register(cs_cpu_get_device(A53_0, CS_DEVCLASS_SOURCE), 0,
                    fun_a53, 0);
    cs_atb_register(cs_cpu_get_device(A53_1, CS_DEVCLASS_SOURCE), 0,
                    fun_a53, 1);
    cs_atb_register(cs_cpu_get_device(A53_2, CS_DEVCLASS_SOURCE), 0,
                    fun_a53, 2);
    cs_atb_register(cs_cpu_get_device(A53_3, CS_DEVCLASS_SOURCE), 0,
                    fun_a53, 3);


    /*common setup */
    fun_main = cs_device_get(0x20040000);
    stm = cs_device_get(0x20100000);
    etf = cs_device_get(0x20010000);
    rep = cs_device_get(0x20120000);
    etr = cs_device_get(0x20070000);
    tpiu = cs_device_get(0x20030000);


    /* look for r1 extras */
    r1_fun_scp = cs_device_get(0x20130000);
    if (r1_fun_scp == 0) {
        /* juno r0 */
        cs_atb_register(fun_a53, 0, fun_main, 0);
        cs_atb_register(fun_a57, 0, fun_main, 1);
        cs_atb_register(stm, 0, fun_main, 2);

        cs_atb_register(fun_main, 0, etf, 0);

        cs_atb_register(etf, 0, rep, 0);


    } else {
        /* juno r1 */
        r1_fun_common = cs_device_get(0x20150000);
        r1_etf_scp = cs_device_get(0x20140000);

#ifdef LIB_DEVICE_UNSUPPORTED
        r1_cti_2 = cs_device_get(0x20160000);
        ela_a53 = cs_device_get(0x230D0000);
        ela_a57 = cs_device_get(0x220D0000);
#endif


        cs_atb_register(fun_a53, 0, fun_main, 0);
        cs_atb_register(fun_a57, 0, fun_main, 1);

        cs_atb_register(stm, 0, r1_fun_scp, 0);

        cs_atb_register(fun_main, 0, etf, 0);
        cs_atb_register(r1_fun_scp, 0, r1_etf_scp, 0);

        cs_atb_register(etf, 0, r1_fun_common, 0);
        cs_atb_register(r1_etf_scp, 0, r1_fun_common, 1);

        cs_atb_register(r1_fun_common, 0, rep, 0);

        /* ELAs can be connected to CTI2 here - but lib doesn't support them yet. */

        devices->itm_etb = r1_etf_scp;
    }

    cs_atb_register(rep, 1, etr, 0);
    cs_atb_register(rep, 0, tpiu, 0);

    /* populate the devices structure */
    devices->itm = stm;
    devices->etb = etf;		/* core output through main etf */

    /* STM needs to init master address and master 0 by default 
       All Juno cores see a single master @ 0, but other select bits
       ensure different cores and security options result in different
       master IDs in output.
    */
    cs_stm_config_master(stm, 0, 0x28000000);
    cs_stm_select_master(stm, 0);

    /* Connect system CTI to devices */
    sys_cti = cs_device_register(0x20020000);
    cs_cti_connect_trigsrc(etf, CS_TRIGOUT_ETB_FULL,
                           cs_cti_trigsrc(sys_cti, 0));
    cs_cti_connect_trigsrc(etf, CS_TRIGOUT_ETB_ACQCOMP,
                           cs_cti_trigsrc(sys_cti, 1));
    cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 7), etf,
                           CS_TRIGIN_ETB_FLUSHIN);
    cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 6), etf,
                           CS_TRIGIN_ETB_TRIGIN);

    cs_cti_connect_trigsrc(etr, CS_TRIGOUT_ETB_FULL,
                           cs_cti_trigsrc(sys_cti, 2));
    cs_cti_connect_trigsrc(etr, CS_TRIGOUT_ETB_ACQCOMP,
                           cs_cti_trigsrc(sys_cti, 3));
    cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 0), etr,
                           CS_TRIGIN_ETB_FLUSHIN);
    cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 1), etr,
                           CS_TRIGIN_ETB_TRIGIN);

    cs_cti_connect_trigsrc(stm, CS_TRIGOUT_STM_TRIGOUTSPTE,
                           cs_cti_trigsrc(sys_cti, 4));
    cs_cti_connect_trigsrc(stm, CS_TRIGOUT_STM_TRIGOUTSW,
                           cs_cti_trigsrc(sys_cti, 5));
    cs_cti_connect_trigsrc(stm, CS_TRIGOUT_STM_TRIGOUTHETE,
                           cs_cti_trigsrc(sys_cti, 6));
    cs_cti_connect_trigsrc(stm, CS_TRIGOUT_STM_ASYNCOUT,
                           cs_cti_trigsrc(sys_cti, 7));

    /* edges of the CTI outputs are connected to separate HW events in STM */
    cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 4), stm, CS_TRIGIN_STM_HWEVENT_0);	/* rising edge */
    cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 4), stm, CS_TRIGIN_STM_HWEVENT_1);	/* falling edge */
    cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 5), stm, CS_TRIGIN_STM_HWEVENT_2);	/* rising edge */
    cs_cti_connect_trigdst(cs_cti_trigdst(sys_cti, 5), stm, CS_TRIGIN_STM_HWEVENT_3);	/* falling edge */

    /* the linux board probe does not set up CPUIDs correctly for Juno - 
       hardcode here for both linux and BAREMETAL. */
    for (i = 0; i < 4; i++)
        devices->cpu_id[i] = 0xD03;
    for (i = 4; i < 6; i++)
        devices->cpu_id[i] = 0xD07;

    return 0;
}

static int do_registration_altera(struct cs_devices_t *devices)
{
    enum { A9_0, A9_1 };
    cs_device_t rep, etr, funnel, tpiu;
    int i;

    if (registration_verbose)
        printf("CSDEMO: Registering CoreSight devices...\n");
    cs_exclude_range(0xff007000, 0xff009000);	/* exclude FPGA CTI and ROM */
    cs_exclude_range(0xff080000, 0xff081000);	/* skipping potentially missing ROM table entry */
    cs_register_romtable(0xff000000);

    if (registration_verbose)
        printf("CSDEMO: Registering CPU affinities...\n");
    /* PTMs */
    cs_device_set_affinity(cs_device_register(0xff11c000), A9_0);
    cs_device_set_affinity(cs_device_register(0xff11d000), A9_1);
    /* CTIs */
    cs_device_set_affinity(cs_device_register(0xff118000), A9_0);
    cs_device_set_affinity(cs_device_register(0xff119000), A9_1);

    if (registration_verbose)
        printf("CSDEMO: Registering trace-bus connections...\n");
    funnel = cs_device_get(0xff004000);
    cs_atb_register(cs_cpu_get_device(A9_0, CS_DEVCLASS_SOURCE), 0, funnel,
                    0);
    cs_atb_register(cs_cpu_get_device(A9_1, CS_DEVCLASS_SOURCE), 0, funnel,
                    1);
    /* 3 is the STM, 2 and 4-7 unused */

    devices->etb = cs_device_get(0xff001000);	/* It's ETF, not ETB actually */
    cs_atb_register(funnel, 0, devices->etb, 0);

    rep = cs_atb_add_replicator(2);
    cs_atb_register(devices->etb, 0, rep, 0);

    /* ETR, not ETB - by default routes to SDRAM, 32kB at 0x00100000 */
    etr = cs_device_get(0xff006000);
    cs_atb_register(rep, 0, etr, 0);

    tpiu = cs_device_get(0xff003000);
    cs_atb_register(rep, 1, tpiu, 0);

    devices->itm = cs_device_register(0xff005000);	/* STM not ITM */
    cs_stm_config_master(devices->itm, 0, 0xfc000000);
    cs_stm_config_master(devices->itm, 1, 0xfd000000);
    cs_stm_config_master(devices->itm, 2, 0xfe000000);
    cs_atb_register(devices->itm, 0, funnel, 3);

    for (i = 0; i < 2; ++i) {
#ifndef BAREMETAL
        devices->cpu_id[i] = cpu_id[i];
#else
        devices->cpu_id[i] = 0xC09;
#endif
    }
    return 0;
}

static int do_registration_axx5500(struct cs_devices_t *devices)
{
#define N_CLUSTER 4
    unsigned int i, j;
    unsigned long long base = 0x2012100000;
    cs_device_t funnel[N_CLUSTER];
    cs_device_t etb[N_CLUSTER];

    if (registration_verbose)
        printf("CSDEMO: Registering CoreSight devices...\n");
    cs_register_romtable(base);
    etb[0] = cs_device_register(base + 0x1000);
    etb[1] = cs_device_register(base + 0x2000);
    etb[2] = cs_device_register(base + 0x4000);
    etb[3] = cs_device_register(base + 0x5000);
    for (i = 0; i < N_CLUSTER; ++i) {
        unsigned long long cluster = base + 0x20000 + i * 0x20000;
        funnel[i] = cs_device_register(cluster + 0x1000);
        cs_atb_register(funnel[i], 0, etb[i], 0);
        for (j = 0; j < 4; ++j) {
            cs_device_t debug, pmu, cti, ptm;
            unsigned int n_cpu = i * 4 + j;
            debug = cs_device_register(cluster + 0x10000 + j * 0x2000);
            pmu = cs_device_register(cluster + 0x11000 + j * 0x2000);
            cti = cs_device_register(cluster + 0x18000 + j * 0x1000);
            ptm = cs_device_register(cluster + 0x1C000 + j * 0x1000);
            cs_device_set_affinity(debug, n_cpu);
            cs_device_set_affinity(pmu, n_cpu);
            cs_device_set_affinity(cti, n_cpu);
            cs_device_set_affinity(ptm, n_cpu);
            cs_atb_register(ptm, 0, funnel[i], j);
        }
    }
    /* For the demo, use the ETB for cluster 0 */
    devices->etb = etb[0];
    devices->itm = cs_device_register(base + 0x7000);
    cs_stm_config_master(devices->itm, 0, 0x2013000000);
    devices->itm_etb = cs_device_register(base + 0x8000);

    for (i = 0; i < N_CLUSTER * 4; ++i) {
#ifndef BAREMETAL
        devices->cpu_id[i] = cpu_id[i];
#else
        devices->cpu_id[i] = 0xC0F;
#endif
    }
    return 0;
}

const struct board known_boards[] = {
    {
        .do_registration = do_registration_arndale,
        .n_cpu = 2,
        .hardware = "ARNDALE",
    }, {
        .do_registration = do_registration_tc2,
        .n_cpu = 5,
        .hardware = "ARM-Versatile Express",
    }, {
        .do_registration = do_registration_juno,
        .n_cpu = 6,
        .hardware = "Juno",
    }, {
        .do_registration = do_registration_altera,
        .n_cpu = 2,
        .hardware = "Altera SOCFPGA",
    }, {
        .do_registration = do_registration_snowball,
        .n_cpu = 2,
        .hardware = "ST-Ericsson Snowball platform",
    }, {
        .do_registration = do_registration_axx5500,
        .n_cpu = 16,
        .hardware = "LSI Axxia",
    },
    {}
};

int setup_known_board(const struct board **board,
                      struct cs_devices_t *devices)
{
    char const *board_name = getenv("CSAL_BOARD");
    if (board_name != NULL) {
        return setup_known_board_by_name(board_name, board, devices);
    }
    return setup_board(board, devices, known_boards);
}

int setup_known_board_by_name(const char *board_name,
                              const struct board **board,
                              struct cs_devices_t *devices)
{
    return setup_named_board(board_name, board, devices, known_boards);
}
