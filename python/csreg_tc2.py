from csaccess import *
from csregistration import boards, enum

def register_tc2(devices):
    """
    Registers TC2 Board and sets up relevant connections between coresight
    components
    """
    cores = enum('A7_0', 'A7_1', 'A7_2', 'A15_0', 'A15_1')

    print "CSDEMO: Registering TC2 CoreSight devices..."
    cs_register_romtable(0x20000000)
    # Set the PTM affinities
    cs_device_set_affinity(cs_device_register(0x2201C000), cores.A15_0)
    cs_device_set_affinity(cs_device_register(0x2201D000), cores.A15_1)
    cs_device_set_affinity(cs_device_register(0x2203C000), cores.A7_0)
    cs_device_set_affinity(cs_device_register(0x2203D000), cores.A7_1)
    cs_device_set_affinity(cs_device_register(0x2203E000), cores.A7_2)

    #  Set the CTI affinities
    cs_device_set_affinity(cs_device_register(0x22018000), cores.A15_0)
    cs_device_set_affinity(cs_device_register(0x22019000), cores.A15_1)
    cs_device_set_affinity(cs_device_register(0x22038000), cores.A7_0)
    cs_device_set_affinity(cs_device_register(0x22039000), cores.A7_1)
    cs_device_set_affinity(cs_device_register(0x2203A000), cores.A7_2)

    print "CSDEMO: Registering trace-bus connections..."
    # Connect the devices
    funnel = cs_device_get(0x20040000)

    # TC2 TRM Table 2.12 Test chip Trace connection addresses
    cs_atb_register(cs_cpu_get_device(cores.A15_0, CS_DEVCLASS_SOURCE), 0, funnel, 0)
    cs_atb_register(cs_cpu_get_device(cores.A15_1, CS_DEVCLASS_SOURCE), 0, funnel, 1)
    cs_atb_register(cs_cpu_get_device(cores.A7_0, CS_DEVCLASS_SOURCE), 0, funnel, 2)
    cs_atb_register(cs_cpu_get_device(cores.A7_1, CS_DEVCLASS_SOURCE), 0, funnel, 4)
    cs_atb_register(cs_cpu_get_device(cores.A7_2, CS_DEVCLASS_SOURCE), 0, funnel, 5)
    # 3 is the ITM (or one of its replicator outputs)

    rep_main = cs_atb_add_replicator(2)
    cs_atb_register(funnel, 0, rep_main, 0)
    devices['etb'] = cs_device_get(0x20010000)
    tpiu = cs_device_get(0x20030000)
    cs_atb_register(rep_main, 0, devices['etb'], 0)
    cs_atb_register(rep_main, 1, tpiu, 0)

    devices['itm'] = cs_device_register(0x20050000)
    rep_itm = cs_atb_add_replicator(2)
    cs_atb_register(devices['itm'], 0, rep_itm, 0)
    cs_atb_register(rep_itm, 0, funnel, 3)

    cscti = cs_device_register(0x20020000)
    cs_cti_connect_trigsrc(devices['etb'], CS_TRIGOUT_ETB_FULL, cs_cti_trigsrc(cscti, 2))
    cs_cti_connect_trigsrc(devices['etb'], CS_TRIGOUT_ETB_ACQCOMP, cs_cti_trigsrc(cscti, 3))
    cs_cti_connect_trigdst(cs_cti_trigdst(cscti, 0), devices['etb'], CS_TRIGIN_ETB_FLUSHIN)
    cs_cti_connect_trigdst(cs_cti_trigdst(cscti, 1), devices['etb'], CS_TRIGIN_ETB_TRIGIN)
    # CSCTI trigouts #2/#3 are connected to TPIU FLUSHIN/TRIGIN
    
    return 0

if __name__ != '__main__':
    """
    Add corresponding metadata about board to the list
    """    
    print "Loaded Info for ARM TC2"
    boards.append({            
        'registration' : register_tc2,
        'n_cpu' : 5,
        'hardware' : 'ARM-Versatile Express',
    })
