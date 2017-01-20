"""
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
"""

from csaccess import *

class CSRegisterError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return 'CS_REGISTRATION: ' + repr(self.value)

def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    return type('Enum', (), enums)

boards = [
    { 
        'registration' : None,
        'n_cpu' : 2,
        'hardware' : 'ARNDALE'
    },  
    {
        'registration' : None,
        'n_cpu' : 2,
        'hardware' : 'Altera SOCFPGA',
    }
]

def probe_board():
    board = None
    
    f = open('/proc/cpuinfo', 'r')
    # Exception Handling
    
    for line in f:
        found = False
        if line.find('Hardware\t: ', 0, 11) != -1:
            hardware = line[11:-1]
            for b in boards:
                if hardware == b['hardware']:
                    found = True
                    board = b
                    break;
        if found:
            break

    f.close()
    return board

def setup_board(devices):
    """
    Registers CoreSight devices, TBD need to probe board and other stuff...
    """
#    devices = {}
    # Probe the board - TBD
    board = probe_board()

    if not board:
        raise CSRegisterError('Failed to detect the board!')

    # Initialise CoreSight Library
    cs_init()

    # Register TC2 - remove this for more `generic' interface
    board['registration'](devices)

    print "Registration Complete: %d" % cs_registration_complete()
    print "Error Count: %d" % cs_error_count()
    
    cs_cti_diag()
    print "CSDEMO: Registration Complete."
    return board

if __name__ != '__main__':
    print "We're running inside a module"
