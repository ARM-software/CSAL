#!/usr/bin/python

"""
Disable all cores and clusters from powering down, to allow ETM trace.

Needs to be sudo.
"""

import os

def wfile(fn, text):
    f = open(fn, "w")
    f.write(text)
    f.close()

sysfs = "/sys/devices/system/cpu"
for d in os.listdir(sysfs):
    if not d.startswith("cpu"):
        continue
    try:
        n = int(d[3:])
    except:
        continue
    cpuidle = sysfs + "/" + d + "/cpuidle"
    for s in [1,2]:
       wfile(((cpuidle + "/state%u/disable") % s), "1")

