#!/usr/bin/python

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

