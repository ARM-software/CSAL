#!/usr/bin/python

"""
Copy the live kernel image from /dev/mem.

This won't pick up loadable kernel modules. Ideally we'd use /proc/kcore instead.

Copyright (C) ARM Ltd. 2018-2021.  All rights reserved.

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

from __future__ import print_function

import os

page_size = os.sysconf("SC_PAGE_SIZE")

f = open("/proc/iomem")
for ln in f:
    if ln.strip().endswith("Kernel code"):
        [start, end] = ln.split()[0].split('-')
        start_addr = int(start, 16)
        end_addr = int(end, 16)
        break
f.close()

size = end_addr - start_addr
assert size > 0, "kernel size 0, you should run as sudo"

cmd = "dd if=/dev/mem of=kernel.image ibs=%uK skip=%u count=%u" % (page_size/1024, start_addr/page_size, (size+page_size-1)/page_size)

print(">>> %s" % cmd)

os.system(cmd)
