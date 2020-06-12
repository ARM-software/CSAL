#!/usr/bin/python

"""
Check all source files (including this one) for the correct software license.

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

from __future__ import print_function

import os


def fn_is_source(fn):
    base, ext = os.path.splitext(fn)
    if "makefile" in base:
        return base
    return ext in [".c", ".cpp", ".h", ".py"]


def fn_is_licensed(fn):
    found = None
    f = open(fn)
    lno = 0
    for ln in f:
        lno += 1
        ix = ln.find("apache.org/licenses/LICENSE-2.0")
        if ix >= 0:
            found = lno
            break
        if lno > 20:
            break
    if False:
        if found is not None:
            print("%s: found at line %u" % (fn, found))
    return found is not None


def check_all_sources_licensed(dir):
    n_files = 0
    for root, dirs, files in os.walk(dir):
        for f in files:
            fn = os.path.join(root, f)   
            if fn_is_source(fn):
                n_files += 1
                if not fn_is_licensed(fn):
                    print("%s: not licensed" % fn)


check_all_sources_licensed(os.path.dirname(os.path.realpath(__file__)))

