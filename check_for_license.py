#!/usr/bin/python

"""
Check all source files (including this one) for the correct software license.
We also allow files to be explicitly marked as having an alternate license
by including the text "CSAL-ALTERNATE-LICENSE".

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

import os, sys

## Distance we need to find the license text in
LICENSE_MAX_LINE = 20

## Texts to search for, with a flag to say if it's the 'approved' license
LICENSE_TEXT = {
    "SPDX-License-Identifier: Apache 2.0": True,
    "apache.org/licenses/LICENSE-2.0": True,
    "CSAL-ALTERNATE-LICENSE": False
}


def fn_is_source(fn):
    """
    Test a filename to check that it's source code and needs a license.
    """
    base, ext = os.path.splitext(fn)
    if "makefile" in base:
        return base
    return ext in [".c", ".cpp", ".h", ".py", ".json", ".xml"]


def fn_is_licensed(fn):
    """
    Check that a source file already has appropriate license text embedded in it.,
    within the first LICENSE_MAX_LINE lines.
    """
    found = None
    f = open(fn)
    lno = 0
    for ln in f:
        lno += 1
        for ltext, is_regular in LICENSE_TEXT.items():
            ix = ln.find(ltext)
            if ix >= 0:
                found = lno
                break
            if found is not None:
                break
        if lno > LICENSE_MAX_LINE:
            break
    if False:
        if found is not None:
            print("%s: found at line %u" % (fn, found))
    return found is not None


def check_all_sources_licensed(dir):
    """
    Scan a directory recursively, and check that all source files embed the license text.
    """
    n_files = 0
    n_unlicensed = 0
    for root, dirs, files in os.walk(dir):
        for f in files:
            fn = os.path.join(root, f)   
            if fn_is_source(fn):
                n_files += 1
                if not fn_is_licensed(fn):
                    n_unlicensed += 1
                    print("%s: not licensed" % fn)
    return n_unlicensed


if __name__ == "__main__":
    sys.exit(check_all_sources_licensed(os.path.dirname(os.path.realpath(__file__))) > 0)

