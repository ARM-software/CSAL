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

from distutils.core import setup, Extension

"""
Script to setup the csaccess library as a Python module.
Called via `make swig' or `python setup.py build_ext --inplace'
"""

setup(ext_modules=[
    Extension("_csaccess",
              sources=[ "csaccess.i"],
              include_dirs=[ "../include", "../demos"],
              library_dirs=[ "../lib/rel"],
              libraries=[ "csaccess" ],
              swig_opts=['-I../include']
              ),
])
