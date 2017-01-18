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
