#############################################################################
#  CoreSight Access Library
#
#  Copyright (C) ARM Limited, 2017. All rights reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at#
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#############################################################################
# Makefile for python module of CS Access library
#

####################################
# tool settings - python module build without using python build utilites
CC=gcc

# gcc flags - these match those used by python 2.6 build utilities.
#           - tune according to your python
CFLAGS= -pthread -fno-strict-aliasing -DNDEBUG -g -fwrapv -O3 -Wall -Wstrict-prototypes -fPIC 

# set to local python installation for build without using python build utils

## python includes 
PYTHON_INC_DIR=/arm/tools/python/python/2.6.5/rhe5-x86_64/include/python2.6/

## python library - leave PYTHON_LIB_LINK empty if not linking to python library (python version dependent)
PYTHON_LIB_DIR=/arm/tools/python/python/2.6.5/rhe5-x86_64/lib
PYTHON_LIB_NAME=python2.6
PYTHON_LIB_LINK=-L$(PYTHON_LIB_DIR) -l$(PYTHON_LIB_NAME)

####################################


# cs-access directories 
SRC_DIR=../source
LIB_DIR=../lib/rel
INC_DIR=../include
DEMO_INC_DIR=../demos


#  the source files - list for dependency resolution to automatically rebuild the lib
#  from this makefile if needed.

CSSRC=  $(SRC_DIR)/cs_init_manage.c \
	$(SRC_DIR)/cs_debug_sample.c \
	$(SRC_DIR)/cs_pmu.c \
	$(SRC_DIR)/cs_access_cmnfns.c \
	$(SRC_DIR)/cs_access_cmnfns.h \
	$(SRC_DIR)/cs_cti_ect.c \
	$(SRC_DIR)/cs_etm.c \
	$(SRC_DIR)/cs_reg_access.c \
	$(SRC_DIR)/cs_sw_stim.c \
	$(SRC_DIR)/cs_topology.c \
	$(SRC_DIR)/cs_trace_sink.c \
	$(SRC_DIR)/cs_trace_source.c

CSINCS= $(INC_DIR)/csaccess.h \
		$(INC_DIR)/cs_cti_ect.h \
		$(INC_DIR)/cs_debug_sample.h \
		$(INC_DIR)/cs_etm.h \
		$(INC_DIR)/cs_etm_types.h \
		$(INC_DIR)/cs_pmu.h \
		$(INC_DIR)/cs_reg_access.h \
		$(INC_DIR)/cs_sw_stim.h \
		$(INC_DIR)/cs_topology.h \
		$(INC_DIR)/cs_trace_sink.h \
		$(INC_DIR)/cs_trace_source.h \
		$(INC_DIR)/csregisters.h \
		$(INC_DIR)/csregistration.h

####################################
#
# Python module
#
# You will likely need "swig" and "python-dev"
#

# use swig and python to build the extension
.PHONY: swig
swig: csaccess.i setup.py $(CSINCS) $(LIB_DIR)/libcsaccess.so
	python setup.py build_ext --inplace


# build python module from outside of python itself
.PHONY: py_so
py_so:  _csaccess.so

csaccess_wrap.c: $(CSINCS)
	swig -python -I$(INC_DIR) csaccess.i

_csaccess.so:  csaccess_wrap.c $(LIB_DIR)/libcsaccess.so
	mkdir -p build
	$(CC) $(CFLAGS) -I$(PYTHON_INC_DIR) -I$(INC_DIR) -I$(DEMO_INC_DIR) -c csaccess_wrap.c -o build/csaccess_wrap.o
	$(CC) -pthread -shared build/csaccess_wrap.o -L$(LIB_DIR) -lcsaccess $(PYTHON_LIB_LINK) -o $@ 


# create rule to rebuild the library 
$(LIB_DIR)/libcsaccess.so: $(CSSRC) $(CSINCS)
	cd ../build && make

# clean up the module
.PHONY: clean
clean:
	rm -fr build
	rm -f _csaccess.so
	rm -f csaccess_wrap.c
	rm -f csaccess.py

