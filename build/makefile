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
# 
# This makefile builds the CS-Access library for both static and dynamic linked versions. 
#
# Default builds the standard release versions, linux application space, arm 32 arch
#
# to build debug add DEBUG=1 to the make command line
# to build in the v7 debug halt extensions add DBG_HALT=1 to the make command line
# to build for baremetal add BAREMETAL=1 to the make command line
#
# e.g. to build the standard debug versions: 
# make DEBUG=1 
#  

# setup architecture & x-compile
include ../makefile-arch.inc

# default settings - allow for cross compile of library 
CC=$(CROSS_COMPILE)gcc
CFLAGS=-Wall -Wno-switch -Werror

LIB_DIR = ../lib/$(ARCH)/rel
LIB_DIR_BM=../lib/$(ARCH)/rel_bm
LIB_NAME=csaccess
LIB_NAME_UTIL=csacc_util
BUILD_DIR=./rel-$(ARCH)
BUILD_DIR_BM=./rel_bm-$(ARCH)

# build options
ifeq ($(DEBUG),1)
CFLAGS+= -O0 -DDEBUG -g
LIB_DIR = ../lib/$(ARCH)/dbg
LIB_DIR_BM = ../lib/$(ARCH)/dbg_bm
BUILD_DIR=./dbg-$(ARCH)
BUILD_DIR_BM=./dbg_bm-$(ARCH)
else
CFLAGS+= -O2 -DNDEBUG
endif

# platform options
ifeq ($(BAREMETAL),1)
CFLAGS+= -DBAREMETAL
LIB_DIR=$(LIB_DIR_BM)
BUILD_DIR=$(BUILD_DIR_BM)
endif

ifeq ($(DBG_HALT),1)
LIB_NAME=csaccess_dbghlt
CFLAGS+= -DUSING_V7_DBG_HALT
CSSRC_HALT=cs_debug_halt.c
endif

# check if building on/for aarch64
ifeq ($(ARCH),arm64)
CFLAGS+= -DCS_VA64BIT
ifneq ($(NOLPAE),1)
CFLAGS+= -DLPAE
endif

else
# arm 32 - might want lpae
ifeq ($(LPAE),1)
CFLAGS+= -DLPAE
endif

endif

#disable diagnostic printing
ifeq ($(NO_DIAG),1)
CFLAGS+= -DDIAG=0
endif

#disable checks 
ifeq ($(NO_CHECK),1)
CFLAGS+= -DCHECK=0
endif

# ensure that the compiler can find the library source
vpath %.c ../source

#  the source files
CSSRC=  cs_init_manage.c \
		cs_debug_sample.c \
		cs_pmu.c \
		cs_access_cmnfns.c \
		cs_cti_ect.c \
		cs_etm.c \
		cs_etm_v4.c \
		cs_memap.c \
		cs_reg_access.c \
		cs_sw_stim.c \
		cs_topology.c \
		cs_trace_sink.c \
		cs_trace_source.c \
		cs_ts_gen.c

# add in the extra for halting debug - blank if not in use 
CSSRC+=$(CSSRC_HALT)

#
# For development use only, we can enable redirecting physical
# memory references to a remote target over a network connection.
#
ifeq ($(DEVMEMD),1)
CSSRC+=cs_stub_devmemd.c
CFLAGS+=-DUSE_DEVMEMD
endif

#
# Enable support for indirecting device accesses via MEM-AP.
#
ifeq ($(MEMAP),1)
CFLAGS+=-DCSAL_MEMAP
endif

CSUTILSRC=	cs_trace_metadata.c \
		cs_util_create_snapshot.c \
		csregistration.c


# set the include paths
INCS=   -I. \
		-I../include


# build rules for the .a lib
$(BUILD_DIR)/a/%.o: %.c
	$(CC) $(CFLAGS) $(INCS) -MMD -MP -c $< -o $@
A_OBJS=$(addprefix $(BUILD_DIR)/a/,$(CSSRC:%.c=%.o))	
A_OBJS_UTIL=$(addprefix $(BUILD_DIR)/a/,$(CSUTILSRC:%.c=%.o))
A_DEPS=$(A_OBJS:.o=.d)
A_DEPS_UTIL=$(A_OBJS_UTIL:.o=.d)

# build rules for the .so lib
$(BUILD_DIR)/so/%.o: %.c
	$(CC) $(CFLAGS) -fPIC $(INCS) -MMD -MP -c $< -o $@	
SO_OBJS=$(addprefix $(BUILD_DIR)/so/,$(CSSRC:%.c=%.o))	
SO_OBJS_UTIL=$(addprefix $(BUILD_DIR)/so/,$(CSUTILSRC:%.c=%.o))
SO_DEPS=$(SO_OBJS:.o=.d)
SO_DEPS_UTIL=$(SO_OBJS_UTIL:.o=.d)

# build both lib types
.PHONY: all
all: start lib_a lib_so 

# start msg
start:
	@echo "CSAL libraries: Building ARCH=$(ARCH), CROSS_COMPILE=$(CROSS_COMPILE)"
	@echo "MAKEFLAGS = $(MAKEFLAGS)"
	@echo ""


# create the lib output and build dirs
.PHONY: lib_dir
lib_dir:
	@mkdir -p  $(LIB_DIR)
	@mkdir -p  $(BUILD_DIR)/a
	@mkdir -p  $(BUILD_DIR)/so	
	@echo "building to $(LIB_DIR)"

# create the static link libraries
.PHONY: lib_a
lib_a: lib_dir lib$(LIB_NAME).a lib$(LIB_NAME_UTIL).a

lib$(LIB_NAME).a:  $(A_OBJS)
	ar cr $(LIB_DIR)/lib$(LIB_NAME).a $(A_OBJS)

lib$(LIB_NAME_UTIL).a: $(A_OBJS_UTIL)
	ar cr $(LIB_DIR)/lib$(LIB_NAME_UTIL).a $(A_OBJS_UTIL)

# create the dynamic link libraries
.PHONY: lib_so
lib_so: lib_dir lib$(LIB_NAME).so lib$(LIB_NAME_UTIL).so 

lib$(LIB_NAME).so: $(SO_OBJS)
	$(CC) -shared -o $(LIB_DIR)/lib$(LIB_NAME).so $(SO_OBJS)

lib$(LIB_NAME_UTIL).so: $(SO_OBJS_UTIL)
	$(CC) -shared -o $(LIB_DIR)/lib$(LIB_NAME_UTIL).so $(SO_OBJS_UTIL)

# include generated dependency files
-include $(A_DEPS)
-include $(A_DEPS_UTIL)
-include $(SO_DEPS)
-include $(SO_DEPS_UTIL)


# clean all object files and libraries
.PHONY: clean
clean: clean_objs
	rm -fr $(LIB_DIR)/*.so
	rm -fr $(LIB_DIR)/*.a

#
# Clean all objects in build directories, even ones not selected by whatever
# make options were passed to make when we ran "make clean".
#
.PHONY: clean_objs
clean_objs:
	#rm -fr $(A_OBJS) $(A_DEPS)
	#rm -fr $(A_OBJS_UTIL) $(A_DEPS_UTIL)
	#rm -fr $(SO_OBJS) $(SO_DEPS)
	#rm -fr $(SO_OBJS_UTIL) $(SO_DEPS_UTIL)
	rm -fr $(BUILD_DIR)/a/*.o $(BUILD_DIR)/a/*.d
	rm -fr $(BUILD_DIR)/so/*.o $(BUILD_DIR)/so/*.d

