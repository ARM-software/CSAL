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
# This makefile builds the demos for the CS Access Library 
#
# Default builds the standard release versions, which build into a common ../bin/<arch>/rel directory
#
# to build debug add DEBUG=1 to the make command line
#
# e.g. to build the standard debug versions: 
# make DEBUG=1 
#  
# to build the csprofile example with halting debug sampling option active (v7 cores only),
# add DBG_HALT=1 to the command line.

# setup architecture & x-compile
include ../makefile-arch.inc

# default settings
CC=$(CROSS_COMPILE)gcc
CFLAGS=-Wall -Werror=implicit-function-declaration -Wno-switch -fno-omit-frame-pointer

# extra per example specific options
CFLAGS_EX=

# directories
CS_LIB_DIR = ../lib/$(ARCH)/rel
BUILD_DIR=./rel-$(ARCH)
BIN_DIR=../bin/$(ARCH)/rel


# build options
ifeq ($(DEBUG),1)
CFLAGS+= -O0 -DDEBUG -g
CS_LIB_DIR = ../lib/$(ARCH)/dbg
BUILD_DIR=./dbg-$(ARCH)
BIN_DIR=../bin/$(ARCH)/dbg
else
CFLAGS+= -O2 -g
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

# set the include paths - for the CS Access library API
INCS=   -I. \
		-I../include


# build rules for the executables
$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) $(CFLAGS_EX) $(INCS) -c -MMD -MP  $< -o $@


# library dependencies
LIB_NAME=csaccess
LIB_INCL=-L $(CS_LIB_DIR)
LIB_NAME_UTIL=csacc_util

# build all demos
.PHONY: all
all: csls tracedemo trace_cti_stop etmdemo 

# (csprofile will not build on snowball demo target so removed from all)

# create the executable output and build dirs
.PHONY: bin_dir
bin_dir:
	@mkdir -p  $(BIN_DIR)
	@mkdir -p  $(BUILD_DIR)
	@echo "building to $(BIN_DIR)"

# **** build the library, if required
$(CS_LIB_DIR)/lib$(LIB_NAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a:
	@$(MAKE) -C ../build

# **** build the CSLS demo
CSLS_SRC=csls.c

CSLS_OBJS=$(addprefix $(BUILD_DIR)/,$(CSLS_SRC:%.c=%.o))
CSLS_DEPS=$(CSLS_OBJS:.o=.d)

csls: bin_dir $(CSLS_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(BIN_DIR)/makefile
	$(CC) -o $(BIN_DIR)/$@ $(CSLS_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a 

#  **** build the tracedemo program
CSTD_SRC=   tracedemo.c \
			cs_demo_known_boards.c

CSTD_OBJS=$(addprefix $(BUILD_DIR)/,$(CSTD_SRC:%.c=%.o))
CSTD_DEPS=$(CSTD_OBJS:.o=.d)

tracedemo: bin_dir $(CSTD_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a $(BIN_DIR)/makefile
	$(CC) -o $(BIN_DIR)/$@ $(CSTD_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a 

#  **** build the trace_cti_stop program
CSTDCTI_SRC=tracedemo_cti_stop.c \
			cs_demo_known_boards.c

CSTDCTI_OBJS=$(addprefix $(BUILD_DIR)/,$(CSTDCTI_SRC:%.c=%.o))
CSTDCTI_DEPS=$(CSTDCTI_OBJS:.o=.d)

trace_cti_stop: bin_dir $(CSTDCTI_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a $(BIN_DIR)/makefile
	$(CC) -o $(BIN_DIR)/$@ $(CSTDCTI_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a 

#  **** build the ETM/PTM config print demo
CSETM_SRC=  cs_etm_config_demo.c \
			cs_demo_known_boards.c

CSETM_OBJS=$(addprefix $(BUILD_DIR)/,$(CSETM_SRC:%.c=%.o))
CSETM_DEPS=$(CSETM_OBJS:.o=.d)


etmdemo: bin_dir $(CSETM_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a $(BIN_DIR)/makefile
	$(CC) -o $(BIN_DIR)/$@ $(CSETM_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a


# include dependencies
-include $(CSLS_DEPS)
-include $(CSTD_DEPS)
-include $(CSTDCTI_DEPS)
-include $(CSETM_DEPS)

# copy the snapshot makefile
$(BIN_DIR)/makefile:
	cp makefile.snapshot $(BIN_DIR)/makefile

# clean all object files and libraries
.PHONY: clean
clean: clean_objs
	rm -fr $(BIN_DIR)/etmdemo
	rm -fr $(BIN_DIR)/csls
	rm -fr $(BIN_DIR)/tracedemo
	rm -fr $(BIN_DIR)/trace_cti_stop
	rm -fr $(BIN_DIR)/makefile

.PHONY: clean_objs
clean_objs:
	rm -fr $(CSLS_OBJS) $(CSLS_DEPS)
	rm -fr $(CSTD_OBJS) $(CSTD_DEPS)
	rm -fr $(CSETM_OBJS) $(CSTDCTI_DEPS)
	rm -fr $(CSTDCTI_OBJS) $(CSETM_DEPS)

