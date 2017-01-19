# CoreSight Access Library - Demonstration and example builds
# 
# This makefile builds the demos for the CS Access Library 
#
# Default builds the standard release versions, which build into a common ../bin/rel directory
#
# to build debug add DEBUG=1 to the make command line
#
# e.g. to build the standard debug versions: 
# make DEBUG=1 
#  
# to build the csprofile example with halting debug sampling option active (v7 cores only),
# add DBG_HALT=1 to the command line.

# default settings
CC=gcc
CFLAGS=-Wall -Werror=implicit-function-declaration -Wno-switch -fno-omit-frame-pointer

# extra per example specific options
CFLAGS_EX=

# directories
CS_LIB_DIR = ../lib/rel
BUILD_DIR=./rel
BIN_DIR=../bin/rel


# build options
ifeq ($(DEBUG),1)
CFLAGS+= -O0 -DDEBUG -g
CS_LIB_DIR = ../lib/dbg
BUILD_DIR=./dbg
BIN_DIR=../bin/dbg
else
CFLAGS+= -O2 -g
endif

# LPAE options
ifeq ($(LPAE),1)
CFLAGS+= -DLPAE
endif

# 64 bit VAs
ifeq ($(VA64),1)
CFLAGS+= -DCS_VA64BIT
endif


# set the include paths - for the CS Access library API
INCS=   -I. \
		-I../include


# build rules for the executables
$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) $(CFLAGS_EX) $(INCS) -c $< -o $@

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

csls: bin_dir $(CSLS_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(BIN_DIR)/Makefile
	$(CC) -o $(BIN_DIR)/$@ $(CSLS_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a 

#  **** build the tracedemo program
CSTD_SRC=   tracedemo.c \
			cs_demo_known_boards.c

CSTD_OBJS=$(addprefix $(BUILD_DIR)/,$(CSTD_SRC:%.c=%.o))

tracedemo: bin_dir $(CSTD_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a $(BIN_DIR)/Makefile
	$(CC) -o $(BIN_DIR)/$@ $(CSTD_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a 


#  **** build the topology generator utility
TOPOGEN_SRC=topogen.c cs_demo_known_boards.c cs_topology_detect.c cs_topology_print.c

topogen: $(TOPOGEN_SRC) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a $(BIN_DIR)/Makefile
	$(CC) $(CFLAGS) $(INCS) -o $@ $(TOPOGEN_SRC) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a

#  **** build the trace_cti_stop program
CSTDCTI_SRC=tracedemo_cti_stop.c \
			cs_demo_known_boards.c

CSTDCTI_OBJS=$(addprefix $(BUILD_DIR)/,$(CSTDCTI_SRC:%.c=%.o))

trace_cti_stop: bin_dir $(CSTDCTI_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a $(BIN_DIR)/Makefile
	$(CC) -o $(BIN_DIR)/$@ $(CSTDCTI_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a 

#  **** build the traceprofile program
CSTP_SRC=   csprofile.c tns.c \
			cs_demo_known_boards.c

CSTP_OBJS=$(addprefix $(BUILD_DIR)/,$(CSTP_SRC:%.c=%.o))

# build with risky halting debug sampling options...
ifeq ($(DBG_HALT),1)
PROF_LIBNAME=$(LIB_NAME)_dbghlt
PROF_CFLAGS=-DUSING_V7_DBG_HALT
else
PROF_LIBNAME=$(LIB_NAME)
PROF_CFLAGS=
endif

csprofile: CFLAGS_EX=$(PROF_CFLAGS) -UNDEBUG
csprofile: bin_dir $(CSTP_OBJS) $(CS_LIB_DIR)/lib$(PROF_LIBNAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a $(BIN_DIR)/Makefile
	$(CC) -o $(BIN_DIR)/$@ $(CSTP_OBJS) $(CS_LIB_DIR)/lib$(PROF_LIBNAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a -lrt -lpthread

#  **** build the ETM/PTM config print demo
CSETM_SRC=  cs_etm_config_demo.c \
			cs_demo_known_boards.c

CSETM_OBJS=$(addprefix $(BUILD_DIR)/,$(CSETM_SRC:%.c=%.o))

etmdemo: bin_dir $(CSETM_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a $(BIN_DIR)/Makefile
	$(CC) -o $(BIN_DIR)/$@ $(CSETM_OBJS) $(CS_LIB_DIR)/lib$(LIB_NAME).a $(CS_LIB_DIR)/lib$(LIB_NAME_UTIL).a


# copy the snapshot makefile
$(BIN_DIR)/Makefile:
	cp Makefile.snapshot $(BIN_DIR)/Makefile

# clean all object files and libraries
.PHONY: clean
clean: clean_objs
	rm -fr $(BIN_DIR)/etmdemo
	rm -fr $(BIN_DIR)/csls
	rm -fr $(BIN_DIR)/tracedemo
	rm -fr $(BIN_DIR)/csprofile

.PHONY: clean_objs
clean_objs:
	rm -fr $(CSLS_OBJS)
	rm -fr $(CSTD_OBJS)
	rm -fr $(CSTP_OBJS)
	rm -fr $(CSETM_OBJS)
	rm -fr $(CSTDCTI_OBJS)

