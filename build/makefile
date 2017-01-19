# CoreSight Access Library
# 
# This makefile builds the CS-Access library for both static and dynamic linked versions. 
#
# Default builds the standard release versions, linux application space
#
# to build debug add DEBUG=1 to the make command line
# to build in the v7 debug halt extensions add DBG_HALT=1 to the make command line
# to build for baremetal add BAREMETAL=1 to the make command line
#
# e.g. to build the standard debug versions: 
# make DEBUG=1 
#  

# default settings
CC=gcc
CFLAGS=-Wall -Wno-switch

LIB_DIR = ../lib/rel
LIB_DIR_BM=../lib/rel_bm
LIB_NAME=csaccess
LIB_NAME_UTIL=csacc_util
BUILD_DIR=./rel
BUILD_DIR_BM=./rel_bm

# build options
ifeq ($(DEBUG),1)
CFLAGS+= -O0 -DDEBUG -g
LIB_DIR = ../lib/dbg
LIB_DIR_BM = ../lib/dbg_bm
BUILD_DIR=./dbg
BUILD_DIR_BM=./dbg_bm
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

# LPAE options
ifeq ($(LPAE),1)
CFLAGS+= -DLPAE
endif

# 64 bit VAs
ifeq ($(VA64),1)
CFLAGS+= -DCS_VA64BIT
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
		cs_reg_access.c \
		cs_sw_stim.c \
		cs_topology.c \
		cs_trace_sink.c \
		cs_trace_source.c \
		cs_ts_gen.c

# add in the extra for halting debug - blank if not in use 
CSSRC+=$(CSSRC_HALT)


CSUTILSRC=	cs_trace_metadata.c \
		cs_util_create_snapshot.c \
		csregistration.c


# set the include paths
INCS=   -I. \
		-I../include


# build rules for the .a lib
$(BUILD_DIR)/a/%.o: %.c
	$(CC) $(CFLAGS) $(INCS) -c $< -o $@
A_OBJS=$(addprefix $(BUILD_DIR)/a/,$(CSSRC:%.c=%.o))	
A_OBJS_UTIL=$(addprefix $(BUILD_DIR)/a/,$(CSUTILSRC:%.c=%.o))

# build rules for the .so lib
$(BUILD_DIR)/so/%.o: %.c
	$(CC) $(CFLAGS) -fPIC $(INCS) -c $< -o $@	
SO_OBJS=$(addprefix $(BUILD_DIR)/so/,$(CSSRC:%.c=%.o))	
SO_OBJS_UTIL=$(addprefix $(BUILD_DIR)/so/,$(CSUTILSRC:%.c=%.o))

# build both lib types
.PHONY: all
all: lib_a lib_so 

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


# clean all object files and libraries
.PHONY: clean
clean: clean_objs
	rm -fr $(LIB_DIR)/*.so
	rm -fr $(LIB_DIR)/*.a

.PHONY: clean_objs
clean_objs:
	rm -fr $(A_OBJS)
	rm -fr $(A_OBJS_UTIL)
	rm -fr $(SO_OBJS)
	rm -fr $(SO_OBJS_UTIL)

###### library maintenance operaions ##################################

# CS Lib API Documentation
docs: ../doxygen-cfg.txt 
	cd ../. && doxygen doxygen-cfg.txt 


# create a distribution file.
libsources = ../source ../include ../build/Makefile ../build/readme_build.md
demosources = ../demos/*.c ../demos/*.h ../demos/Makefile ../demos/readme_demos.md
pythonsources = ../python/*.py ../python/Makefile ../python/csaccess_py.c ../python/csaccess.i 
sources = $(libsources) $(demosources) $(pythonsources)
distfile = csaccess.tar.gz

.PHONY: dist
dist: $(distfile)

# readme.html

$(distfile): $(sources) ../doxygen-cfg.txt ../README.md ../LICENCE
	tar -czf $@ $^
	tar -tzf $@

