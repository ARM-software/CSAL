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
# Master makefile - calls to build library and demos.
#

# setup architecture & x-compile
include makefile-arch.inc

# export architecture info
export $(ARCH)
export $(PLAT_ARCH)

###### library build targets  ##################################

#### builders....

.PHONY: all
all: start lib demos

start:
	@echo "CoreSight Access Library - building libraries and demos"
	@echo "Using ARCH=$(ARCH), CROSS_COMPILE=$(CROSS_COMPILE)"
	@echo "MAKEFLAGS = $(MAKEFLAGS)"
	@echo ""

.PHONY: lib
lib:
	cd ./build && make

.PHONY: demos
demos:
	cd ./demos && make

.PHONY: experimental
experimental:
	cd ./experimental && make

.PHONY: python
python:
	cd ./python && make

#### cleaners...

.PHONY: clean
clean: lib_clean demos_clean

.PHONY: lib_clean
lib_clean:
	cd ./build && make clean

.PHONY: demos_clean
demos_clean:
	cd ./demos && make clean

.PHONY: experimental_clean
experimental_clean:
	cd ./experimental && make clean

.PHONY: python_clean
python_clean:
	cd ./python && make clean


###### library maintenance operaions ##################################
# CS Lib API Documentation
.PHONY: docs
docs: doxygen-cfg.txt 
	doxygen doxygen-cfg.txt 

# create a source distribution file.
libsources = ./source ./include ./build/makefile ./build/readme_buildlib.md
demosources = ./demos/*.c ./demos/*.h ./demos/makefile ./demos/readme_demos.md ./demos/*.py ./demos/juno_demo_setup/*.* ./demos/makefile.snapshot
pythonsources = ./python/*.py ./python/makefile ./python/readme_python.md ./python/csaccess.i
exprsources = ./experimental/*.c ./experimental/*.h ./experimental/*.py ./experimental/makefile
rootsources = doxygen-cfg.txt README.md LICENSE makefile *.py makefile-arch.inc make-info.txt
sources = $(libsources) $(demosources) $(pythonsources) $(rootsources)
distfile = csaccess.tar.gz

.PHONY: dist
dist: $(distfile)

$(distfile): $(sources)
	tar -czf $@ $^
	tar -tzf $@

.PHONY: help
help:
	@cat make-info.txt
