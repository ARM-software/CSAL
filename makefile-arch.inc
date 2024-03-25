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
# Architecture and cross compile tests for makefiles
#
# There are three architectures involved:
#
#   PLAT_ARCH    - the architecture we are on now: the build platform;
#                  when cross-compiling, this could be anything
#
#   ARCH         - the architecture of the CSAL binaries:
#                  this will be arm or arm64, except in the case that
#                  DEVMEMD=1 when it could be anything
#
#   target arch  - this will be an Arm architecture of some kind,
#                  and will be the same as ARCH except when DEVMEMD=1
#

# figure platform arch
ifndef PLAT_ARCH
PLAT_ARCH := $(shell uname -m 2>/dev/null || echo not)
endif

ifneq ($(DEVMEMD),1)
ifeq ($(PLAT_ARCH),$(filter $(PLAT_ARCH), x86 x86_64 ))
ifeq ($(CROSS_COMPILE), )
$(error no CROSS_COMPILE set on x86 platform)
endif
ifeq ($(ARCH), )
$(error no arm target ARCH set on x86 platform)
endif
endif
endif

# set build arch - default to arm
ifndef ARCH
ifneq ($(DEVMEMD),1)
ifeq ($(PLAT_ARCH),$(filter $(PLAT_ARCH), aarch64 arm64 ))
ARCH=arm64
else
ARCH=arm
endif
else
ARCH=$(PLAT_ARCH)
endif
endif
