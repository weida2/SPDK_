#  SPDX-License-Identifier: BSD-3-Clause
#

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../..)
$(info SPDK_ROOT_DIR is $(SPDK_ROOT_DIR))
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk
include $(SPDK_ROOT_DIR)/mk/spdk.modules.mk

APP = test

C_SRCS := test.c

SPDK_LIB_LIST = $(ALL_MODULES_LIST) event event_bdev

include $(SPDK_ROOT_DIR)/mk/spdk.app.mk
