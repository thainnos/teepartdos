# Build with:
#   make -C ta TA_DEV_KIT_DIR=/path/to/export-ta_arm64

BINARY=159e414d-c5b1-4652-8ec0-5d42beb160a9

ifeq ($(TA_DEV_KIT_DIR),)
$(error TA_DEV_KIT_DIR is not set. Example: make -C ta TA_DEV_KIT_DIR=/path/to/export-ta_arm64)
endif

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
