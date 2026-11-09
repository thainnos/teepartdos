TARGET := tls_echo_server_scenario_c
HOST_SRCS := host/tls_echo_server_scenario_c.c host/tee_sign_client.c
HOST_CPPFLAGS := -Ihost -Ita/include
REQUIRE_TEEC := 1

TA_DEV_KIT_DIR ?=
TA_CROSS_COMPILE ?= $(if $(TARGET_PREFIX),$(TARGET_PREFIX),aarch64-poky-linux-)

include ../common/host.mk

.PHONY: all ta check-ta-env clean
all: host ta

check-ta-env:
	@test -n "$(TA_DEV_KIT_DIR)" && test -d "$(TA_DEV_KIT_DIR)" || { \
		echo "ERROR: TA_DEV_KIT_DIR is missing."; exit 1; \
	}

ta: check-ta-env
	$(MAKE) -C ta \
		TA_DEV_KIT_DIR="$(TA_DEV_KIT_DIR)" \
		TA_CROSS_COMPILE="$(TA_CROSS_COMPILE)" \
		CROSS_COMPILE="$(TA_CROSS_COMPILE)" \
		CROSS_COMPILE_ta_arm64="$(TA_CROSS_COMPILE)" \
		LIBGCC_LOCATE_CFLAGS="--sysroot=$(OECORE_TARGET_SYSROOT)" \
		CPPFLAGS= CFLAGS= CXXFLAGS= LDFLAGS= LDLIBS=

clean: clean-host
	@if [ -n "$(TA_DEV_KIT_DIR)" ] && [ -d "$(TA_DEV_KIT_DIR)" ]; then \
		$(MAKE) -C ta clean TA_DEV_KIT_DIR="$(TA_DEV_KIT_DIR)" || true; \
	fi
