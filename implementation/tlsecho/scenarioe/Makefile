TARGET := tls_echo_server_scenario_e
HOST_SRCS := host/tls_echo_server_scenario_e.c \
             host/tee_km_client.c \
             host/tee_sign_client.c \
             host/tee_tls_d_client.c
HOST_CPPFLAGS := -Ihost -Iinclude
REQUIRE_TEEC := 1

TA_DEV_KIT_DIR ?=
TA_CROSS_COMPILE ?= $(if $(TARGET_PREFIX),$(TARGET_PREFIX),aarch64-poky-linux-)

include ../common/host.mk

.PHONY: all full tas ta-b ta-c ta-d check-ta-env clean clean-tas
all: host
full: host tas

check-ta-env:
	@test -n "$(TA_DEV_KIT_DIR)" && test -d "$(TA_DEV_KIT_DIR)" || { \
		echo "ERROR: TA_DEV_KIT_DIR is missing."; exit 1; \
	}

tas: ta-b ta-c ta-d

define build_ta
	$(MAKE) -C $(1) \
		TA_DEV_KIT_DIR="$(TA_DEV_KIT_DIR)" \
		TA_CROSS_COMPILE="$(TA_CROSS_COMPILE)" \
		CROSS_COMPILE="$(TA_CROSS_COMPILE)" \
		CROSS_COMPILE_ta_arm64="$(TA_CROSS_COMPILE)" \
		LIBGCC_LOCATE_CFLAGS="--sysroot=$(OECORE_TARGET_SYSROOT)" \
		CPPFLAGS= CFLAGS= CXXFLAGS= LDFLAGS= LDLIBS=
endef

ta-b: check-ta-env
	$(call build_ta,../scenariob/ta)

ta-c: check-ta-env
	$(call build_ta,../scenarioc/ta)

ta-d: check-ta-env
	$(call build_ta,../scenariod/ta)

clean: clean-host

clean-tas: check-ta-env
	$(MAKE) -C ../scenariob/ta clean TA_DEV_KIT_DIR="$(TA_DEV_KIT_DIR)" || true
	$(MAKE) -C ../scenarioc/ta clean TA_DEV_KIT_DIR="$(TA_DEV_KIT_DIR)" || true
	$(MAKE) -C ../scenariod/ta clean TA_DEV_KIT_DIR="$(TA_DEV_KIT_DIR)" || true
