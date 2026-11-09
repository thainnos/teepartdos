SHELL := /bin/bash

CC ?= cc
OPENSSL_PREFIX ?=
FSTACK_PATH ?= /opt/f-stack-v1.25
BUILD_DIR ?= build
BIN_DIR ?= bin

TLSGEN_GIT_COMMIT := $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
TLSGEN_GIT_DIRTY := $(shell if git rev-parse --is-inside-work-tree >/dev/null 2>&1 && test -n "$$(git status --porcelain --untracked-files=no)"; then echo -dirty; fi)
BASE_CPPFLAGS := -Isrc -DTLSGEN_GIT_COMMIT=\"$(TLSGEN_GIT_COMMIT)$(TLSGEN_GIT_DIRTY)\"
BASE_CFLAGS := -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Werror
BASE_LDLIBS := -pthread

ifeq ($(strip $(OPENSSL_PREFIX)),)
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl)
OPENSSL_LIBS := $(shell pkg-config --libs openssl)
OPENSSL_VERSION := $(shell pkg-config --modversion openssl 2>/dev/null)
else
OPENSSL_PCDIR := $(OPENSSL_PREFIX)/lib/pkgconfig
OPENSSL_CFLAGS := $(shell PKG_CONFIG_LIBDIR='$(OPENSSL_PCDIR)' pkg-config --cflags openssl)
OPENSSL_LIBS := $(shell PKG_CONFIG_LIBDIR='$(OPENSSL_PCDIR)' pkg-config --libs openssl) -Wl,-rpath,$(OPENSSL_PREFIX)/lib
OPENSSL_VERSION := $(shell PKG_CONFIG_LIBDIR='$(OPENSSL_PCDIR)' pkg-config --modversion openssl 2>/dev/null)
endif

COMMON_SRCS := \
	src/main.c \
	src/app.c \
	src/config.c \
	src/util.c \
	src/session_pool.c \
	src/openssl_net_bio.c \
	src/tls_engine.c \
	src/backend_posix.c \
	src/backend_fstack.c

POSIX_BIN := $(BIN_DIR)/tls_loadgen_posix
FSTACK_BIN := $(BIN_DIR)/tls_loadgen_fstack

.PHONY: all posix fstack clean check openssl-info fstack-info smoke-posix scheduler-regression-posix external-tool-check

all: posix

posix: preflight-openssl $(POSIX_BIN)

$(POSIX_BIN): $(COMMON_SRCS) src/tls_loadgen.h | $(BIN_DIR)
	@echo "Building $@ against OpenSSL $(OPENSSL_VERSION)"
	$(CC) $(BASE_CPPFLAGS) $(OPENSSL_CFLAGS) $(BASE_CFLAGS) \
		-o $@ $(COMMON_SRCS) $(OPENSSL_LIBS) $(BASE_LDLIBS)

fstack: preflight-openssl preflight-fstack $(FSTACK_BIN)

$(FSTACK_BIN): $(COMMON_SRCS) src/tls_loadgen.h | $(BIN_DIR)
	@echo "Building $@ against F-Stack at $(FSTACK_PATH) and OpenSSL $(OPENSSL_VERSION)"
	FSTACK_DPDK_PCDIR="$$(find '$(FSTACK_PATH)' -type d -path '*/lib/pkgconfig' -print -quit)"; \
	test -n "$$FSTACK_DPDK_PCDIR" || { echo "Unable to locate bundled DPDK pkg-config directory under $(FSTACK_PATH)" >&2; exit 1; }; \
	DPDK_CFLAGS="$$(PKG_CONFIG_PATH="$$FSTACK_DPDK_PCDIR$${PKG_CONFIG_PATH:+:$${PKG_CONFIG_PATH}}" pkg-config --cflags libdpdk)"; \
	DPDK_LIBS="$$(PKG_CONFIG_PATH="$$FSTACK_DPDK_PCDIR$${PKG_CONFIG_PATH:+:$${PKG_CONFIG_PATH}}" pkg-config --static --libs libdpdk)"; \
	if [[ " $$DPDK_LIBS " == *" -lsystemd "* ]] && ! pkg-config --exists libsystemd; then \
		echo "Bundled DPDK requires libsystemd development files; install Ubuntu package libsystemd-dev." >&2; \
		exit 1; \
	fi; \
	$(CC) $(BASE_CPPFLAGS) -DHAVE_FSTACK -I'$(FSTACK_PATH)/lib' $(OPENSSL_CFLAGS) $$DPDK_CFLAGS $(BASE_CFLAGS) \
		-o $@ $(COMMON_SRCS) -L'$(FSTACK_PATH)/lib' \
		-Wl,--whole-archive -lfstack -Wl,--no-whole-archive \
		$$DPDK_LIBS $(OPENSSL_LIBS) -lrt -lm -ldl -pthread -lnuma

$(BIN_DIR):
	mkdir -p $@

preflight-openssl:
	@test -n "$(OPENSSL_VERSION)" || { echo "OpenSSL development metadata not found. Set OPENSSL_PREFIX=/opt/openssl-3.5.7 or install libssl-dev." >&2; exit 1; }
	@python3 -c 'import sys; v="$(OPENSSL_VERSION)".split("."); sys.exit(0 if tuple(map(int,v[:2])) >= (3,5) else 1)' || { echo "OpenSSL >= 3.5 required; found $(OPENSSL_VERSION)" >&2; exit 1; }

preflight-fstack:
	@test -f '$(FSTACK_PATH)/lib/libfstack.a' || { echo "Missing $(FSTACK_PATH)/lib/libfstack.a; run scripts/install_fstack.sh" >&2; exit 1; }
	@test -f '$(FSTACK_PATH)/lib/ff_api.h' || { echo "Missing $(FSTACK_PATH)/lib/ff_api.h" >&2; exit 1; }

openssl-info: preflight-openssl
	@echo "OpenSSL version: $(OPENSSL_VERSION)"
	@echo "OpenSSL prefix:  $(if $(OPENSSL_PREFIX),$(OPENSSL_PREFIX),system pkg-config)"
	@echo "CFLAGS:          $(OPENSSL_CFLAGS)"
	@echo "LIBS:            $(OPENSSL_LIBS)"

fstack-info:
	@echo "F-Stack path: $(FSTACK_PATH)"
	@if test -d '$(FSTACK_PATH)/.git'; then git -C '$(FSTACK_PATH)' describe --tags --always --dirty; else echo "not installed as a Git checkout"; fi

check: posix
	@$(POSIX_BIN) --help >/dev/null
	@$(POSIX_BIN) --version | grep -Eq '^tls_loadgen 0[.]1[.]5 git=[0-9a-f]{12}$$' || { \
		echo "Generator version identity is unknown or dirty; commit tracked source changes before building." >&2; \
		exit 1; \
	}
	@echo "POSIX binary CLI/version check: PASS"
	@if command -v ldd >/dev/null; then ldd $(POSIX_BIN) | grep -E 'libssl|libcrypto'; fi

smoke-posix: posix
	OPENSSL_PREFIX='$(OPENSSL_PREFIX)' bash tests/local_posix_smoke.sh

scheduler-regression-posix: posix
	bash tests/record_scheduler_stall.sh

external-tool-check:
	python3 tests/test_external_tool_runner.py

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR) tests/.tmp tests/.scheduler-stall results
