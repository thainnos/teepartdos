# Common host build rules for the A-E D4 SDK platform.
# The including Makefile must define TARGET and HOST_SRCS.

CC      ?= gcc
SYSROOT ?= $(OECORE_TARGET_SYSROOT)

CPPFLAGS ?=
CPPFLAGS += -D_POSIX_C_SOURCE=200809L $(HOST_CPPFLAGS)

CFLAGS ?= -O2 -g -Wall -Wextra -Wpedantic -std=c11
CFLAGS += -Werror=implicit-function-declaration \
          -Werror=incompatible-pointer-types \
          -Wcast-function-type

LDFLAGS ?=
LDLIBS  ?= -lmbedtls -lmbedx509 -lmbedcrypto
ifeq ($(REQUIRE_TEEC),1)
LDLIBS += -lteec
endif

MBEDTLS_CONFIG := $(SYSROOT)/usr/include/mbedtls/mbedtls_config.h
MBEDTLS_SSL_HEADER := $(SYSROOT)/usr/include/mbedtls/ssl.h

ifneq ($(strip $(SYSROOT)),)
CPPFLAGS += --sysroot=$(SYSROOT) -I$(SYSROOT)/usr/include
LDFLAGS  += --sysroot=$(SYSROOT) -L$(SYSROOT)/usr/lib
endif

.PHONY: host check-host-env print-config clean-host

host: $(TARGET)

check-host-env:
	@test -n "$(OECORE_TARGET_SYSROOT)" || { \
		echo "ERROR: OECORE_TARGET_SYSROOT is not set. Source ./init.sh first."; \
		exit 1; \
	}
	@test -d "$(SYSROOT)" || { \
		echo "ERROR: target sysroot not found: $(SYSROOT)"; \
		exit 1; \
	}
	@test -f "$(MBEDTLS_CONFIG)" || { \
		echo "ERROR: Mbed TLS configuration not found: $(MBEDTLS_CONFIG)"; \
		exit 1; \
	}
	@test -f "$(MBEDTLS_SSL_HEADER)" || { \
		echo "ERROR: Mbed TLS SSL header not found: $(MBEDTLS_SSL_HEADER)"; \
		exit 1; \
	}
	@for macro in \
		MBEDTLS_SSL_PROTO_TLS1_3 \
		MBEDTLS_SSL_ASYNC_PRIVATE \
		MBEDTLS_SSL_TLS1_3_SERVER_EXTERNAL_SIGNING \
		MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND \
		MBEDTLS_SSL_SRV_C \
		MBEDTLS_X509_CRT_PARSE_C; do \
		grep -Eq "^[[:space:]]*#define[[:space:]]+$$macro([[:space:]]|$$)" \
			"$(MBEDTLS_CONFIG)" || { \
			echo "ERROR: common D4 SDK does not enable $$macro."; \
			exit 1; \
		}; \
	done
	@grep -Eq '^[[:space:]]*#define[[:space:]]+MBEDTLS_SSL_L1_PATCH_VERSION[[:space:]]+1([[:space:]]|$$)' \
		"$(MBEDTLS_CONFIG)" || { \
		echo "ERROR: SDK is not Mbed TLS L1 patch version 1."; \
		exit 1; \
	}
	@grep -Eq '^[[:space:]]*#define[[:space:]]+MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND_API_VERSION[[:space:]]+5u([[:space:]]|$$)' \
		"$(MBEDTLS_SSL_HEADER)" || { \
		echo "ERROR: SDK does not expose D4 crypto-backend API version 5."; \
		exit 1; \
	}
	@machine="$$( $(CC) -dumpmachine 2>/dev/null )"; \
	case "$$machine" in \
		aarch64*) ;; \
		*) echo "ERROR: compiler target is '$$machine', expected aarch64."; exit 1 ;; \
	esac

$(TARGET): $(HOST_SRCS) | check-host-env
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(HOST_SRCS) $(LDFLAGS) $(LDLIBS)

print-config: check-host-env
	@echo "CC=$(CC)"
	@echo "SYSROOT=$(SYSROOT)"
	@echo "TARGET=$(TARGET)"
	@echo "HOST_SRCS=$(HOST_SRCS)"
	@echo "TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)"
	@echo "TA_CROSS_COMPILE=$(TA_CROSS_COMPILE)"
	@echo "compiler_target=$$( $(CC) -dumpmachine )"

clean-host:
	rm -f $(TARGET)
