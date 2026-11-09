CC ?= cc
PKG_CONFIG ?= pkg-config
TARGET := tls_reference_client
SRC := src/tls_reference_client.c

# OpenSSL is intentionally kept separate from the distribution copy.
# The default matches the recommended side-by-side installation used by the
# reference-client platform. Override on the make command line if needed:
#   make OPENSSL_PREFIX=/opt/openssl-3.5.x
OPENSSL_PREFIX ?= /opt/openssl-3.5.7
OPENSSL_MIN_VERSION ?= 3.5.0

# The recommended OpenSSL build uses --libdir=lib. OPENSSL_PKGCONFIG_DIR can
# still be overridden explicitly for another installation layout.
OPENSSL_PKGCONFIG_DIR ?= $(firstword $(wildcard \
	$(OPENSSL_PREFIX)/lib/pkgconfig \
	$(OPENSSL_PREFIX)/lib64/pkgconfig))
ifeq ($(strip $(OPENSSL_PKGCONFIG_DIR)),)
OPENSSL_PKGCONFIG_DIR := $(OPENSSL_PREFIX)/lib/pkgconfig
endif

# Use PKG_CONFIG_LIBDIR rather than only PKG_CONFIG_PATH so pkg-config cannot
# silently fall back to the distribution OpenSSL installation.
OPENSSL_PKG_ENV := PKG_CONFIG_PATH= PKG_CONFIG_LIBDIR=$(OPENSSL_PKGCONFIG_DIR)
OPENSSL_VERSION := $(shell $(OPENSSL_PKG_ENV) $(PKG_CONFIG) --modversion openssl 2>/dev/null)
OPENSSL_CFLAGS := $(shell $(OPENSSL_PKG_ENV) $(PKG_CONFIG) --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell $(OPENSSL_PKG_ENV) $(PKG_CONFIG) --libs openssl 2>/dev/null)
OPENSSL_LIBDIR := $(shell $(OPENSSL_PKG_ENV) $(PKG_CONFIG) --variable=libdir openssl 2>/dev/null)
OPENSSL_PC_PREFIX := $(shell $(OPENSSL_PKG_ENV) $(PKG_CONFIG) --variable=prefix openssl 2>/dev/null)

# If pkg-config could not resolve the requested installation, keep the linker
# flag syntactically valid; check-openssl will fail before compilation.
ifeq ($(strip $(OPENSSL_LIBDIR)),)
OPENSSL_LIBDIR := $(OPENSSL_PREFIX)/lib
endif

GIT_COMMIT := $(shell git rev-parse --verify HEAD 2>/dev/null || printf unknown)

CPPFLAGS += -DCLIENT_GIT_COMMIT=\"$(GIT_COMMIT)\"
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror $(OPENSSL_CFLAGS)
LDFLAGS += -Wl,-rpath,$(OPENSSL_LIBDIR)
LDLIBS += $(OPENSSL_LIBS)

.PHONY: all clean check smoke check-openssl openssl-info

all: check-openssl $(TARGET)

check-openssl:
	@command -v "$(PKG_CONFIG)" >/dev/null 2>&1 || { \
		echo "ERROR: pkg-config not found (PKG_CONFIG=$(PKG_CONFIG))." >&2; \
		exit 1; \
	}
	@test -f "$(OPENSSL_PKGCONFIG_DIR)/openssl.pc" || { \
		echo "ERROR: $(OPENSSL_PKGCONFIG_DIR)/openssl.pc not found." >&2; \
		echo "Requested OpenSSL prefix: $(OPENSSL_PREFIX)" >&2; \
		echo "If OpenSSL uses another layout, set OPENSSL_PKGCONFIG_DIR explicitly." >&2; \
		exit 1; \
	}
	@$(OPENSSL_PKG_ENV) $(PKG_CONFIG) --exists openssl || { \
		echo "ERROR: pkg-config cannot resolve OpenSSL from $(OPENSSL_PKGCONFIG_DIR)." >&2; \
		exit 1; \
	}
	@$(OPENSSL_PKG_ENV) $(PKG_CONFIG) --atleast-version=$(OPENSSL_MIN_VERSION) openssl || { \
		echo "ERROR: OpenSSL >= $(OPENSSL_MIN_VERSION) is required; found $(OPENSSL_VERSION)." >&2; \
		exit 1; \
	}
	@test "$(OPENSSL_PC_PREFIX)" = "$(OPENSSL_PREFIX)" || { \
		echo "ERROR: openssl.pc resolves prefix '$(OPENSSL_PC_PREFIX)', expected '$(OPENSSL_PREFIX)'." >&2; \
		echo "Refusing to fall back to another OpenSSL installation." >&2; \
		exit 1; \
	}
	@test -d "$(OPENSSL_LIBDIR)" || { \
		echo "ERROR: OpenSSL library directory not found: $(OPENSSL_LIBDIR)" >&2; \
		exit 1; \
	}

openssl-info: check-openssl
	@printf '%-24s %s\n' "OpenSSL prefix:" "$(OPENSSL_PREFIX)"
	@printf '%-24s %s\n' "OpenSSL version:" "$(OPENSSL_VERSION)"
	@printf '%-24s %s\n' "pkg-config directory:" "$(OPENSSL_PKGCONFIG_DIR)"
	@printf '%-24s %s\n' "OpenSSL library dir:" "$(OPENSSL_LIBDIR)"
	@printf '%-24s %s\n' "OpenSSL CFLAGS:" "$(OPENSSL_CFLAGS)"
	@printf '%-24s %s\n' "OpenSSL LIBS:" "$(OPENSSL_LIBS)"

$(TARGET): $(SRC) | check-openssl
	@echo "Building $(TARGET) against OpenSSL $(OPENSSL_VERSION) from $(OPENSSL_PREFIX)"
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

check: all
	./$(TARGET) --help >/dev/null
	@ssl_path="$$(ldd ./$(TARGET) | awk '/libssl\.so/{print $$3; exit}')"; \
	crypto_path="$$(ldd ./$(TARGET) | awk '/libcrypto\.so/{print $$3; exit}')"; \
	case "$$ssl_path" in "$(OPENSSL_LIBDIR)"/*) ;; \
		*) echo "ERROR: $(TARGET) resolves libssl outside $(OPENSSL_LIBDIR): $$ssl_path" >&2; exit 1 ;; esac; \
	case "$$crypto_path" in "$(OPENSSL_LIBDIR)"/*) ;; \
		*) echo "ERROR: $(TARGET) resolves libcrypto outside $(OPENSSL_LIBDIR): $$crypto_path" >&2; exit 1 ;; esac; \
	printf '%-24s %s\n' "Resolved libssl:" "$$ssl_path"; \
	printf '%-24s %s\n' "Resolved libcrypto:" "$$crypto_path"

smoke: all
	OPENSSL_PREFIX="$(OPENSSL_PREFIX)" \
	OPENSSL_LIBDIR="$(OPENSSL_LIBDIR)" \
	OPENSSL_BIN="$(OPENSSL_PREFIX)/bin/openssl" \
		bash ./tests/local_openssl_smoke.sh

clean:
	rm -f $(TARGET)
