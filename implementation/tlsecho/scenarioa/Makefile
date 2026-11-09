TARGET := tls_echo_server_scenario_a
HOST_SRCS := host/tls_echo_server_scenario_a.c
HOST_CPPFLAGS := -Ihost
REQUIRE_TEEC := 0

include ../common/host.mk

.PHONY: all clean
all: host
clean: clean-host
