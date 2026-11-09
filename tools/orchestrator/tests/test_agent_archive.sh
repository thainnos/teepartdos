#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/dut-runs/run1/state" "$TMP/load-runs/run1/output"
printf 'dut-log\n' >"$TMP/dut-runs/run1/server.log"
printf 'state\n' >"$TMP/dut-runs/run1/state/info.txt"
printf 'generator\n' >"$TMP/load-runs/run1/output/generator.log"

cat >"$TMP/dut.conf" <<EOF
RUN_ROOT=$TMP/dut-runs
DATA_INTERFACE=lo
DATA_ADDRESS=127.0.0.1
CONTROL_INTERFACE=lo
CONTROL_ADDRESS=127.0.0.1
TLS_PORT=4433
SERVER_CPU=0
SERVER_CERT=/dev/null
SERVER_KEY=/dev/null
IPERF3=/bin/true
MAX_PAYLOAD=16384
LISTEN_BACKLOG=128
MAX_CONNECTIONS=256
HANDSHAKE_TIMEOUT_MS=30000
IDLE_TIMEOUT_MS=30000
SUMMARY_INTERVAL_MS=1000
SCENARIO_A_BINARY=/bin/true
SCENARIO_B_BINARY=/bin/true
SCENARIO_C_BINARY=/bin/true
SCENARIO_D_BINARY=/bin/true
SCENARIO_E_BINARY=/bin/true
EOF
TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" "$ROOT/remote/tee-tls-dut-agent" archive-run run1 >"$TMP/dut.tar"
mkdir "$TMP/dut-out"
tar -C "$TMP/dut-out" -xf "$TMP/dut.tar"
grep -q '^dut-log$' "$TMP/dut-out/server.log"
grep -q '^state$' "$TMP/dut-out/state/info.txt"

cat >"$TMP/load.conf" <<EOF
RUN_OWNER=$(id -un)
RUN_GROUP=$(id -gn)
EXPECTED_GENERATOR_VERSION=0.1.5
PROJECT_ROOT=$TMP
RUN_ROOT=$TMP/load-runs
DATA_INTERFACE=lo
DATA_ADDRESS=127.0.0.1
CONTROL_INTERFACE=lo
CONTROL_ADDRESS=127.0.0.1
PCI_ADDRESS=0000:00:00.0
KERNEL_DRIVER=none
DUT_ADDRESS=127.0.0.1
DUT_MAC=00:00:00:00:00:00
TLS_PORT=4433
IPERF_PORT=5201
POSIX_BINARY=/bin/true
FSTACK_BINARY=/bin/true
GENERATOR_CONFIG=/dev/null
FSTACK_CONFIG=/dev/null
CA_FILE=/dev/null
OPENSSL_LIB=/tmp
OPENSSL_MODULES=/tmp
SCHEDULED_EXEC=/bin/true
IPERF3=/bin/true
SERVER_NAME=test
PAYLOAD_SIZE=1024
MTU=1500
TLS_CIPHERSUITE=TLS_AES_128_GCM_SHA256
TLS_GROUP=P-256
TLS_SIGNATURE_ALGORITHM=ecdsa_secp256r1_sha256
EXPECTED_NETWORK_NETMASK=255.255.255.0
EXPECTED_TCP_NODELAY=true
EXPECTED_MAX_RELEASE_BURST=4096
EXPECTED_DRAIN_TIMEOUT_MS=10000
EXPECTED_TCP_CONNECT_TIMEOUT_MS=5000
EXPECTED_TLS_HANDSHAKE_TIMEOUT_MS=5000
EXPECTED_IO_TIMEOUT_MS=5000
EXPECTED_PAYLOAD_PATTERN_HEX=a5
EXPECTED_FULL_ECHO_AFTER_HANDSHAKE=false
EXPECTED_RESUMPTION_POLICY=reuse_seed
EXPECTED_RESUMPTION_POOL_SIZE=32
EXPECTED_WAIT_FOR_FRESH_TICKET=true
EXPECTED_RECORD_MAX_PENDING_RELEASES=4096
EXPECTED_RECORD_RECONNECT=true
EXPECTED_RECORD_RECONNECT_BACKOFF_MS=1000
EXPECTED_STDOUT_PROGRESS=true
EXPECTED_FSTACK_PROC_ID=0
EOF
TEE_TLS_LOADGEN_AGENT_CONFIG="$TMP/load.conf" "$ROOT/remote/tee-tls-loadgen-agent" archive-run run1 >"$TMP/load.tar"
mkdir "$TMP/load-out"
tar -C "$TMP/load-out" -xf "$TMP/load.tar"
grep -q '^generator$' "$TMP/load-out/output/generator.log"

# The DUT is a minimal Yocto image. Where BusyBox is available in the test
# environment, verify that the agent-produced archive is readable by BusyBox tar.
if command -v busybox >/dev/null 2>&1 && busybox tar --help >/dev/null 2>&1; then
  mkdir "$TMP/dut-busybox-out"
  busybox tar -C "$TMP/dut-busybox-out" -xf "$TMP/dut.tar"
  grep -q '^dut-log$' "$TMP/dut-busybox-out/server.log"
fi

echo "remote agent archive stream: PASS"
