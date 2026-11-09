#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat >"$TMP/dut.conf" <<EOF_CONF
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
EOF_CONF

DUT_CLOCK=$(env -i \
  TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" \
  PATH=/bin:/usr/bin \
  "$ROOT/remote/tee-tls-dut-agent" clock-ns)
[[ $DUT_CLOCK =~ ^[0-9]{16,20}$ ]]
DUT_PROBES=$(printf '0\n1\n' | env -i \
  TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" \
  PATH=/bin:/usr/bin \
  "$ROOT/remote/tee-tls-dut-agent" clock-probe)
grep -Eq '^READY$' <<<"$DUT_PROBES"
grep -Eq '^0 [0-9]{16,20}$' <<<"$DUT_PROBES"
grep -Eq '^1 [0-9]{16,20}$' <<<"$DUT_PROBES"

cat >"$TMP/loadgen.conf" <<EOF_CONF
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
EOF_CONF

LOAD_CLOCK=$(env -i \
  TEE_TLS_LOADGEN_AGENT_CONFIG="$TMP/loadgen.conf" \
  PATH=/bin:/usr/bin \
  "$ROOT/remote/tee-tls-loadgen-agent" clock-ns)
[[ $LOAD_CLOCK =~ ^[0-9]{16,20}$ ]]
LOAD_PROBES=$(printf '0\n1\n' | env -i \
  TEE_TLS_LOADGEN_AGENT_CONFIG="$TMP/loadgen.conf" \
  PATH=/bin:/usr/bin \
  "$ROOT/remote/tee-tls-loadgen-agent" clock-probe)
grep -Eq '^READY$' <<<"$LOAD_PROBES"
grep -Eq '^0 [0-9]{16,20}$' <<<"$LOAD_PROBES"
grep -Eq '^1 [0-9]{16,20}$' <<<"$LOAD_PROBES"

echo "remote agent environment: PASS"
