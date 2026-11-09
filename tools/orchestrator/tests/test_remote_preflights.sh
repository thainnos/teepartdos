#!/bin/bash
set -euo pipefail

REQUIRE_ROOT=0
if [[ ${1:-} == --require-root ]]; then REQUIRE_ROOT=1; shift; fi
[[ $# -eq 0 ]] || { echo "Usage: $0 [--require-root]" >&2; exit 2; }
if [[ $(id -u) -ne 0 ]]; then
  if [[ $REQUIRE_ROOT -eq 1 ]]; then echo "ERROR: remote preflight mock requires root" >&2; exit 2; fi
  echo "remote preflight mocks: SKIP (requires root; run 'sudo make test-remote-preflights-root')"
  exit 0
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
CPU=$(python3 - <<'PY'
import os
print(min(os.sched_getaffinity(0)))
PY
)
LO_MTU=$(cat /sys/class/net/lo/mtu)

cat >"$TMP/mock-server" <<'EOF'
#!/bin/sh
if [ "${1:-}" = --help ]; then
cat <<'HELP'
--bind-ip --port --cert --key --log-file --session-tickets --session-cache
--strict-cert-profile --log-mode --debug-level --max-payload --listen-backlog
--max-connections --handshake-timeout-ms --idle-timeout-ms --summary-interval-ms
--tee-derive-on-handshake --tee-selftest --ticket-debug-hashes --external-signing
--async-debug-events --crypto-backend --tee-ticket-protection
HELP
exit 0
fi
exit 0
EOF
chmod 0755 "$TMP/mock-server"
cat >"$TMP/mock-iperf3" <<'EOF'
#!/bin/sh
if [ "${1:-}" = --help ]; then
  echo '--server --one-off --client --port --time --parallel --json --reverse --udp --bitrate'
fi
exit 0
EOF
chmod 0755 "$TMP/mock-iperf3"
cat >"$TMP/dut.conf" <<EOF
RUN_ROOT=$TMP/dut-runs
DATA_INTERFACE=lo
DATA_ADDRESS=127.0.0.1
CONTROL_INTERFACE=lo
CONTROL_ADDRESS=127.0.0.1
TLS_PORT=4433
MTU=$LO_MTU
SERVER_CPU=$CPU
SERVER_CERT=/dev/null
SERVER_KEY=/dev/null
IPERF3=$TMP/mock-iperf3
MAX_PAYLOAD=16384
LISTEN_BACKLOG=128
MAX_CONNECTIONS=256
HANDSHAKE_TIMEOUT_MS=30000
IDLE_TIMEOUT_MS=30000
SUMMARY_INTERVAL_MS=1000
SCENARIO_A_BINARY=$TMP/mock-server
SCENARIO_B_BINARY=$TMP/mock-server
SCENARIO_C_BINARY=$TMP/mock-server
SCENARIO_D_BINARY=$TMP/mock-server
SCENARIO_E_BINARY=$TMP/mock-server
EOF
DUT=$(TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" "$ROOT/remote/tee-tls-dut-agent" preflight)
grep -q '^ARCHIVE_METHOD=tar-stream$' <<<"$DUT"
grep -q '^FAILURES=0$' <<<"$DUT"
# TLS campaign preflight must not require iperf3 on a minimal Yocto image.
sed -i "s#^IPERF3=.*#IPERF3=$TMP/does-not-exist#" "$TMP/dut.conf"
DUT_NO_IPERF=$(TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" "$ROOT/remote/tee-tls-dut-agent" preflight)
grep -q '^FAILURES=0$' <<<"$DUT_NO_IPERF"
if TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" "$ROOT/remote/tee-tls-dut-agent" iperf-preflight >/dev/null 2>&1; then
  echo "iperf-preflight unexpectedly passed without iperf3" >&2
  exit 1
fi

PCI=""
DRIVER=""
for dev in /sys/bus/pci/devices/*; do
  if [[ -L $dev/driver ]]; then PCI=$(basename "$dev"); DRIVER=$(basename "$(readlink -f "$dev/driver")"); break; fi
done
[[ -n $PCI && -n $DRIVER ]]
cat >"$TMP/mock-generator" <<'EOF'
#!/bin/sh
if [ "${1:-}" = "--version" ]; then
    echo "tls_loadgen 0.1.5 git=0123456789ab"
    exit 0
fi
cat <<'HELP'
--config --backend --scenario --workload --mode --rate --duration --max-inflight
--record-connections --target --port --output-dir --run-id --fstack-conf
HELP
EOF
chmod 0755 "$TMP/mock-generator"
cat >"$TMP/generator.conf" <<EOF
target.address=127.0.0.1
target.port=4433
target.mac=00:00:00:00:00:00
network.source_address=127.0.0.1
network.interface=lo
network.mtu=$LO_MTU
network.netmask = 255.255.255.0 # parser-compatible spacing/comment
network.tcp_nodelay=true
tls.ca_file=/dev/null
tls.server_name=test
tls.verify_peer=true
tls.verify_hostname=false
tls.ciphersuite=TLS_AES_128_GCM_SHA256
tls.group=P-256
tls.signature_algorithm=ecdsa_secp256r1_sha256
payload.size=1024
run.max_release_burst=4096
run.drain_timeout_ms=10000
timeout.tcp_connect_ms=5000
timeout.tls_handshake_ms=5000
timeout.io_ms=5000
payload.pattern_hex=a5
full.echo_after_handshake=false
resumption.session_policy=reuse_seed
resumption.pool_size=32
resumption.wait_for_fresh_ticket=true
record.max_pending_releases=4096
record.reconnect=true
record.reconnect_backoff_ms=1000
output.stdout_progress=true
fstack.proc_id=0
EOF
cat >"$TMP/load.conf" <<EOF
RUN_OWNER=$(id -un)
RUN_GROUP=$(id -gn)
PROJECT_ROOT=$TMP
RUN_ROOT=$TMP/load-runs
DATA_INTERFACE=lo
DATA_ADDRESS=127.0.0.1
CONTROL_INTERFACE=lo
CONTROL_ADDRESS=127.0.0.1
PCI_ADDRESS=$PCI
KERNEL_DRIVER=$DRIVER
DUT_ADDRESS=127.0.0.1
DUT_MAC=00:00:00:00:00:00
TLS_PORT=4433
IPERF_PORT=5201
POSIX_BINARY=$TMP/mock-generator
FSTACK_BINARY=$TMP/mock-generator
GENERATOR_CONFIG=$TMP/generator.conf
FSTACK_CONFIG=/dev/null
CA_FILE=/dev/null
OPENSSL_LIB=/tmp
OPENSSL_MODULES=/tmp
SCHEDULED_EXEC=/bin/true
IPERF3=$TMP/mock-iperf3
SERVER_NAME=test
PAYLOAD_SIZE=1024
MTU=$LO_MTU
TLS_CIPHERSUITE=TLS_AES_128_GCM_SHA256
TLS_GROUP=P-256
TLS_SIGNATURE_ALGORITHM=ecdsa_secp256r1_sha256
EXPECTED_GENERATOR_VERSION=0.1.5
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
cp "$TMP/load.conf" "$TMP/load-missing-root.conf"
sed -i "s#^PROJECT_ROOT=.*#PROJECT_ROOT=$TMP/does-not-exist#" "$TMP/load-missing-root.conf"
set +e
MISSING_ROOT=$(TEE_TLS_LOADGEN_AGENT_CONFIG="$TMP/load-missing-root.conf" "$ROOT/remote/tee-tls-loadgen-agent" preflight posix 2>&1)
MISSING_ROOT_RC=$?
set -e
[[ $MISSING_ROOT_RC -ne 0 ]]
grep -q '^FAIL=project_root_unusable:' <<<"$MISSING_ROOT"

LOAD=$(TEE_TLS_LOADGEN_AGENT_CONFIG="$TMP/load.conf" "$ROOT/remote/tee-tls-loadgen-agent" preflight posix)
grep -q '^ARCHIVE_METHOD=tar-stream$' <<<"$LOAD"
grep -q '^FAILURES=0$' <<<"$LOAD"

sed -i 's/git=0123456789ab/git=unknown/' "$TMP/mock-generator"
set +e
UNKNOWN_ID=$(TEE_TLS_LOADGEN_AGENT_CONFIG="$TMP/load.conf" "$ROOT/remote/tee-tls-loadgen-agent" preflight posix 2>&1)
UNKNOWN_ID_RC=$?
set -e
[[ $UNKNOWN_ID_RC -ne 0 ]]
grep -q '^FAIL=generator_git_identity:' <<<"$UNKNOWN_ID"

echo "remote preflight mocks: PASS"
