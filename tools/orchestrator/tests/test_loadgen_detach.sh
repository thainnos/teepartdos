#!/bin/bash
set -euo pipefail

REQUIRE_ROOT=0
if [[ ${1:-} == --require-root ]]; then REQUIRE_ROOT=1; shift; fi
[[ $# -eq 0 ]] || { echo "Usage: $0 [--require-root]" >&2; exit 2; }
if [[ $(id -u) -ne 0 ]]; then
  if [[ $REQUIRE_ROOT -eq 1 ]]; then echo "ERROR: load-generator detached lifecycle mock requires root" >&2; exit 2; fi
  echo "load-generator detached lifecycle: SKIP (requires root; run 'sudo make test-loadgen-detach-root')"
  exit 0
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LO_MTU=$(cat /sys/class/net/lo/mtu)
TMP=$(mktemp -d)
RUN_ID=loadgen-detach
cleanup() {
  TEE_TLS_LOADGEN_AGENT_CONFIG="$TMP/load.conf" \
    "$ROOT/remote/tee-tls-loadgen-agent" run-stop "$RUN_ID" 1 >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

PCI=""; DRIVER=""
for dev in /sys/bus/pci/devices/*; do
  if [[ -L $dev/driver ]]; then
    PCI=$(basename "$dev")
    DRIVER=$(basename "$(readlink -f "$dev/driver")")
    break
  fi
done
[[ -n $PCI && -n $DRIVER ]]

cat >"$TMP/mock-generator" <<'EOF_GENERATOR'
#!/bin/bash
set -euo pipefail
if [[ ${1:-} == --version ]]; then
  echo "tls_loadgen 0.1.5 git=0123456789ab"
  exit 0
fi
if [[ ${1:-} == --help ]]; then
  cat <<'HELP'
--config --backend --scenario --workload --mode --rate --duration --max-inflight
--record-connections --target --port --output-dir --run-id --fstack-conf
HELP
  exit 0
fi
output=""; run_id=""; scenario=""; workload=""; mode=""; backend=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) output=$2; shift 2 ;;
    --run-id) run_id=$2; shift 2 ;;
    --scenario) scenario=$2; shift 2 ;;
    --workload) workload=$2; shift 2 ;;
    --mode) mode=$2; shift 2 ;;
    --backend) backend=$2; shift 2 ;;
    --*) shift 2 ;;
    *) shift ;;
  esac
done
mkdir -p "$output/tls_loadgen_${scenario}_${workload}_${mode}_${run_id}"
out="$output/tls_loadgen_${scenario}_${workload}_${mode}_${run_id}"
printf '{"run_id":"%s","scenario":"%s","workload":"%s","mode":"%s","backend":"%s"}\n' \
  "$run_id" "$scenario" "$workload" "$mode" "$backend" >"$out/generator.metadata.json"
printf 'local_capacity_drop_total\n0\n' >"$out/generator_stats.csv"
trap 'exit 0' TERM INT
while :; do sleep 1; done
EOF_GENERATOR
chmod 0755 "$TMP/mock-generator"

cat >"$TMP/generator.conf" <<EOF_CONFIG
target.address=127.0.0.1
target.port=4433
target.mac=00:00:00:00:00:00
network.source_address=127.0.0.1
network.interface=lo
network.mtu=$LO_MTU
network.netmask=255.255.255.0
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
EOF_CONFIG

cat >"$TMP/load.conf" <<EOF_CONFIG
RUN_OWNER=$(id -un)
RUN_GROUP=auto
EXPECTED_GENERATOR_VERSION=0.1.5
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
SCHEDULED_EXEC=$ROOT/orchestration/scheduled_exec.py
IPERF3=/bin/true
SERVER_NAME=test
PAYLOAD_SIZE=1024
MTU=$LO_MTU
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
EOF_CONFIG

START_NS=$(python3 - <<'PY'
import time
print(time.time_ns() + 300_000_000)
PY
)
START=$(date +%s%N)
OUTPUT=$(timeout 3 env TEE_TLS_LOADGEN_AGENT_CONFIG="$TMP/load.conf" \
  "$ROOT/remote/tee-tls-loadgen-agent" run-start \
  "$RUN_ID" A full-handshake benign posix 1 30 64 8 "$START_NS")
END=$(date +%s%N)
ELAPSED_MS=$(( (END - START) / 1000000 ))
[[ $ELAPSED_MS -lt 3000 ]]
grep -q '"state":"submitted"' <<<"$OUTPUT"

STATUS=""
for _ in $(seq 1 80); do
  STATUS=$(TEE_TLS_LOADGEN_AGENT_CONFIG="$TMP/load.conf" \
    "$ROOT/remote/tee-tls-loadgen-agent" run-status "$RUN_ID")
  grep -q '"state": "running"' <<<"$STATUS" && break
  sleep 0.1
done
grep -q '"state": "running"' <<<"$STATUS"

STOP=$(TEE_TLS_LOADGEN_AGENT_CONFIG="$TMP/load.conf" \
  "$ROOT/remote/tee-tls-loadgen-agent" run-stop "$RUN_ID" 3)
grep -q '"state":"stopped"' <<<"$STOP"

for _ in $(seq 1 50); do
  STATUS=$(TEE_TLS_LOADGEN_AGENT_CONFIG="$TMP/load.conf" \
    "$ROOT/remote/tee-tls-loadgen-agent" run-status "$RUN_ID")
  grep -q '"state": "finished"' <<<"$STATUS" && break
  sleep 0.1
done
grep -q '"state": "finished"' <<<"$STATUS"
echo $$ >"$TMP/load-runs/$RUN_ID/generator.pid"
ALREADY=$(TEE_TLS_LOADGEN_AGENT_CONFIG="$TMP/load.conf" \
  "$ROOT/remote/tee-tls-loadgen-agent" run-stop "$RUN_ID" 1)
grep -q '"state":"already_finished"' <<<"$ALREADY"

echo "load-generator detached lifecycle: PASS (${ELAPSED_MS} ms submission)"
