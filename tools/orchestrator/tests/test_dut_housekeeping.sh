#!/bin/sh
set -eu
ROOT=${1:-.}
AGENT="$ROOT/remote/tee-tls-dut-agent"
[ -x "$AGENT" ] || { echo "missing executable agent: $AGENT" >&2; exit 2; }
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$TMP/runs/finished" "$TMP/runs/active"
printf '0\n' > "$TMP/runs/finished/server.exit_code"
printf 'evidence\n' > "$TMP/runs/finished/server.log"
printf '%s\n' "$$" > "$TMP/runs/active/server.pid"
cat > "$TMP/dut.conf" <<EOF
RUN_ROOT=$TMP/runs
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
TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" "$AGENT" delete-run finished > "$TMP/out"
grep -q '^STATE=deleted$' "$TMP/out"
[ ! -e "$TMP/runs/finished" ]
set +e
TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" "$AGENT" delete-run active > "$TMP/active.out" 2> "$TMP/active.err"
rc=$?
set -e
[ "$rc" -ne 0 ]
[ -d "$TMP/runs/active" ]
grep -q 'run_still_active' "$TMP/active.err"
TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" "$AGENT" delete-run absent > "$TMP/missing.out"
grep -q '^STATE=missing$' "$TMP/missing.out"
echo "DUT housekeeping agent test: PASS"
