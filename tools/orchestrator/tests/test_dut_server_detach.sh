#!/bin/bash
set -euo pipefail

REQUIRE_ROOT=0
if [[ ${1:-} == "--require-root" ]]; then
  REQUIRE_ROOT=1
  shift
fi
if [[ $# -ne 0 ]]; then
  echo "Usage: $0 [--require-root]" >&2
  exit 2
fi

if [[ $(id -u) -ne 0 ]]; then
  if [[ $REQUIRE_ROOT -eq 1 ]]; then
    echo "ERROR: DUT detached server lifecycle test requires root." >&2
    echo "Run: sudo make test-dut-server-detach-root" >&2
    exit 2
  fi
  echo "DUT detached server lifecycle: SKIP (requires root; run 'sudo make test-dut-server-detach-root')"
  exit 0
fi

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
RUN_ID=detach-test
cleanup() {
  TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" \
    "$ROOT/remote/tee-tls-dut-agent" server-stop "$RUN_ID" 2 >/dev/null 2>&1 || true
  TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" \
    "$ROOT/remote/tee-tls-dut-agent" iperf-stop iperf-detach tcp-forward 1 >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

CPU=$(python3 - <<'PY'
import os
print(min(os.sched_getaffinity(0)))
PY
)

cat >"$TMP/mock-server" <<'EOF_SERVER'
#!/bin/sh
set -eu
log_file=""
scenario=A
while [ "$#" -gt 0 ]; do
  case "$1" in
    --log-file) log_file=$2; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$log_file" ]
printf 'manifest scenario=%s test=detached\n' "$scenario" >>"$log_file"
trap 'exit 0' TERM INT
while :; do sleep 1; done
EOF_SERVER
chmod 0755 "$TMP/mock-server"

cat >"$TMP/mock-iperf3" <<'EOF_IPERF'
#!/bin/sh
trap 'exit 0' TERM INT
printf '{"start":{},"end":{}}\n'
while :; do sleep 1; done
EOF_IPERF
chmod 0755 "$TMP/mock-iperf3"

cat >"$TMP/dut.conf" <<EOF_CONF
RUN_ROOT=$TMP/dut-runs
DATA_INTERFACE=lo
DATA_ADDRESS=127.0.0.1
CONTROL_INTERFACE=lo
CONTROL_ADDRESS=127.0.0.1
TLS_PORT=4433
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
EOF_CONF

START=$(date +%s%N)
START_OUTPUT=$(timeout 3 env \
  TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" \
  "$ROOT/remote/tee-tls-dut-agent" server-start "$RUN_ID" A pilot-debug)
END=$(date +%s%N)
ELAPSED_MS=$(( (END - START) / 1000000 ))
[[ $ELAPSED_MS -lt 3000 ]]
grep -q '^RUN_DIR=' <<<"$START_OUTPUT"
grep -q '^WRAPPER_PID=' <<<"$START_OUTPUT"

STATUS=""
READY=0
for _ in $(seq 1 80); do
  STATUS=$(TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" \
    "$ROOT/remote/tee-tls-dut-agent" server-status "$RUN_ID")
  if grep -q '^STATE=running$' <<<"$STATUS" \
      && grep -q '^MANIFEST_READY=1$' <<<"$STATUS" \
      && grep -q "^AFFINITY=$CPU$" <<<"$STATUS"; then
    READY=1
    break
  fi
  if grep -q '^STATE=exited$' <<<"$STATUS"; then
    break
  fi
  sleep 0.1
done

if [[ $READY -ne 1 ]]; then
  echo "DUT detached server lifecycle did not become ready." >&2
  printf '%s\n' "$STATUS" >&2
  for file in wrapper.stderr.log server.stderr.log startup.error wrapper.exit_code server.exit_code; do
    path="$TMP/dut-runs/$RUN_ID/$file"
    if [[ -s $path ]]; then
      echo "--- $file ---" >&2
      cat "$path" >&2
    fi
  done
  exit 1
fi

TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" \
  "$ROOT/remote/tee-tls-dut-agent" server-stop "$RUN_ID" 5 >/dev/null

for _ in $(seq 1 30); do
  STATUS=$(TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" \
    "$ROOT/remote/tee-tls-dut-agent" server-status "$RUN_ID")
  grep -q '^STATE=exited$' <<<"$STATUS" && break
  sleep 0.1
done
grep -q '^STATE=exited$' <<<"$STATUS"
[[ $(cat "$TMP/dut-runs/$RUN_ID/server.exit_code") == 0 ]]
[[ $(cat "$TMP/dut-runs/$RUN_ID/wrapper.exit_code") == 0 ]]
# Exit files must win over a reused PID. The agent must not signal this test
# shell merely because its PID was written into a stale server.pid file.
echo $$ >"$TMP/dut-runs/$RUN_ID/server.pid"
STALE_STATUS=$(TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" \
  "$ROOT/remote/tee-tls-dut-agent" server-status "$RUN_ID")
grep -q '^STATE=exited$' <<<"$STALE_STATUS"
STALE_STOP=$(TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" \
  "$ROOT/remote/tee-tls-dut-agent" server-stop "$RUN_ID" 1)
grep -q '^STATE=already_exited$' <<<"$STALE_STOP"

IPERF_ID=iperf-detach
IPERF_START=$(date +%s%N)
IPERF_OUTPUT=$(timeout 3 env TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" \
  "$ROOT/remote/tee-tls-dut-agent" iperf-start "$IPERF_ID" tcp-forward 5201)
IPERF_END=$(date +%s%N)
IPERF_ELAPSED_MS=$(( (IPERF_END - IPERF_START) / 1000000 ))
[[ $IPERF_ELAPSED_MS -lt 3000 ]]
grep -q '^RUN_DIR=' <<<"$IPERF_OUTPUT"
IPERF_STATUS=$(TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" \
  "$ROOT/remote/tee-tls-dut-agent" iperf-status "$IPERF_ID" tcp-forward)
grep -q '^STATE=running$' <<<"$IPERF_STATUS"
TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" \
  "$ROOT/remote/tee-tls-dut-agent" iperf-stop "$IPERF_ID" tcp-forward 2 >/dev/null
for _ in $(seq 1 30); do
  IPERF_STATUS=$(TEE_TLS_DUT_AGENT_CONFIG="$TMP/dut.conf" \
    "$ROOT/remote/tee-tls-dut-agent" iperf-status "$IPERF_ID" tcp-forward)
  grep -q '^STATE=exited$' <<<"$IPERF_STATUS" && break
  sleep 0.1
done
grep -q '^STATE=exited$' <<<"$IPERF_STATUS"
[[ $(cat "$TMP/dut-runs/$IPERF_ID/iperf/tcp-forward/server.exit_code") == 0 ]]

echo "DUT detached server/iperf lifecycle: PASS (${ELAPSED_MS}/${IPERF_ELAPSED_MS} ms submission)"
