#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
cleanup() {
  [[ -n ${CANCEL_PID:-} ]] && kill -KILL "$CANCEL_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

START=$(( $(date +%s%N) + 1000000000 ))
python3 "$ROOT/orchestration/scheduled_exec.py" \
  --scheduled-start-ns "$START" \
  --status "$TMP/status.json" \
  --stdout "$TMP/stdout.log" \
  --stderr "$TMP/stderr.log" \
  --pid-file "$TMP/pid" \
  -- /bin/sh -c 'printf scheduled-exec-pass'
grep -q 'scheduled-exec-pass' "$TMP/stdout.log"
python3 - "$TMP/status.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f: s=json.load(f)
assert s["state"] == "finished"
assert s["exit_code"] == 0
assert abs(s["start_lag_ns"]) < 1_000_000_000
PY

# Cancellation while the wrapper is still waiting must prevent the command
# from starting. Earlier versions installed a signal handler that did nothing
# before CHILD existed, allowing a cancelled campaign process to start later.
CANCEL_START=$(( $(date +%s%N) + 10000000000 ))
python3 "$ROOT/orchestration/scheduled_exec.py" \
  --scheduled-start-ns "$CANCEL_START" \
  --status "$TMP/cancel-status.json" \
  --stdout "$TMP/cancel-stdout.log" \
  --stderr "$TMP/cancel-stderr.log" \
  --pid-file "$TMP/cancel-pid" \
  -- /bin/sh -c 'echo should-not-run' &
CANCEL_PID=$!
for _ in $(seq 1 250); do
  [[ -s $TMP/cancel-status.json ]] && break
  if ! kill -0 "$CANCEL_PID" 2>/dev/null; then
    break
  fi
  sleep 0.02
done
if [[ ! -s $TMP/cancel-status.json ]]; then
  echo "ERROR: scheduled wrapper did not publish waiting status" >&2
  set +e
  kill -KILL "$CANCEL_PID" 2>/dev/null
  wait "$CANCEL_PID" 2>/dev/null
  set -e
  CANCEL_PID=""
  exit 1
fi
kill -TERM "$CANCEL_PID"
set +e
wait "$CANCEL_PID"
RC=$?
set -e
CANCEL_PID=""
[[ $RC -eq 143 ]]
python3 - "$TMP/cancel-status.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f: s=json.load(f)
assert s["state"] == "cancelled_before_start", s
assert s["exit_code"] == 143, s
PY
[[ ! -s $TMP/cancel-stdout.log ]]

# A missing executable must still produce a terminal status rather than leave
# the orchestration poller waiting on a stale "waiting" document.
MISSING_START=$(( $(date +%s%N) + 100000000 ))
set +e
python3 "$ROOT/orchestration/scheduled_exec.py" \
  --scheduled-start-ns "$MISSING_START" \
  --status "$TMP/missing-status.json" \
  --stdout "$TMP/missing-stdout.log" \
  --stderr "$TMP/missing-stderr.log" \
  --pid-file "$TMP/missing-pid" \
  -- "$TMP/does-not-exist"
MISSING_RC=$?
set -e
[[ $MISSING_RC -eq 127 ]]
python3 - "$TMP/missing-status.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f: s=json.load(f)
assert s["state"] == "failed_before_start", s
assert s["exit_code"] == 127, s
assert "FileNotFoundError" in s["error"], s
PY
[[ ! -e $TMP/missing-pid ]]

echo "scheduled exec: PASS"
