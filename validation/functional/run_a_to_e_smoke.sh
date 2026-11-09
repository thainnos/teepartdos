#!/usr/bin/env bash
set -uo pipefail

BOARD_IP="${BOARD_IP:-192.0.2.150}"
PORT="${PORT:-4433}"
SSH_TARGET="${SSH_TARGET:-root@192.0.2.150}"
CA_FILE="${CA_FILE:-../../certificates/server.crt}"
REMOTE_CERT="${REMOTE_CERT:-/root/certs/server.crt}"
REMOTE_KEY="${REMOTE_KEY:-/root/certs/server.key}"
OUT_ROOT="${OUT_ROOT:-./common-smoke-results}"
DEBUG_LEVEL="${DEBUG_LEVEL:-2}"

for cmd in openssl timeout ssh grep date tee; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "ERROR: missing command: $cmd" >&2; exit 2;
    }
done
[[ -r "$CA_FILE" ]] || { echo "ERROR: unreadable CA file: $CA_FILE" >&2; exit 2; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$OUT_ROOT/a-to-e-$STAMP"
SUMMARY="$OUT_DIR/summary.txt"
mkdir -p "$OUT_DIR"
: >"$SUMMARY"
PASS=0
FAIL=0
record(){ printf '%s\n' "$*" | tee -a "$SUMMARY"; }
pass(){ PASS=$((PASS+1)); record "PASS  $*"; }
fail(){ FAIL=$((FAIL+1)); record "FAIL  $*"; }

run_one() {
    local letter="$1" dir="$2" binary="$3" extra="$4"
    local log="$dir/smoke-${letter}.log"
    local pidfile="$dir/smoke-${letter}.pid"
    local session="$OUT_DIR/${letter}.pem"
    local full="$OUT_DIR/${letter}-full.log"
    local resumed="$OUT_DIR/${letter}-resumed.log"

    ssh "$SSH_TARGET" "
        set -eu
        mkdir -p '$dir'
        : > '$log'
        nohup '$binary' \
          --bind-ip '$BOARD_IP' --port '$PORT' \
          --cert '$REMOTE_CERT' --key '$REMOTE_KEY' \
          --log-file '$log' \
          --session-tickets on --session-cache off \
          --strict-cert-profile on \
          --log-mode debug --debug-level '$DEBUG_LEVEL' \
          $extra > '$dir/smoke-${letter}.stdout.log' 2>&1 &
        echo \$! > '$pidfile'
    " || { fail "Scenario $letter start"; return; }

    local ready=0
    for _ in $(seq 1 20); do
        if ssh "$SSH_TARGET" "grep -q 'manifest scenario=$letter ' '$log'" >/dev/null 2>&1; then
            ready=1; break
        fi
        sleep 1
    done
    if (( ! ready )); then
        fail "Scenario $letter readiness"
        ssh "$SSH_TARGET" "cat '$dir/smoke-${letter}.stdout.log' '$log' 2>/dev/null || true" \
          >"$OUT_DIR/${letter}-startup.log" 2>&1 || true
        return
    fi

    { printf 'scenario-%s-full\n' "$letter"; sleep 1; } |
      timeout 30s openssl s_client \
        -connect "$BOARD_IP:$PORT" -tls1_3 \
        -ciphersuites TLS_AES_128_GCM_SHA256 \
        -groups P-256 -sigalgs ecdsa_secp256r1_sha256 \
        -CAfile "$CA_FILE" -verify_ip "$BOARD_IP" -verify_return_error \
        -sess_out "$session" -prexit >"$full" 2>&1
    local rc1=${PIPESTATUS[1]}

    { printf 'scenario-%s-resumed\n' "$letter"; sleep 1; } |
      timeout 30s openssl s_client \
        -connect "$BOARD_IP:$PORT" -tls1_3 \
        -ciphersuites TLS_AES_128_GCM_SHA256 \
        -groups P-256 -sigalgs ecdsa_secp256r1_sha256 \
        -CAfile "$CA_FILE" -verify_ip "$BOARD_IP" -verify_return_error \
        -sess_in "$session" -prexit >"$resumed" 2>&1
    local rc2=${PIPESTATUS[1]}

    ssh "$SSH_TARGET" "
      pid=\$(cat '$pidfile' 2>/dev/null || true)
      test -n \"\$pid\" && kill -TERM \"\$pid\" 2>/dev/null || true
      sleep 1
      rm -f '$pidfile'
      cat '$log'
    " >"$OUT_DIR/${letter}-server.log" 2>&1 || true

    if (( rc1 == 0 )) && grep -q 'Verify return code: 0' "$full"; then
        pass "Scenario $letter full handshake"
    else
        fail "Scenario $letter full handshake"
    fi
    if (( rc2 == 0 )) && grep -Eq 'Reused, TLSv1\.3|Reused' "$resumed"; then
        pass "Scenario $letter resumed handshake"
    else
        fail "Scenario $letter resumed handshake"
    fi
}

run_one A /root/scenarios/a /root/scenarios/a/tls_echo_server_scenario_a ""
run_one B /root/scenarios/b /root/scenarios/b/tls_echo_server_scenario_b \
    "--tee-selftest on --tee-derive-on-handshake off --ticket-debug-hashes on"
run_one C /root/scenarios/c /root/scenarios/c/tls_echo_server_scenario_c \
    "--tee-selftest on --external-signing on --async-debug-events on"
run_one D /root/scenarios/d /root/scenarios/d/tls_echo_server_scenario_d \
    "--tee-selftest on --crypto-backend on"
run_one E /root/scenarios/e /root/scenarios/e/tls_echo_server_scenario_e \
    "--tee-selftest on --tee-ticket-protection on --external-signing on --crypto-backend on --ticket-debug-hashes on"

record "RESULT pass=$PASS fail=$FAIL"
(( FAIL == 0 ))
