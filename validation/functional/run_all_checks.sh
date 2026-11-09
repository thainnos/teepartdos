#!/usr/bin/env bash
set -uo pipefail

# Final functional acceptance checks for Scenarios A-E.
#
# The script starts the required server configuration on the remote target,
# invokes the corresponding scenario-specific test script, stops the server,
# and continues with the next test. Scenario E's own test script manages its
# remote server lifecycle and is therefore invoked directly.

BOARD_IP="${BOARD_IP:-192.0.2.150}"
PORT="${PORT:-4433}"
SSH_TARGET="${SSH_TARGET:-root@192.0.2.150}"
CA_FILE="${CA_FILE:-CHANGE_ME_CA_CERT_PATH}"
REMOTE_CERT="${REMOTE_CERT:-/root/certs/server.crt}"
REMOTE_KEY="${REMOTE_KEY:-/root/certs/server.key}"
OUT_ROOT="${OUT_ROOT:-./functional-test-results}"
DEBUG_LEVEL="${DEBUG_LEVEL:-3}"
MAX_CLOCK_SKEW_SEC="${MAX_CLOCK_SKEW_SEC:-5}"
STABILITY_RUNS="${STABILITY_RUNS:-10}"
FULL_HANDSHAKE_RUNS="${FULL_HANDSHAKE_RUNS:-10}"
READY_TIMEOUT_SEC="${READY_TIMEOUT_SEC:-30}"
FAIL_FAST=0

EXPECTED_A_BUILD_ID="${EXPECTED_A_BUILD_ID:-scenario-a-common-d4-v1}"
EXPECTED_C_BUILD_ID="${EXPECTED_C_BUILD_ID:-scenario-c-common-d4-v1}"
EXPECTED_D_BUILD_ID="${EXPECTED_D_BUILD_ID:-scenario-d-common-d4-v1}"
EXPECTED_E_BUILD_ID="${EXPECTED_E_BUILD_ID:-scenario-e-case-a-common-d4-v1}"
EXPECTED_L1_PATCH_VERSION="${EXPECTED_L1_PATCH_VERSION:-1}"

# Optional explicit overrides. Empty values trigger canonical-path discovery.
TEST_A_SCRIPT="${TEST_A_SCRIPT:-}"
TEST_B_SCRIPT="${TEST_B_SCRIPT:-}"
TEST_C_SCRIPT="${TEST_C_SCRIPT:-}"
TEST_C_NEG_SCRIPT="${TEST_C_NEG_SCRIPT:-}"
TEST_D_SCRIPT="${TEST_D_SCRIPT:-}"
TEST_D_DISABLED_SCRIPT="${TEST_D_DISABLED_SCRIPT:-}"
TEST_E_SCRIPT="${TEST_E_SCRIPT:-}"

usage() {
    cat <<USAGE
Usage: $0 [options]

Runs the complete scenario-specific M0 regression sequence:
  1. Scenario A M0
  2. Scenario B M0
  3. Scenario C M0
  4. Scenario C external-signing negative control
  5. Scenario D D4 active-backend test
  6. Scenario D D4 disabled-backend control
  7. Scenario E Case-A test

Options:
  --board-ip <ip>               Board/service IP (default: $BOARD_IP)
  --port <port>                 TLS port (default: $PORT)
  --ssh-target <user@host>      Remote target (default: $SSH_TARGET)
  --ca-file <path>              Local trusted certificate (default: $CA_FILE)
  --remote-cert <path>          Remote server certificate (default: $REMOTE_CERT)
  --remote-key <path>           Remote server key (default: $REMOTE_KEY)
  --out-root <dir>              Combined result root (default: $OUT_ROOT)
  --debug-level <0-4>           Remote server debug level (default: $DEBUG_LEVEL)
  --max-clock-skew-sec <n>      Child-test warning threshold (default: $MAX_CLOCK_SKEW_SEC)
  --stability-runs <n>          A/B resumed-handshake runs (default: $STABILITY_RUNS)
  --full-handshake-runs <n>     C repeated full handshakes (default: $FULL_HANDSHAKE_RUNS)
  --ready-timeout-sec <n>       Remote manifest readiness timeout (default: $READY_TIMEOUT_SEC)
  --fail-fast                   Stop after the first failed test
  --help                        Show this help

The script expects binaries deployed at:
  /root/scenarios/a/tls_echo_server_scenario_a
  /root/scenarios/b/tls_echo_server_scenario_b
  /root/scenarios/c/tls_echo_server_scenario_c
  /root/scenarios/d/tls_echo_server_scenario_d
  /root/scenarios/e/tls_echo_server_scenario_e

Canonical test-script locations are discovered below each scenario's scripts/
directory. Individual paths can be overridden with TEST_A_SCRIPT,
TEST_B_SCRIPT, TEST_C_SCRIPT, TEST_C_NEG_SCRIPT, TEST_D_SCRIPT,
TEST_D_DISABLED_SCRIPT, and TEST_E_SCRIPT.
USAGE
}

while (($#)); do
    case "$1" in
        --board-ip) BOARD_IP="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --ssh-target) SSH_TARGET="$2"; shift 2 ;;
        --ca-file) CA_FILE="$2"; shift 2 ;;
        --remote-cert) REMOTE_CERT="$2"; shift 2 ;;
        --remote-key) REMOTE_KEY="$2"; shift 2 ;;
        --out-root) OUT_ROOT="$2"; shift 2 ;;
        --debug-level) DEBUG_LEVEL="$2"; shift 2 ;;
        --max-clock-skew-sec) MAX_CLOCK_SKEW_SEC="$2"; shift 2 ;;
        --stability-runs) STABILITY_RUNS="$2"; shift 2 ;;
        --full-handshake-runs) FULL_HANDSHAKE_RUNS="$2"; shift 2 ;;
        --ready-timeout-sec) READY_TIMEOUT_SEC="$2"; shift 2 ;;
        --fail-fast) FAIL_FAST=1; shift ;;
        --help) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

for cmd in bash ssh grep date tee mkdir dirname basename chmod find sort tail; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "ERROR: required command not found: $cmd" >&2
        exit 2
    }
done

[[ -r "$CA_FILE" ]] || {
    echo "ERROR: CA/server certificate is not readable: $CA_FILE" >&2
    exit 2
}
[[ -n "$SSH_TARGET" ]] || {
    echo "ERROR: --ssh-target must not be empty" >&2
    exit 2
}
[[ "$PORT" =~ ^[1-9][0-9]*$ ]] && ((PORT <= 65535)) || {
    echo "ERROR: --port must be between 1 and 65535" >&2
    exit 2
}
[[ "$DEBUG_LEVEL" =~ ^[0-4]$ ]] || {
    echo "ERROR: --debug-level must be 0-4" >&2
    exit 2
}
for value_name in MAX_CLOCK_SKEW_SEC STABILITY_RUNS FULL_HANDSHAKE_RUNS READY_TIMEOUT_SEC EXPECTED_L1_PATCH_VERSION; do
    value="${!value_name}"
    [[ "$value" =~ ^[0-9]+$ ]] || {
        echo "ERROR: $value_name must be a non-negative integer" >&2
        exit 2
    }
done
((STABILITY_RUNS > 0 && FULL_HANDSHAKE_RUNS > 0 && READY_TIMEOUT_SEC > 0 && EXPECTED_L1_PATCH_VERSION > 0)) || {
    echo "ERROR: run counts, readiness timeout, and L1 patch version must be positive" >&2
    exit 2
}

resolve_script() {
    local explicit="$1"
    shift
    local candidate

    if [[ -n "$explicit" ]]; then
        [[ -f "$explicit" ]] || {
            echo "ERROR: explicitly configured test script does not exist: $explicit" >&2
            return 1
        }
        printf '%s\n' "$explicit"
        return 0
    fi

    for candidate in "$@"; do
        if [[ -f "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

TEST_A_SCRIPT="$(resolve_script "$TEST_A_SCRIPT" \
    "$SELF_DIR/run_scenario_a_tests.sh")" || {
        echo "ERROR: could not locate Scenario A test script" >&2; exit 2;
    }
TEST_B_SCRIPT="$(resolve_script "$TEST_B_SCRIPT" \
    "$SELF_DIR/run_scenario_b_tests.sh")" || {
        echo "ERROR: could not locate Scenario B test script" >&2; exit 2;
    }
TEST_C_SCRIPT="$(resolve_script "$TEST_C_SCRIPT" \
    "$SELF_DIR/run_scenario_c_tests.sh")" || {
        echo "ERROR: could not locate Scenario C test script" >&2; exit 2;
    }
TEST_C_NEG_SCRIPT="$(resolve_script "$TEST_C_NEG_SCRIPT" \
    "$SELF_DIR/run_scenario_c_negative_control.sh")" || {
        echo "ERROR: could not locate Scenario C negative-control script" >&2; exit 2;
    }
TEST_D_SCRIPT="$(resolve_script "$TEST_D_SCRIPT" \
    "$SELF_DIR/run_scenario_d_tests.sh")" || {
        echo "ERROR: could not locate Scenario D D4 test script" >&2; exit 2;
    }
TEST_D_DISABLED_SCRIPT="$(resolve_script "$TEST_D_DISABLED_SCRIPT" \
    "$SELF_DIR/run_scenario_d_disabled_control.sh")" || {
        echo "ERROR: could not locate Scenario D disabled-control script" >&2; exit 2;
    }
TEST_E_SCRIPT="$(resolve_script "$TEST_E_SCRIPT" \
    "$SELF_DIR/run_scenario_e_tests.sh")" || {
        echo "ERROR: could not locate Scenario E test script" >&2; exit 2;
    }

for script in \
    "$TEST_A_SCRIPT" "$TEST_B_SCRIPT" "$TEST_C_SCRIPT" \
    "$TEST_C_NEG_SCRIPT" "$TEST_D_SCRIPT" \
    "$TEST_D_DISABLED_SCRIPT" "$TEST_E_SCRIPT"; do
    bash -n "$script" || {
        echo "ERROR: shell syntax validation failed: $script" >&2
        exit 2
    }
done

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$OUT_ROOT/a-to-e-specific-$STAMP"
SUMMARY="$RUN_DIR/summary.txt"
RESULTS_TSV="$RUN_DIR/results.tsv"
RUNNER_LOG_DIR="$RUN_DIR/runner-logs"
mkdir -p "$RUNNER_LOG_DIR"
chmod 700 "$RUN_DIR"
: >"$SUMMARY"
printf 'test\tstatus\texit_code\tstart_utc\tend_utc\tartifacts_root\trunner_log\n' >"$RESULTS_TSV"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
CURRENT_PID_FILE=""

record() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }
pass() { PASS_COUNT=$((PASS_COUNT + 1)); record "PASS  $*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); record "FAIL  $*"; }

remote_exec() {
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$SSH_TARGET" "$@"
}

stop_remote_server() {
    local pid_file="${1:-$CURRENT_PID_FILE}"
    [[ -n "$pid_file" ]] || return 0

    remote_exec "
        pid_file='$pid_file'
        if test -s \"\$pid_file\"; then
            pid=\$(cat \"\$pid_file\" 2>/dev/null || true)
            if test -n \"\$pid\"; then
                kill -TERM \"\$pid\" 2>/dev/null || true
                i=0
                while kill -0 \"\$pid\" 2>/dev/null && test \"\$i\" -lt 10; do
                    sleep 1
                    i=\$((i + 1))
                done
                kill -KILL \"\$pid\" 2>/dev/null || true
            fi
            rm -f \"\$pid_file\"
        fi
    " >/dev/null 2>&1 || true

    if [[ "$CURRENT_PID_FILE" == "$pid_file" ]]; then
        CURRENT_PID_FILE=""
    fi
}

stop_all_known_servers() {
    remote_exec "
        for pid_file in /root/scenarios/?/*.pid; do
            test -s "\$pid_file" || continue
            pid=\$(cat "\$pid_file" 2>/dev/null || true)
            if test -n "\$pid"; then
                kill -TERM "\$pid" 2>/dev/null || true
                i=0
                while kill -0 "\$pid" 2>/dev/null && test "\$i" -lt 10; do
                    sleep 1
                    i=\$((i + 1))
                done
                kill -KILL "\$pid" 2>/dev/null || true
            fi
            rm -f "\$pid_file"
        done
    " >/dev/null 2>&1 || true
    CURRENT_PID_FILE=""
}

cleanup() {
    stop_all_known_servers
}
trap cleanup EXIT INT TERM

start_remote_server() {
    local scenario_letter="$1"
    local remote_dir="$2"
    local binary="$3"
    local log_file="$4"
    local pid_file="$5"
    shift 5
    local -a extra_args=("$@")
    local stdout_file="$remote_dir/regression-${scenario_letter}.stdout.log"
    local remote_cmd

    stop_remote_server "$CURRENT_PID_FILE"
    CURRENT_PID_FILE="$pid_file"

    printf -v remote_cmd '%q ' \
        "$binary" \
        --bind-ip "$BOARD_IP" \
        --port "$PORT" \
        --cert "$REMOTE_CERT" \
        --key "$REMOTE_KEY" \
        --log-file "$log_file" \
        "${extra_args[@]}"

    remote_exec "
        set -eu
        mkdir -p '$remote_dir'
        test -x '$binary'
        test -r '$REMOTE_CERT'
        test -r '$REMOTE_KEY'
        if test -s '$pid_file'; then
            old=\$(cat '$pid_file' 2>/dev/null || true)
            test -n \"\$old\" && kill -TERM \"\$old\" 2>/dev/null || true
            sleep 1
            test -n \"\$old\" && kill -KILL \"\$old\" 2>/dev/null || true
        fi
        : > '$log_file'
        : > '$stdout_file'
        nohup $remote_cmd > '$stdout_file' 2>&1 &
        echo \$! > '$pid_file'
    " || return 1

    local elapsed=0
    while ((elapsed < READY_TIMEOUT_SEC)); do
        if remote_exec "
            test -s '$pid_file' &&
            pid=\$(cat '$pid_file') &&
            kill -0 \"\$pid\" 2>/dev/null &&
            grep -q 'manifest scenario=$scenario_letter ' '$log_file'
        " >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    remote_exec "cat '$stdout_file' '$log_file' 2>/dev/null || true" \
        >"$RUNNER_LOG_DIR/${scenario_letter}-startup-failure.log" 2>&1 || true
    return 1
}

run_child_test() {
    local test_id="$1"
    local label="$2"
    local artifacts_root="$3"
    local script="$4"
    shift 4
    local -a args=("$@")
    local start_utc end_utc rc status runner_log

    mkdir -p "$artifacts_root"
    runner_log="$RUNNER_LOG_DIR/${test_id}.log"
    start_utc="$(date -u --iso-8601=seconds)"
    record "RUN   $label"
    record "      script=$script"
    record "      artifacts=$artifacts_root"

    (
        cd -- "$(dirname -- "$script")"
        bash "$script" "${args[@]}"
    ) > >(tee "$runner_log") 2>&1
    rc=${PIPESTATUS[0]}
    end_utc="$(date -u --iso-8601=seconds)"

    if ((rc == 0)); then
        status="PASS"
        pass "$label"
    else
        status="FAIL"
        fail "$label (exit=$rc)"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$test_id" "$status" "$rc" "$start_utc" "$end_utc" \
        "$artifacts_root" "$runner_log" >>"$RESULTS_TSV"

    if ((rc != 0 && FAIL_FAST)); then
        record "FAIL-FAST: stopping after $label"
        finalize_and_exit
    fi
    return "$rc"
}

start_or_record_failure() {
    local test_id="$1"
    local label="$2"
    local artifacts_root="$3"
    local scenario_letter="$4"
    local remote_dir="$5"
    local binary="$6"
    local log_file="$7"
    local pid_file="$8"
    shift 8

    record "START $label server"
    if start_remote_server "$scenario_letter" "$remote_dir" "$binary" "$log_file" "$pid_file" "$@"; then
        record "READY $label server"
        return 0
    fi

    local now
    now="$(date -u --iso-8601=seconds)"
    fail "$label server did not become ready"
    printf '%s\tFAIL\t125\t%s\t%s\t%s\t%s\n' \
        "$test_id" "$now" "$now" "$artifacts_root" \
        "$RUNNER_LOG_DIR/${scenario_letter}-startup-failure.log" >>"$RESULTS_TSV"
    stop_remote_server "$pid_file"
    if ((FAIL_FAST)); then
        finalize_and_exit
    fi
    return 1
}

finalize_and_exit() {
    stop_all_known_servers
    trap - EXIT INT TERM
    record ""
    record "UTC end: $(date -u --iso-8601=seconds)"
    record "RESULT pass=$PASS_COUNT fail=$FAIL_COUNT skip=$SKIP_COUNT"
    record "Combined artifacts: $RUN_DIR"
    record "Per-test results: $RESULTS_TSV"
    if ((FAIL_COUNT == 0)); then
        record "VERDICT: Complete A-E scenario-specific M0 regression passed."
        exit 0
    fi
    record "VERDICT: Complete A-E scenario-specific M0 regression did not pass."
    exit 1
}

record "A-E scenario-specific M0 regression"
record "UTC start: $(date -u --iso-8601=seconds)"
record "repository=$SELF_DIR"
record "board=$BOARD_IP port=$PORT ssh=$SSH_TARGET"
record "ca_file=$CA_FILE"
record "debug_level=$DEBUG_LEVEL"
record "output=$RUN_DIR"
record ""
record "Resolved test scripts:"
record "  A:          $TEST_A_SCRIPT"
record "  B:          $TEST_B_SCRIPT"
record "  C:          $TEST_C_SCRIPT"
record "  C-negative: $TEST_C_NEG_SCRIPT"
record "  D-active:   $TEST_D_SCRIPT"
record "  D-disabled: $TEST_D_DISABLED_SCRIPT"
record "  E:          $TEST_E_SCRIPT"
record ""

record "Remote deployment preflight"
if remote_exec "
    set -eu
    test -r '$REMOTE_CERT'
    test -r '$REMOTE_KEY'
    test -x /root/scenarios/a/tls_echo_server_scenario_a
    test -x /root/scenarios/b/tls_echo_server_scenario_b
    test -x /root/scenarios/c/tls_echo_server_scenario_c
    test -x /root/scenarios/d/tls_echo_server_scenario_d
    test -x /root/scenarios/e/tls_echo_server_scenario_e
    test -r /lib/optee_armtz/159e414d-c5b1-4652-8ec0-5d42beb160a9.ta
    test -r /lib/optee_armtz/2b85d8aa-7d3b-4cc3-9f6e-8f7d4a6a5c2b.ta
    test -r /lib/optee_armtz/8b2d21dc-b49f-469b-9200-bdf2bb42798d.ta
    sha256sum \
      /root/scenarios/a/tls_echo_server_scenario_a \
      /root/scenarios/b/tls_echo_server_scenario_b \
      /root/scenarios/c/tls_echo_server_scenario_c \
      /root/scenarios/d/tls_echo_server_scenario_d \
      /root/scenarios/e/tls_echo_server_scenario_e \
      /lib/optee_armtz/159e414d-c5b1-4652-8ec0-5d42beb160a9.ta \
      /lib/optee_armtz/2b85d8aa-7d3b-4cc3-9f6e-8f7d4a6a5c2b.ta \
      /lib/optee_armtz/8b2d21dc-b49f-469b-9200-bdf2bb42798d.ta
" >"$RUN_DIR/deployment-inventory.txt" 2>&1; then
    pass "remote binaries, TAs, certificate, and key are present"
else
    fail "remote deployment preflight failed"
    record "See: $RUN_DIR/deployment-inventory.txt"
    finalize_and_exit
fi

# Remove stale servers started by earlier orchestrated runs before binding the
# shared TLS port. Only PID-file-managed processes below /root/scenarios/? are
# affected.
stop_all_known_servers

# Scenario A
A_DIR="/root/scenarios/a"
A_BIN="$A_DIR/tls_echo_server_scenario_a"
A_LOG="$A_DIR/tls_echo_server_a.log"
A_PID="$A_DIR/tls_echo_server_a.pid"
A_OUT="$RUN_DIR/scenario-a"
if start_or_record_failure "scenario-a" "Scenario A M0" "$A_OUT" A \
    "$A_DIR" "$A_BIN" "$A_LOG" "$A_PID" \
    --session-tickets on \
    --session-cache off \
    --strict-cert-profile on \
    --log-mode debug \
    --debug-level "$DEBUG_LEVEL"; then
    run_child_test "scenario-a" "Scenario A M0" "$A_OUT" "$TEST_A_SCRIPT" \
        --board-ip "$BOARD_IP" \
        --port "$PORT" \
        --ca-file "$CA_FILE" \
        --out-root "$A_OUT" \
        --session-wait-sec 5 \
        --stability-runs "$STABILITY_RUNS" \
        --ssh-target "$SSH_TARGET" \
        --server-log "$A_LOG" \
        --server-binary "$A_BIN" \
        --max-clock-skew-sec "$MAX_CLOCK_SKEW_SEC" \
        --expected-debug-level "$DEBUG_LEVEL" \
        --expected-build-id "$EXPECTED_A_BUILD_ID" || true
    stop_remote_server "$A_PID"
fi

# Scenario B
B_DIR="/root/scenarios/b"
B_BIN="$B_DIR/tls_echo_server_scenario_b"
B_LOG="$B_DIR/tls_echo_server_b.log"
B_PID="$B_DIR/tls_echo_server_b.pid"
B_OUT="$RUN_DIR/scenario-b"
if start_or_record_failure "scenario-b" "Scenario B M0" "$B_OUT" B \
    "$B_DIR" "$B_BIN" "$B_LOG" "$B_PID" \
    --session-tickets on \
    --session-cache off \
    --strict-cert-profile on \
    --tee-derive-on-handshake off \
    --tee-selftest on \
    --ticket-debug-hashes on \
    --log-mode debug \
    --debug-level "$DEBUG_LEVEL"; then
    run_child_test "scenario-b" "Scenario B M0" "$B_OUT" "$TEST_B_SCRIPT" \
        --board-ip "$BOARD_IP" \
        --port "$PORT" \
        --ca-file "$CA_FILE" \
        --out-root "$B_OUT" \
        --session-wait-sec 5 \
        --stability-runs "$STABILITY_RUNS" \
        --ssh-target "$SSH_TARGET" \
        --server-log "$B_LOG" \
        --max-clock-skew-sec "$MAX_CLOCK_SKEW_SEC" \
        --expected-debug-level "$DEBUG_LEVEL" || true
    stop_remote_server "$B_PID"
fi

# Scenario C active external signing.
C_DIR="/root/scenarios/c"
C_BIN="$C_DIR/tls_echo_server_scenario_c"
C_LOG="$C_DIR/tls_echo_server_c.log"
C_PID="$C_DIR/tls_echo_server_c.pid"
C_OUT="$RUN_DIR/scenario-c"
if start_or_record_failure "scenario-c" "Scenario C M0" "$C_OUT" C \
    "$C_DIR" "$C_BIN" "$C_LOG" "$C_PID" \
    --session-tickets off \
    --session-cache off \
    --strict-cert-profile on \
    --tee-selftest on \
    --async-debug-events on \
    --external-signing on \
    --log-mode debug \
    --debug-level "$DEBUG_LEVEL"; then
    run_child_test "scenario-c" "Scenario C M0" "$C_OUT" "$TEST_C_SCRIPT" \
        --board-ip "$BOARD_IP" \
        --port "$PORT" \
        --ca-file "$CA_FILE" \
        --out-root "$C_OUT" \
        --full-handshake-runs "$FULL_HANDSHAKE_RUNS" \
        --ssh-target "$SSH_TARGET" \
        --server-log "$C_LOG" \
        --server-binary "$C_BIN" \
        --max-clock-skew-sec "$MAX_CLOCK_SKEW_SEC" \
        --expected-debug-level "$DEBUG_LEVEL" \
        --expected-build-id "$EXPECTED_C_BUILD_ID" \
        --expected-l1-patch-version "$EXPECTED_L1_PATCH_VERSION" || true
    stop_remote_server "$C_PID"
fi

# Scenario C negative control.
C_NEG_LOG="$C_DIR/tls_echo_server_c_negative.log"
C_NEG_PID="$C_DIR/tls_echo_server_c_negative.pid"
C_NEG_OUT="$RUN_DIR/scenario-c-negative"
if start_or_record_failure "scenario-c-negative" "Scenario C negative control" "$C_NEG_OUT" C \
    "$C_DIR" "$C_BIN" "$C_NEG_LOG" "$C_NEG_PID" \
    --session-tickets off \
    --session-cache off \
    --strict-cert-profile on \
    --tee-selftest on \
    --async-debug-events on \
    --external-signing off \
    --log-mode debug \
    --debug-level "$DEBUG_LEVEL"; then
    run_child_test "scenario-c-negative" "Scenario C negative control" "$C_NEG_OUT" "$TEST_C_NEG_SCRIPT" \
        --board-ip "$BOARD_IP" \
        --port "$PORT" \
        --ca-file "$CA_FILE" \
        --out-root "$C_NEG_OUT" \
        --ssh-target "$SSH_TARGET" \
        --server-log "$C_NEG_LOG" \
        --server-binary "$C_BIN" \
        --expected-debug-level "$DEBUG_LEVEL" \
        --expected-build-id "$EXPECTED_C_BUILD_ID" \
        --expected-l1-patch-version "$EXPECTED_L1_PATCH_VERSION" || true
    stop_remote_server "$C_NEG_PID"
fi

# Scenario D active D4 backend.
D_DIR="/root/scenarios/d"
D_BIN="$D_DIR/tls_echo_server_scenario_d"
D_LOG="$D_DIR/tls_echo_server_d_d4.log"
D_PID="$D_DIR/tls_echo_server_d_d4.pid"
D_OUT="$RUN_DIR/scenario-d-active"
if start_or_record_failure "scenario-d-active" "Scenario D D4 active" "$D_OUT" D \
    "$D_DIR" "$D_BIN" "$D_LOG" "$D_PID" \
    --session-tickets on \
    --session-cache off \
    --strict-cert-profile on \
    --crypto-backend on \
    --tee-selftest on \
    --log-mode debug \
    --debug-level "$DEBUG_LEVEL"; then
    EXPECTED_BUILD_ID="$EXPECTED_D_BUILD_ID" \
    EXPECTED_L1_PATCH_VERSION="$EXPECTED_L1_PATCH_VERSION" \
    run_child_test "scenario-d-active" "Scenario D D4 active" "$D_OUT" "$TEST_D_SCRIPT" \
        --board-ip "$BOARD_IP" \
        --port "$PORT" \
        --ca-file "$CA_FILE" \
        --out-root "$D_OUT" \
        --ssh-target "$SSH_TARGET" \
        --server-log "$D_LOG" \
        --server-binary "$D_BIN" \
        --max-clock-skew-sec "$MAX_CLOCK_SKEW_SEC" || true
    stop_remote_server "$D_PID"
fi

# Scenario D software/disabled-backend control.
D_DISABLED_LOG="$D_DIR/tls_echo_server_d_d4_disabled.log"
D_DISABLED_PID="$D_DIR/tls_echo_server_d_d4_disabled.pid"
D_DISABLED_OUT="$RUN_DIR/scenario-d-disabled"
if start_or_record_failure "scenario-d-disabled" "Scenario D D4 disabled control" "$D_DISABLED_OUT" D \
    "$D_DIR" "$D_BIN" "$D_DISABLED_LOG" "$D_DISABLED_PID" \
    --session-tickets on \
    --session-cache off \
    --strict-cert-profile on \
    --crypto-backend off \
    --tee-selftest on \
    --log-mode debug \
    --debug-level "$DEBUG_LEVEL"; then
    EXPECTED_BUILD_ID="$EXPECTED_D_BUILD_ID" \
    EXPECTED_L1_PATCH_VERSION="$EXPECTED_L1_PATCH_VERSION" \
    run_child_test "scenario-d-disabled" "Scenario D D4 disabled control" "$D_DISABLED_OUT" "$TEST_D_DISABLED_SCRIPT" \
        --board-ip "$BOARD_IP" \
        --port "$PORT" \
        --ca-file "$CA_FILE" \
        --out-root "$D_DISABLED_OUT" \
        --ssh-target "$SSH_TARGET" \
        --server-log "$D_DISABLED_LOG" \
        --server-binary "$D_BIN" \
        --max-clock-skew-sec "$MAX_CLOCK_SKEW_SEC" || true
    stop_remote_server "$D_DISABLED_PID"
fi

# Scenario E's supplied test owns its remote process lifecycle.
stop_remote_server "$CURRENT_PID_FILE"
E_OUT="$RUN_DIR/scenario-e"
REMOTE_CERT="$REMOTE_CERT" \
REMOTE_KEY="$REMOTE_KEY" \
EXPECTED_BUILD_ID="$EXPECTED_E_BUILD_ID" \
EXPECTED_L1_PATCH_VERSION="$EXPECTED_L1_PATCH_VERSION" \
run_child_test "scenario-e" "Scenario E Case A" "$E_OUT" "$TEST_E_SCRIPT" \
    --board-ip "$BOARD_IP" \
    --port "$PORT" \
    --ssh-target "$SSH_TARGET" \
    --ca-file "$CA_FILE" \
    --out-root "$E_OUT" \
    --debug-level "$DEBUG_LEVEL" || true

finalize_and_exit
