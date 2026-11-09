#!/usr/bin/env bash
set -uo pipefail

BOARD_IP="${BOARD_IP:-192.0.2.150}"
PORT="${PORT:-4433}"
CA_FILE="${CA_FILE:-CHANGE_ME_CA_CERT_PATH}"
OUT_ROOT="${OUT_ROOT:-./functional-results}"
COMMAND_TIMEOUT_SEC="${COMMAND_TIMEOUT_SEC:-25}"
SSH_TARGET="${SSH_TARGET:-root@192.0.2.150}"
SERVER_LOG="${SERVER_LOG:-/root/scenarios/c/tls_echo_server_c.log}"
SERVER_BINARY="${SERVER_BINARY:-/root/scenarios/c/tls_echo_server_scenario_c}"
EXPECTED_DEBUG_LEVEL="${EXPECTED_DEBUG_LEVEL:-3}"
EXPECTED_BUILD_ID="${EXPECTED_BUILD_ID:-scenario-c-l1-m0-debug-v4}"
EXPECTED_L1_PATCH_VERSION="${EXPECTED_L1_PATCH_VERSION:-1}"

usage() {
    cat <<USAGE
Usage: $0 [options]

Options:
  --board-ip <ip>                 Server IP (default: $BOARD_IP)
  --port <port>                   TLS port (default: $PORT)
  --ca-file <path>                Trusted server certificate (default: $CA_FILE)
  --out-root <dir>                Parent result directory (default: $OUT_ROOT)
  --ssh-target <user@host>        Target used to collect the server log
  --server-log <path>             Remote server log (default: $SERVER_LOG)
  --server-binary <path>          Remote server executable (default: $SERVER_BINARY)
  --expected-debug-level <0-4>    Expected debug level (default: $EXPECTED_DEBUG_LEVEL)
  --expected-build-id <id>        Expected build marker (default: $EXPECTED_BUILD_ID)
  --expected-l1-patch-version <n> Expected local L1 patch revision (default: $EXPECTED_L1_PATCH_VERSION)
  --help                          Show this help

The Scenario C server must already be running with:
  --session-tickets off
  --session-cache off
  --external-signing off
  --tee-selftest on
  --async-debug-events on
  --log-mode debug
  --debug-level 3

This is a negative control. The TLS handshake must fail because the configured
certificate key is public-only and the TEE signing callback is not registered.
USAGE
}

while (($#)); do
    case "$1" in
        --board-ip) BOARD_IP="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --ca-file) CA_FILE="$2"; shift 2 ;;
        --out-root) OUT_ROOT="$2"; shift 2 ;;
        --ssh-target) SSH_TARGET="$2"; shift 2 ;;
        --server-log) SERVER_LOG="$2"; shift 2 ;;
        --server-binary) SERVER_BINARY="$2"; shift 2 ;;
        --expected-debug-level) EXPECTED_DEBUG_LEVEL="$2"; shift 2 ;;
        --expected-build-id) EXPECTED_BUILD_ID="$2"; shift 2 ;;
        --expected-l1-patch-version) EXPECTED_L1_PATCH_VERSION="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

for cmd in openssl timeout grep sed date tee ssh sha256sum; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "ERROR: required command not found: $cmd" >&2
        exit 2
    }
done

[[ -r "$CA_FILE" ]] || {
    echo "ERROR: certificate not readable: $CA_FILE" >&2
    exit 2
}
[[ -n "$SSH_TARGET" ]] || {
    echo "ERROR: the negative control requires --ssh-target." >&2
    exit 2
}
[[ "$EXPECTED_DEBUG_LEVEL" =~ ^[0-4]$ ]] || {
    echo "ERROR: --expected-debug-level must be 0-4." >&2
    exit 2
}
[[ "$EXPECTED_L1_PATCH_VERSION" =~ ^[1-9][0-9]*$ ]] || {
    echo "ERROR: --expected-l1-patch-version must be positive." >&2
    exit 2
}

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$OUT_ROOT/scenario-c-negative-control-$STAMP"
SUMMARY="$OUT_DIR/summary.txt"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"
: >"$SUMMARY"

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

record() { printf '%s\n' "$*" | tee -a "$SUMMARY"; }
pass() { PASS_COUNT=$((PASS_COUNT + 1)); record "PASS  $*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); record "FAIL  $*"; }
warn() { WARN_COUNT=$((WARN_COUNT + 1)); record "WARN  $*"; }

contains() {
    local file="$1" pattern="$2"
    grep -Eq "$pattern" "$file"
}

collect_server_log() {
    local destination="$1"
    set +e
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$SSH_TARGET" \
        "cat '$SERVER_LOG'" >"$destination" 2>&1
    local rc=$?
    set -e
    return "$rc"
}

collect_remote_binary_info() {
    local destination="$1"
    set +e
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$SSH_TARGET" "
        set -e
        test -f '$SERVER_BINARY'
        echo 'path=$SERVER_BINARY'
        sha256sum '$SERVER_BINARY'
        if command -v file >/dev/null 2>&1; then file '$SERVER_BINARY'; fi
        if command -v ldd >/dev/null 2>&1; then ldd '$SERVER_BINARY'; fi
    " >"$destination" 2>&1
    local rc=$?
    set -e
    return "$rc"
}

extract_counter() {
    local key="$1" file="$2" line token
    line="$(grep -E '\] (SUMRY|FINAL) ' "$file" 2>/dev/null | tail -n 1)"
    [[ -n "$line" ]] || return 1
    token="$(grep -oE "(^|[[:space:]])${key}=[0-9]+" <<<"$line" | tail -n 1)"
    [[ -n "$token" ]] || return 1
    printf '%s\n' "${token##*=}"
}

declare -A BEFORE_COUNTERS=()

capture_before_counters() {
    local file="$1" key value
    for key in accepted hs_ok hs_fail tee_sign_ok tee_sign_fail \
               async_start async_resume async_cancel echo_responses \
               ticket_write_ok ticket_write_fail ticket_parse_ok \
               ticket_parse_fail ssl_read_fail ssl_write_fail; do
        value="$(extract_counter "$key" "$file" || true)"
        [[ "$value" =~ ^[0-9]+$ ]] && BEFORE_COUNTERS["$key"]="$value"
    done
}

counter_delta() {
    local key="$1" file="$2"
    local before after
    after="$(extract_counter "$key" "$file" || true)"
    [[ "$after" =~ ^[0-9]+$ ]] || return 1
    before="${BEFORE_COUNTERS[$key]-0}"
    [[ "$before" =~ ^[0-9]+$ ]] || before=0
    ((after >= before)) || return 1
    printf '%s\n' "$((after - before))"
}

count_pattern_delta() {
    local pattern="$1" before_file="$2" after_file="$3"
    local before=0 after=0
    before="$(grep -Ec "$pattern" "$before_file" 2>/dev/null || true)"
    after="$(grep -Ec "$pattern" "$after_file" 2>/dev/null || true)"
    [[ "$before" =~ ^[0-9]+$ ]] || before=0
    [[ "$after" =~ ^[0-9]+$ ]] || after=0
    ((after >= before)) || {
        printf '%s\n' "$after"
        return
    }
    printf '%s\n' "$((after - before))"
}

check_delta_eq() {
    local key="$1" expected="$2" file="$3" value
    value="$(counter_delta "$key" "$file" || true)"
    if [[ "$value" =~ ^[0-9]+$ ]] && ((value == expected)); then
        pass "server counter delta $key=$value"
    else
        fail "server counter delta $key=${value:-unavailable}, expected=$expected"
    fi
}

set -e
record "Scenario C external-signing negative control"
record "UTC start: $(date -u --iso-8601=seconds)"
record "Endpoint: ${BOARD_IP}:${PORT}"
record "Output: $OUT_DIR"
record ""

{
    uname -a
    openssl version -a
    printf 'SERVER_BINARY=%s\n' "$SERVER_BINARY"
    printf 'BOARD_IP=%s\nPORT=%s\nCA_FILE=%s\n' "$BOARD_IP" "$PORT" "$CA_FILE"
    printf 'EXPECTED_BUILD_ID=%s\nEXPECTED_L1_PATCH_VERSION=%s\n' \
        "$EXPECTED_BUILD_ID" "$EXPECTED_L1_PATCH_VERSION"
    sha256sum "$CA_FILE"
} >"$OUT_DIR/environment.txt" 2>&1

if openssl x509 -in "$CA_FILE" -noout -checkip "$BOARD_IP" \
    >"$OUT_DIR/certificate-ip-check.txt" 2>&1; then
    pass "local trust certificate matches IP $BOARD_IP"
else
    fail "local trust certificate does not match IP $BOARD_IP"
fi

if collect_remote_binary_info "$OUT_DIR/server-binary.txt"; then
    if grep -Eq 'libteec\.so' "$OUT_DIR/server-binary.txt"; then
        pass "Scenario C binary links against libteec"
    else
        fail "Scenario C binary does not show the required libteec dependency"
    fi
else
    warn "could not collect Scenario C binary metadata"
fi

if ! collect_server_log "$OUT_DIR/server-before.log"; then
    fail "could not collect server log before the negative control"
else
    placement="$(grep 'manifest scenario=C ' "$OUT_DIR/server-before.log" | tail -n 1)"
    runtime="$(grep 'manifest bind=' "$OUT_DIR/server-before.log" | tail -n 1)"

    contains <(printf '%s\n' "$placement") "build=${EXPECTED_BUILD_ID}([[:space:]]|$)" &&
        pass "manifest confirms build=$EXPECTED_BUILD_ID" ||
        fail "manifest does not show build=$EXPECTED_BUILD_ID"
    contains <(printf '%s\n' "$placement") 'mbedtls_lineage=L1' &&
        pass "manifest confirms Mbed TLS lineage L1" ||
        fail "manifest does not show mbedtls_lineage=L1"
    contains <(printf '%s\n' "$placement") "mbedtls_l1_patch_version=${EXPECTED_L1_PATCH_VERSION}([[:space:]]|$)" &&
        pass "manifest confirms L1 patch version $EXPECTED_L1_PATCH_VERSION" ||
        fail "manifest does not show expected L1 patch version"
    contains <(printf '%s\n' "$placement") 'tls13_external_sign=server_sync_v1' &&
        pass "manifest confirms the patched TLS 1.3 signing capability" ||
        fail "manifest does not show tls13_external_sign=server_sync_v1"
    contains <(printf '%s\n' "$placement") 'external_signing_registered=off' &&
        pass "manifest confirms the external signer is intentionally unregistered" ||
        fail "manifest does not show external_signing_registered=off"
    contains <(printf '%s\n' "$placement") 'certificate_verify_backend=software_negative_control' &&
        pass "manifest confirms software negative-control backend" ||
        fail "manifest does not show certificate_verify_backend=software_negative_control"
    contains <(printf '%s\n' "$placement") 'runtime_private_key_op=disabled_negative_control' &&
        pass "manifest confirms runtime TEE signing is disabled for the control" ||
        fail "manifest does not show runtime_private_key_op=disabled_negative_control"
    contains <(printf '%s\n' "$runtime") 'external_signing=off' &&
        pass "runtime manifest confirms --external-signing off" ||
        fail "runtime manifest does not show external_signing=off"
    contains <(printf '%s\n' "$runtime") 'session_tickets=off' &&
        pass "runtime manifest confirms tickets disabled" ||
        fail "runtime manifest does not show session_tickets=off"
    contains <(printf '%s\n' "$runtime") 'session_cache=off' &&
        pass "runtime manifest confirms cache disabled" ||
        fail "runtime manifest does not show session_cache=off"
    contains <(printf '%s\n' "$runtime") 'log_mode=debug' &&
        pass "runtime manifest confirms debug logging" ||
        fail "runtime manifest does not show log_mode=debug"
    contains <(printf '%s\n' "$runtime") "debug_level=${EXPECTED_DEBUG_LEVEL}([[:space:]]|$)" &&
        pass "runtime manifest confirms debug_level=$EXPECTED_DEBUG_LEVEL" ||
        warn "runtime manifest does not show debug_level=$EXPECTED_DEBUG_LEVEL"

    capture_before_counters "$OUT_DIR/server-before.log"
fi

COMMON_ARGS=(
    -connect "${BOARD_IP}:${PORT}"
    -tls1_3
    -ciphersuites TLS_AES_128_GCM_SHA256
    -groups P-256
    -sigalgs ecdsa_secp256r1_sha256
    -CAfile "$CA_FILE"
    -verify_ip "$BOARD_IP"
    -verify_return_error
    -brief
)

set +e
{
    printf '%s\n' "Scenario C negative control"
    sleep 1
} | timeout "${COMMAND_TIMEOUT_SEC}s" openssl s_client "${COMMON_ARGS[@]}" \
    >"$OUT_DIR/01-negative-control-handshake.log" 2>&1
client_rc=${PIPESTATUS[1]}
set -e

if ((client_rc != 0)); then
    pass "TLS handshake failed as expected with the external signer disabled"
else
    fail "TLS handshake unexpectedly succeeded with the external signer disabled"
fi

sleep 2

if collect_server_log "$OUT_DIR/server-after.log"; then
    counter_file="$OUT_DIR/server-after.log"

    check_delta_eq accepted 1 "$counter_file"
    check_delta_eq hs_ok 0 "$counter_file"
    check_delta_eq hs_fail 1 "$counter_file"
    check_delta_eq tee_sign_ok 0 "$counter_file"
    check_delta_eq tee_sign_fail 0 "$counter_file"
    check_delta_eq async_start 0 "$counter_file"
    check_delta_eq async_resume 0 "$counter_file"
    check_delta_eq async_cancel 0 "$counter_file"
    check_delta_eq echo_responses 0 "$counter_file"
    check_delta_eq ticket_write_ok 0 "$counter_file"
    check_delta_eq ticket_write_fail 0 "$counter_file"
    check_delta_eq ticket_parse_ok 0 "$counter_file"
    check_delta_eq ticket_parse_fail 0 "$counter_file"

    software_events="$(count_pattern_delta 'TLS 1\.3 CertificateVerify backend: software' \
        "$OUT_DIR/server-before.log" "$counter_file")"
    external_events="$(count_pattern_delta 'TLS 1\.3 CertificateVerify backend: external' \
        "$OUT_DIR/server-before.log" "$counter_file")"
    async_events="$(count_pattern_delta 'async_sign_start ' \
        "$OUT_DIR/server-before.log" "$counter_file")"

    if [[ "$software_events" =~ ^[0-9]+$ ]] && ((software_events >= 1)); then
        pass "Mbed TLS selected the software CertificateVerify path"
    else
        fail "software CertificateVerify backend selection was not observed"
    fi

    if [[ "$external_events" =~ ^[0-9]+$ ]] && ((external_events == 0)); then
        pass "Mbed TLS did not select the external CertificateVerify path"
    else
        fail "external CertificateVerify backend was selected unexpectedly"
    fi

    if [[ "$async_events" =~ ^[0-9]+$ ]] && ((async_events == 0)); then
        pass "Scenario C async signing callback was not invoked"
    else
        fail "Scenario C async signing callback was invoked unexpectedly"
    fi

    if grep -Eq 'mbedtls_pk_sign_ext|ECP - The private key or public key is invalid|0x4c80' \
        "$counter_file"; then
        pass "server trace identifies the expected local-signing failure"
    else
        warn "server trace does not explicitly identify the expected local-signing failure"
    fi

    if grep -Eq 'tee_sign_selftest_ok' "$counter_file"; then
        pass "TA startup sign-and-verify self-test still passed"
    else
        fail "TA startup self-test evidence is missing"
    fi

    grep -E 'manifest |TLS 1\.3 CertificateVerify backend|mbedtls_pk_sign_ext|tee_sign_selftest|async_sign_start|handshake_failed|\] (SUMRY|FINAL) ' \
        "$counter_file" >"$OUT_DIR/server-diagnostics-filtered.log" || true
else
    fail "could not collect server log after the negative control"
fi

record ""
record "UTC end: $(date -u --iso-8601=seconds)"
record "RESULT pass=$PASS_COUNT fail=$FAIL_COUNT warn=$WARN_COUNT"
record "Artifacts: $OUT_DIR"

if ((FAIL_COUNT > 0)); then
    exit 1
fi
exit 0
