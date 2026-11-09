#!/usr/bin/env bash
set -uo pipefail

BOARD_IP="${BOARD_IP:-192.0.2.150}"
PORT="${PORT:-4433}"
CA_FILE="${CA_FILE:-CHANGE_ME_CA_CERT_PATH}"
OUT_ROOT="${OUT_ROOT:-./functional-results}"
FULL_HANDSHAKE_RUNS="${FULL_HANDSHAKE_RUNS:-10}"
COMMAND_TIMEOUT_SEC="${COMMAND_TIMEOUT_SEC:-25}"
SSH_TARGET="${SSH_TARGET:-root@192.0.2.150}"
SERVER_LOG="${SERVER_LOG:-/root/scenarios/c/tls_echo_server_c.log}"
SERVER_BINARY="${SERVER_BINARY:-/root/scenarios/c/tls_echo_server_scenario_c}"
MAX_CLOCK_SKEW_SEC="${MAX_CLOCK_SKEW_SEC:-5}"
EXPECTED_DEBUG_LEVEL="${EXPECTED_DEBUG_LEVEL:-3}"
EXPECTED_BUILD_ID="${EXPECTED_BUILD_ID:-scenario-c-l1-m0-debug-v4}"
EXPECTED_L1_PATCH_VERSION="${EXPECTED_L1_PATCH_VERSION:-1}"

usage() {
    cat <<USAGE
Usage: $0 [options]

Options:
  --board-ip <ip>              Server IP (default: $BOARD_IP)
  --port <port>                TLS port (default: $PORT)
  --ca-file <path>             Trusted server certificate (default: $CA_FILE)
  --out-root <dir>             Parent result directory (default: $OUT_ROOT)
  --full-handshake-runs <n>    Additional full-handshake stability runs (default: $FULL_HANDSHAKE_RUNS)
  --ssh-target <user@host>     Optional target used to collect the server log
  --server-log <path>          Remote server log (default: $SERVER_LOG)
  --server-binary <path>       Remote server executable (default: $SERVER_BINARY)
  --max-clock-skew-sec <n>     Warn if board/client UTC skew exceeds this value (default: $MAX_CLOCK_SKEW_SEC)
  --expected-debug-level <0-4> Expected server debug level; mismatch is a warning (default: $EXPECTED_DEBUG_LEVEL)
  --expected-build-id <id>     Expected Scenario C build marker (default: $EXPECTED_BUILD_ID)
  --expected-l1-patch-version <n> Expected local Mbed TLS L1 patch revision (default: $EXPECTED_L1_PATCH_VERSION)
  --help                       Show this help

The Scenario C server must already be running with:
  --session-tickets off --session-cache off --external-signing on
For M0 diagnostics, also use:
  --tee-selftest on --async-debug-events on --log-mode debug --debug-level 3

Tickets are intentionally disabled: every tested connection must execute the
TLS 1.3 CertificateVerify signature through the Scenario C TA.
USAGE
}

while (($#)); do
    case "$1" in
        --board-ip) BOARD_IP="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --ca-file) CA_FILE="$2"; shift 2 ;;
        --out-root) OUT_ROOT="$2"; shift 2 ;;
        --full-handshake-runs) FULL_HANDSHAKE_RUNS="$2"; shift 2 ;;
        --ssh-target) SSH_TARGET="$2"; shift 2 ;;
        --server-log) SERVER_LOG="$2"; shift 2 ;;
        --server-binary) SERVER_BINARY="$2"; shift 2 ;;
        --max-clock-skew-sec) MAX_CLOCK_SKEW_SEC="$2"; shift 2 ;;
        --expected-debug-level) EXPECTED_DEBUG_LEVEL="$2"; shift 2 ;;
        --expected-build-id) EXPECTED_BUILD_ID="$2"; shift 2 ;;
        --expected-l1-patch-version) EXPECTED_L1_PATCH_VERSION="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

for cmd in openssl timeout sha256sum grep awk sed date tee seq diff; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "ERROR: required command not found: $cmd" >&2
        exit 2
    }
done
if [[ -n "$SSH_TARGET" ]] && ! command -v ssh >/dev/null 2>&1; then
    echo "ERROR: --ssh-target requires ssh." >&2
    exit 2
fi
[[ -r "$CA_FILE" ]] || { echo "ERROR: certificate not readable: $CA_FILE" >&2; exit 2; }
[[ "$FULL_HANDSHAKE_RUNS" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: --full-handshake-runs must be positive." >&2; exit 2; }
[[ "$MAX_CLOCK_SKEW_SEC" =~ ^[0-9]+$ ]] || { echo "ERROR: --max-clock-skew-sec must be non-negative." >&2; exit 2; }
[[ "$EXPECTED_DEBUG_LEVEL" =~ ^[0-4]$ ]] || { echo "ERROR: --expected-debug-level must be 0-4." >&2; exit 2; }
[[ "$EXPECTED_L1_PATCH_VERSION" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: --expected-l1-patch-version must be positive." >&2; exit 2; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$OUT_ROOT/scenario-c-m0-$STAMP"
SUMMARY="$OUT_DIR/summary.txt"
mkdir -p "$OUT_DIR/stability"
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

run_client() {
    local output="$1" payload="$2" wait_sec="$3"
    shift 3
    set +e
    {
        printf '%s\n' "$payload"
        sleep "$wait_sec"
    } | timeout "${COMMAND_TIMEOUT_SEC}s" openssl s_client "$@" >"$output" 2>&1
    local rc=${PIPESTATUS[1]}
    set -e
    return "$rc"
}

collect_server_log() {
    local destination="$1"
    [[ -n "$SSH_TARGET" ]] || return 1
    set +e
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$SSH_TARGET" \
        "cat '$SERVER_LOG'" >"$destination" 2>&1
    local rc=$?
    set -e
    return "$rc"
}

get_remote_epoch() {
    [[ -n "$SSH_TARGET" ]] || return 1
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$SSH_TARGET" 'date +%s' 2>/dev/null
}

collect_remote_binary_info() {
    local destination="$1"
    [[ -n "$SSH_TARGET" ]] || return 1
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
    for key in \
        accepted hs_ok hs_fail \
        tee_sign_ok tee_sign_fail \
        async_start async_resume async_cancel \
        ticket_write_ok ticket_write_fail \
        ticket_parse_ok ticket_parse_fail \
        echo_responses ssl_read_fail ssl_write_fail; do
        value="$(extract_counter "$key" "$file" || true)"
        [[ "$value" =~ ^[0-9]+$ ]] && BEFORE_COUNTERS["$key"]="$value"
    done
}

counter_observation() {
    local key="$1" file="$2"
    local after before observed mode
    after="$(extract_counter "$key" "$file" || true)"
    [[ "$after" =~ ^[0-9]+$ ]] || return 1
    before="${BEFORE_COUNTERS[$key]-}"
    if [[ "$before" =~ ^[0-9]+$ ]] && ((after >= before)); then
        observed=$((after - before))
        printf '%s delta %s %s\n' "$observed" "$before" "$after"
    else
        printf '%s absolute n/a %s\n' "$after" "$after"
    fi
}

count_pattern_delta() {
    local pattern="$1" before_file="$2" after_file="$3"
    local before=0 after=0 observed mode
    if [[ -r "$before_file" ]]; then
        before="$(grep -Ec "$pattern" "$before_file" 2>/dev/null || true)"
    fi
    after="$(grep -Ec "$pattern" "$after_file" 2>/dev/null || true)"
    [[ "$before" =~ ^[0-9]+$ ]] || before=0
    [[ "$after" =~ ^[0-9]+$ ]] || after=0

    if ((after >= before)); then
        observed=$((after - before))
        mode="delta"
    else
        observed="$after"
        mode="absolute"
    fi
    printf '%s %s %s %s\n' "$observed" "$mode" "$before" "$after"
}

check_counter_eq() {
    local key="$1" expected="$2" file="$3" observation observed mode before after
    observation="$(counter_observation "$key" "$file" || true)"
    if [[ "$observation" =~ ^([0-9]+)[[:space:]]+(delta|absolute)[[:space:]]+([^[:space:]]+)[[:space:]]+([0-9]+)$ ]]; then
        observed="${BASH_REMATCH[1]}"; mode="${BASH_REMATCH[2]}"
        before="${BASH_REMATCH[3]}"; after="${BASH_REMATCH[4]}"
        if ((observed == expected)); then
            pass "server counter $key=$observed expected=$expected mode=$mode before=$before after=$after"
        else
            fail "server counter $key=$observed expected=$expected mode=$mode before=$before after=$after"
        fi
    else
        fail "server counter $key could not be extracted"
    fi
}

check_counter_zero() {
    check_counter_eq "$1" 0 "$2"
}

check_absolute_gt0() {
    local key="$1" file="$2" value
    value="$(extract_counter "$key" "$file" || true)"
    if [[ "$value" =~ ^[0-9]+$ ]] && ((value > 0)); then
        pass "server startup counter $key=$value"
    else
        fail "server startup counter $key is absent or zero"
    fi
}

extract_presented_cert() {
    local transcript="$1" pem="$2"
    awk '
        /-----BEGIN CERTIFICATE-----/ { capture=1 }
        capture { print }
        /-----END CERTIFICATE-----/ { exit }
    ' "$transcript" >"$pem"
    [[ -s "$pem" ]]
}

cert_fingerprint() {
    openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null |
        sed 's/^sha256 Fingerprint=//; s/^SHA256 Fingerprint=//'
}

set -e
record "Scenario C M0 verification"
record "UTC start: $(date -u --iso-8601=seconds)"
record "Endpoint: ${BOARD_IP}:${PORT}"
record "Output: $OUT_DIR"
record "Expected placement: TLS control/records in REE; CertificateVerify signing in TEE"
record ""

{
    uname -a
    openssl version -a
    printf 'SERVER_BINARY=%s\n' "$SERVER_BINARY"
    printf 'BOARD_IP=%s\nPORT=%s\nCA_FILE=%s\nFULL_HANDSHAKE_RUNS=%s\n' \
        "$BOARD_IP" "$PORT" "$CA_FILE" "$FULL_HANDSHAKE_RUNS"
    printf 'EXPECTED_BUILD_ID=%s\nEXPECTED_L1_PATCH_VERSION=%s\n' \
        "$EXPECTED_BUILD_ID" "$EXPECTED_L1_PATCH_VERSION"
    sha256sum "$CA_FILE"
} >"$OUT_DIR/environment.txt" 2>&1

openssl x509 -in "$CA_FILE" -noout -subject -issuer -dates -fingerprint -sha256 \
    -ext subjectAltName >"$OUT_DIR/certificate-local.txt" 2>&1 || true

if openssl x509 -in "$CA_FILE" -noout -checkip "$BOARD_IP" \
    >"$OUT_DIR/certificate-ip-check.txt" 2>&1; then
    pass "local trust certificate matches IP $BOARD_IP"
else
    fail "local trust certificate does not match IP $BOARD_IP"
fi

if [[ -n "$SSH_TARGET" ]]; then
    client_epoch="$(date +%s)"
    board_epoch="$(get_remote_epoch || true)"
    if [[ "$board_epoch" =~ ^[0-9]+$ ]]; then
        skew=$((client_epoch - board_epoch)); ((skew < 0)) && skew=$((-skew))
        printf 'client_epoch=%s\nboard_epoch=%s\nabsolute_skew_sec=%s\n' \
            "$client_epoch" "$board_epoch" "$skew" >"$OUT_DIR/clock-skew.txt"
        if ((skew <= MAX_CLOCK_SKEW_SEC)); then
            pass "board/client clock skew is ${skew}s"
        else
            warn "board/client clock skew is ${skew}s (limit ${MAX_CLOCK_SKEW_SEC}s)"
        fi
    else
        warn "could not retrieve board time"
    fi
fi

if [[ -n "$SSH_TARGET" ]]; then
    if collect_remote_binary_info "$OUT_DIR/server-binary.txt"; then
        if grep -Eq 'libteec\.so' "$OUT_DIR/server-binary.txt"; then
            pass "Scenario C binary links against libteec"
        else
            fail "Scenario C binary does not show the required libteec dependency"
        fi
    else
        warn "could not collect Scenario C binary metadata"
    fi
fi

if collect_server_log "$OUT_DIR/server-before.log"; then
    manifest="$(grep 'manifest bind=' "$OUT_DIR/server-before.log" | tail -n 1)"
    placement="$(grep 'manifest scenario=C ' "$OUT_DIR/server-before.log" | tail -n 1)"

    contains <(printf '%s\n' "$placement") "build=${EXPECTED_BUILD_ID}([[:space:]]|$)" &&
        pass "manifest confirms build=$EXPECTED_BUILD_ID" ||
        fail "manifest does not show build=$EXPECTED_BUILD_ID"
    contains <(printf '%s\n' "$placement") 'mbedtls_lineage=L1' &&
        pass "manifest confirms Mbed TLS lineage L1" ||
        fail "manifest does not show mbedtls_lineage=L1"
    contains <(printf '%s\n' "$placement") "mbedtls_l1_patch_version=${EXPECTED_L1_PATCH_VERSION}([[:space:]]|$)" &&
        pass "manifest confirms L1 patch version $EXPECTED_L1_PATCH_VERSION" ||
        fail "manifest does not show the expected L1 patch version"
    contains <(printf '%s\n' "$placement") 'tls13_external_sign=server_sync_v1' &&
        pass "manifest confirms synchronous TLS 1.3 server external signing" ||
        fail "manifest does not show tls13_external_sign=server_sync_v1"
    contains <(printf '%s\n' "$placement") 'external_signing_registered=on' &&
        pass "manifest confirms external signer registration" ||
        fail "manifest does not show external_signing_registered=on"
    contains <(printf '%s\n' "$placement") 'certificate_verify_backend=tee' &&
        pass "manifest confirms TEE CertificateVerify backend" ||
        fail "manifest does not show certificate_verify_backend=tee"
    contains <(printf '%s\n' "$placement") 'placement=normal_world_plus_tee_private_key' &&
        pass "manifest confirms Scenario C placement" ||
        fail "manifest does not confirm Scenario C placement"
    contains <(printf '%s\n' "$placement") 'runtime_private_key_op=tee' &&
        pass "manifest confirms TEE runtime signing" ||
        fail "manifest does not confirm runtime_private_key_op=tee"
    contains <(printf '%s\n' "$placement") 'provisioning_source=ree_keyfile_import' &&
        pass "manifest records prototype REE key-file provisioning" ||
        fail "manifest does not record provisioning_source=ree_keyfile_import"
    contains <(printf '%s\n' "$placement") 'ree_parsed_key_context_after_import=released' &&
        pass "manifest confirms parsed REE key context was released" ||
        fail "manifest does not confirm parsed-key-context release"
    contains <(printf '%s\n' "$placement") 'nonextractable_key_generation=no' &&
        pass "manifest records that prototype provisioning is not non-extractable generation" ||
        fail "manifest does not record the provisioning limitation"
    contains <(printf '%s\n' "$placement") 'async_api_mode=synchronous_completion' &&
        pass "manifest records synchronous completion through the async-private API" ||
        fail "manifest does not record the async API completion mode"
    contains <(printf '%s\n' "$placement") 'traffic_keys=normal_world' &&
        pass "manifest confirms traffic keys remain in normal world" ||
        fail "manifest does not confirm normal-world traffic keys"
    contains <(printf '%s\n' "$placement") 'tls13_kex_modes=ephemeral\+psk_ephemeral' &&
        pass "manifest confirms full and resumable ECDHE modes" ||
        fail "manifest does not show ephemeral+psk_ephemeral"

    contains <(printf '%s\n' "$manifest") 'session_tickets=off' &&
        pass "server manifest: session tickets disabled" ||
        fail "server manifest does not show session_tickets=off"
    contains <(printf '%s\n' "$manifest") 'session_cache=off' &&
        pass "server manifest: session cache disabled" ||
        fail "server manifest does not show session_cache=off"
    contains <(printf '%s\n' "$manifest") 'strict_cert_profile=on' &&
        pass "server manifest: strict certificate profile enabled" ||
        fail "server manifest does not show strict_cert_profile=on"
    contains <(printf '%s\n' "$manifest") 'tee_selftest=on' &&
        pass "server manifest: TEE sign self-test enabled" ||
        fail "server manifest does not show tee_selftest=on"
    contains <(printf '%s\n' "$manifest") 'async_debug_events=on' &&
        pass "server manifest: async callback diagnostics enabled" ||
        warn "server manifest does not show async_debug_events=on"
    contains <(printf '%s\n' "$manifest") 'external_signing=on' &&
        pass "server manifest: external signing enabled" ||
        fail "server manifest does not show external_signing=on"
    contains <(printf '%s\n' "$manifest") 'log_mode=debug' &&
        pass "server manifest: debug log mode enabled" ||
        warn "server manifest does not show log_mode=debug"
    contains <(printf '%s\n' "$manifest") "debug_level=${EXPECTED_DEBUG_LEVEL}([[:space:]]|$)" &&
        pass "server manifest: debug_level=$EXPECTED_DEBUG_LEVEL" ||
        warn "server manifest does not show debug_level=$EXPECTED_DEBUG_LEVEL"

    capture_before_counters "$OUT_DIR/server-before.log"
else
    warn "could not collect server log before testing; absolute counter checks will be used"
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
)

# 1. Strict full handshake and echo. No ticket is offered.
if run_client "$OUT_DIR/01-full-handshake.log" "M0 C full handshake" 1 \
    "${COMMON_ARGS[@]}" -showcerts; then
    if contains "$OUT_DIR/01-full-handshake.log" '^New, TLSv1\.3, Cipher is TLS_AES_128_GCM_SHA256' &&
       contains "$OUT_DIR/01-full-handshake.log" 'Peer signature type: ECDSA' &&
       contains "$OUT_DIR/01-full-handshake.log" 'Server Temp Key: ECDH, prime256v1, 256 bits' &&
       contains "$OUT_DIR/01-full-handshake.log" 'Verify return code: 0 \(ok\)' &&
       grep -Fxq 'M0 C full handshake' "$OUT_DIR/01-full-handshake.log"; then
        pass "strict full TLS 1.3 handshake, fixed profile, and echo"
    else
        fail "full handshake transcript does not match the fixed profile"
    fi
else
    fail "strict full handshake command failed"
fi

if extract_presented_cert "$OUT_DIR/01-full-handshake.log" "$OUT_DIR/certificate-presented.pem"; then
    local_fp="$(cert_fingerprint "$CA_FILE")"
    presented_fp="$(cert_fingerprint "$OUT_DIR/certificate-presented.pem")"
    printf 'local=%s\npresented=%s\n' "$local_fp" "$presented_fp" \
        >"$OUT_DIR/certificate-fingerprints.txt"
    if [[ -n "$local_fp" && "$local_fp" == "$presented_fp" ]]; then
        pass "presented certificate matches the configured trust certificate"
    else
        fail "presented certificate differs from the configured trust certificate"
    fi
else
    fail "could not extract the presented certificate"
fi

# 2. Repeated full handshakes. These deliberately do not use sess_in.
stability_failures=0
for i in $(seq 1 "$FULL_HANDSHAKE_RUNS"); do
    run_file="$OUT_DIR/stability/run-$(printf '%02d' "$i").log"
    payload="M0 C full $(printf '%02d' "$i")"
    if ! run_client "$run_file" "$payload" 1 "${COMMON_ARGS[@]}" -brief; then
        stability_failures=$((stability_failures + 1))
        continue
    fi
    if ! contains "$run_file" 'Protocol version: TLSv1\.3' ||
       ! contains "$run_file" 'Ciphersuite: TLS_AES_128_GCM_SHA256' ||
       ! contains "$run_file" 'Signature type: ECDSA' ||
       ! grep -Fxq "$payload" "$run_file"; then
        stability_failures=$((stability_failures + 1))
    fi
done

if ((stability_failures == 0)); then
    pass "$FULL_HANDSHAKE_RUNS additional full handshakes completed with echo"
else
    fail "$stability_failures checks failed in the full-handshake stability sequence"
fi

# 3. Server-side proof that every tested handshake used the TA callback.
if collect_server_log "$OUT_DIR/server-after.log"; then
    counter_file="$OUT_DIR/server-after.log"
    expected_runtime=$((1 + FULL_HANDSHAKE_RUNS))

    check_absolute_gt0 tee_init_ok "$counter_file"
    check_absolute_gt0 tee_import_ok "$counter_file"
    check_absolute_gt0 tee_selftest_ok "$counter_file"

    check_counter_eq hs_ok "$expected_runtime" "$counter_file"
    check_counter_eq tee_sign_ok "$expected_runtime" "$counter_file"
    check_counter_eq async_start "$expected_runtime" "$counter_file"
    check_counter_eq async_resume "$expected_runtime" "$counter_file"
    check_counter_eq echo_responses "$expected_runtime" "$counter_file"

    for key in hs_fail tee_sign_fail async_cancel ticket_write_ok ticket_write_fail \
               ticket_parse_ok ticket_parse_fail ssl_read_fail ssl_write_fail; do
        check_counter_zero "$key" "$counter_file"
    done

    start_observation="$(count_pattern_delta 'async_sign_start ' "$OUT_DIR/server-before.log" "$counter_file")"
    resume_observation="$(count_pattern_delta 'async_resume signature_len=' "$OUT_DIR/server-before.log" "$counter_file")"
    external_observation="$(count_pattern_delta 'TLS 1\.3 CertificateVerify backend: external' "$OUT_DIR/server-before.log" "$counter_file")"
    software_observation="$(count_pattern_delta 'TLS 1\.3 CertificateVerify backend: software' "$OUT_DIR/server-before.log" "$counter_file")"

    read -r start_events start_mode start_before start_after <<<"$start_observation"
    read -r resume_events resume_mode resume_before resume_after <<<"$resume_observation"
    read -r external_events external_mode external_before external_after <<<"$external_observation"
    read -r software_events software_mode software_before software_after <<<"$software_observation"

    if ((start_events == expected_runtime && resume_events == expected_runtime)); then
        pass "debug trace contains one async start/resume pair per tested handshake"
    else
        fail "debug trace async_start=$start_events async_resume=$resume_events expected=$expected_runtime"
    fi

    if ((external_events == expected_runtime)); then
        pass "Mbed TLS selected the external CertificateVerify backend for every tested handshake"
    else
        fail "external backend selections=$external_events expected=$expected_runtime"
    fi

    if ((software_events == 0)); then
        pass "Mbed TLS did not use the software CertificateVerify backend"
    else
        fail "software CertificateVerify backend was selected $software_events time(s)"
    fi

    {
        printf 'async_start observed=%s mode=%s before=%s after=%s\n' \
            "$start_events" "$start_mode" "$start_before" "$start_after"
        printf 'async_resume observed=%s mode=%s before=%s after=%s\n' \
            "$resume_events" "$resume_mode" "$resume_before" "$resume_after"
        printf 'external_backend observed=%s mode=%s before=%s after=%s\n' \
            "$external_events" "$external_mode" "$external_before" "$external_after"
        printf 'software_backend observed=%s mode=%s before=%s after=%s\n' \
            "$software_events" "$software_mode" "$software_before" "$software_after"
    } >"$OUT_DIR/debug-event-deltas.txt"

    if grep -Eq 'tee_sign_selftest_ok' "$counter_file"; then
        pass "server log confirms TA sign-and-verify self-test"
    else
        fail "server log does not contain tee_sign_selftest_ok"
    fi

    grep -E 'manifest |TLS 1\.3 CertificateVerify backend|external CertificateVerify signature|tee_sign_selftest|async_sign_start|async_sign_ready|async_resume|async_cancel|tee_sign_failed|\] (SUMRY|FINAL) |handshake_failed' \
        "$counter_file" >"$OUT_DIR/server-diagnostics-filtered.log" || true
else
    warn "could not collect server log after testing"
fi

record ""
record "UTC end: $(date -u --iso-8601=seconds)"
record "RESULT pass=$PASS_COUNT fail=$FAIL_COUNT warn=$WARN_COUNT"
record "Artifacts: $OUT_DIR"

if ((FAIL_COUNT > 0)); then
    exit 1
fi
exit 0
