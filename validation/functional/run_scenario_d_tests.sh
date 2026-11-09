#!/usr/bin/env bash
set -uo pipefail

BOARD_IP="${BOARD_IP:-192.0.2.150}"
PORT="${PORT:-4433}"
CA_FILE="${CA_FILE:-CHANGE_ME_CA_CERT_PATH}"
OUT_ROOT="${OUT_ROOT:-./functional-results}"
COMMAND_TIMEOUT_SEC="${COMMAND_TIMEOUT_SEC:-30}"
SSH_TARGET="${SSH_TARGET:-root@192.0.2.150}"
SERVER_BINARY="${SERVER_BINARY:-/root/scenarios/d/tls_echo_server_scenario_d}"
MAX_CLOCK_SKEW_SEC="${MAX_CLOCK_SKEW_SEC:-5}"
EXPECTED_L1_PATCH_VERSION="${EXPECTED_L1_PATCH_VERSION:-1}"

usage() {
    cat <<USAGE
Usage: $0 [options]

D4 active resumption verification.

Options:
  --board-ip <ip>
  --port <port>
  --ca-file <path>
  --out-root <dir>
  --ssh-target <user@host>
  --server-log <path>
  --server-binary <path>
  --max-clock-skew-sec <n>
  --help
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
        --max-clock-skew-sec) MAX_CLOCK_SKEW_SEC="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

for command in openssl timeout grep awk sed date tee ssh sha256sum; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "ERROR: required command not found: $command" >&2
        exit 2
    }
done
[[ -r "$CA_FILE" ]] || { echo "ERROR: certificate not readable: $CA_FILE" >&2; exit 2; }
[[ "$MAX_CLOCK_SKEW_SEC" =~ ^[0-9]+$ ]] || { echo "ERROR: invalid clock-skew limit." >&2; exit 2; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$OUT_ROOT/scenario-d-d4-$STAMP"
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

run_client() {
    local output="$1" payload="$2" sess_arg="$3" sess_file="$4"
    if [[ "$sess_arg" == "out" ]]; then
        { printf '%s\n' "$payload"; sleep 1; } | \
            timeout "${COMMAND_TIMEOUT_SEC}s" openssl s_client \
                -connect "$BOARD_IP:$PORT" \
                -tls1_3 \
                -ciphersuites TLS_AES_128_GCM_SHA256 \
                -groups P-256 \
                -sigalgs ecdsa_secp256r1_sha256 \
                -CAfile "$CA_FILE" \
                -verify_ip "$BOARD_IP" \
                -verify_return_error \
                -prexit \
                -sess_out "$sess_file" \
                >"$output" 2>&1
    elif [[ "$sess_arg" == "in" ]]; then
        { printf '%s\n' "$payload"; sleep 1; } | \
            timeout "${COMMAND_TIMEOUT_SEC}s" openssl s_client \
                -connect "$BOARD_IP:$PORT" \
                -tls1_3 \
                -ciphersuites TLS_AES_128_GCM_SHA256 \
                -groups P-256 \
                -sigalgs ecdsa_secp256r1_sha256 \
                -CAfile "$CA_FILE" \
                -verify_ip "$BOARD_IP" \
                -verify_return_error \
                -prexit \
                -sess_in "$sess_file" \
                >"$output" 2>&1
    else
        { printf '%s\n' "$payload"; sleep 1; } | \
            timeout "${COMMAND_TIMEOUT_SEC}s" openssl s_client \
                -connect "$BOARD_IP:$PORT" \
                -tls1_3 \
                -ciphersuites TLS_AES_128_GCM_SHA256 \
                -groups P-256 \
                -sigalgs ecdsa_secp256r1_sha256 \
                -CAfile "$CA_FILE" \
                -verify_ip "$BOARD_IP" \
                -verify_return_error \
                -prexit \
                >"$output" 2>&1
    fi
    local status=${PIPESTATUS[1]}
    return "$status"
}

collect_server_log() {
    local destination="$1"
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$SSH_TARGET" "cat '$SERVER_LOG'" >"$destination" 2>&1
    local status=$?
    return "$status"
}

collect_remote_binary_info() {
    local destination="$1"
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$SSH_TARGET" "
        set -e
        test -f '$SERVER_BINARY'
        echo 'path=$SERVER_BINARY'
        sha256sum '$SERVER_BINARY'
        command -v file >/dev/null 2>&1 && file '$SERVER_BINARY' || true
        command -v ldd >/dev/null 2>&1 && ldd '$SERVER_BINARY' || true
    " >"$destination" 2>&1
    local status=$?
    return "$status"
}

get_remote_epoch() {
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$SSH_TARGET" 'date +%s' 2>/dev/null
}

contains_file() { grep -Eq "$2" "$1"; }

last_manifest() { grep -E 'manifest scenario=D ' "$1" 2>/dev/null | tail -n 1; }
last_config_manifest() { grep -E 'manifest bind=' "$1" 2>/dev/null | tail -n 1; }
last_summary_line() { grep -E '\] (SUMRY|FINAL) ' "$1" 2>/dev/null | tail -n 1; }

extract_counter_from_line() {
    local key="$1" line="$2" token
    token="$(grep -oE "(^|[[:space:]])${key}=[0-9]+" <<<"$line" | tail -n 1)"
    [[ -n "$token" ]] || return 1
    printf '%s\n' "${token##*=}"
}

counter_value() {
    local key="$1" file="$2" line
    line="$(last_summary_line "$file")"
    [[ -n "$line" ]] || return 1
    extract_counter_from_line "$key" "$line"
}

declare -A BEFORE=()
capture_before() {
    local file="$1" key value line
    line="$(last_summary_line "$file")"
    [[ -n "$line" ]] || return 0
    for key in "$@"; do :; done
    for key in $COUNTER_KEYS; do
        value="$(extract_counter_from_line "$key" "$line" || true)"
        [[ "$value" =~ ^[0-9]+$ ]] && BEFORE["$key"]="$value"
    done
}

counter_delta() {
    local key="$1" file="$2" after before
    after="$(counter_value "$key" "$file" || true)"
    [[ "$after" =~ ^[0-9]+$ ]] || return 1
    before="${BEFORE[$key]-0}"
    [[ "$before" =~ ^[0-9]+$ ]] || before=0
    if (( after >= before )); then
        printf '%s %s %s\n' "$((after - before))" "$before" "$after"
    else
        printf '%s %s %s\n' "$after" "$before" "$after"
    fi
}

check_counter_eq() {
    local key="$1" expected="$2" file="$3" observed before after
    read -r observed before after < <(counter_delta "$key" "$file" || echo "ERR 0 0")
    if [[ "$observed" =~ ^[0-9]+$ ]] && (( observed == expected )); then
        pass "counter $key delta=$observed expected=$expected before=$before after=$after"
    else
        fail "counter $key delta=${observed:-?} expected=$expected before=$before after=$after"
    fi
}

check_counter_gt() {
    local key="$1" file="$2" observed before after
    read -r observed before after < <(counter_delta "$key" "$file" || echo "ERR 0 0")
    if [[ "$observed" =~ ^[0-9]+$ ]] && (( observed > 0 )); then
        pass "counter $key delta=$observed greater_than=0 before=$before after=$after"
    else
        fail "counter $key delta=${observed:-?} not greater than 0 before=$before after=$after"
    fi
}

count_pattern_delta() {
    local pattern="$1" before_file="$2" after_file="$3"
    local before=0 after=0
    [[ -r "$before_file" ]] && before="$(grep -Ec "$pattern" "$before_file" 2>/dev/null || true)"
    after="$(grep -Ec "$pattern" "$after_file" 2>/dev/null || true)"
    [[ "$before" =~ ^[0-9]+$ ]] || before=0
    [[ "$after" =~ ^[0-9]+$ ]] || after=0
    if (( after >= before )); then
        printf '%s %s %s\n' "$((after - before))" "$before" "$after"
    else
        printf '%s %s %s\n' "$after" "$before" "$after"
    fi
}

check_pattern_gt() {
    local label="$1" pattern="$2" before_file="$3" after_file="$4" observed before after
    read -r observed before after < <(count_pattern_delta "$pattern" "$before_file" "$after_file")
    if (( observed > 0 )); then
        pass "$label delta=$observed greater_than=0 before=$before after=$after"
    else
        fail "$label delta=$observed not greater than 0 before=$before after=$after"
    fi
}

check_pattern_eq() {
    local label="$1" pattern="$2" expected="$3" before_file="$4" after_file="$5" observed before after
    read -r observed before after < <(count_pattern_delta "$pattern" "$before_file" "$after_file")
    if (( observed == expected )); then
        pass "$label delta=$observed expected=$expected before=$before after=$after"
    else
        fail "$label delta=$observed expected=$expected before=$before after=$after"
    fi
}

finalize() {
    record "RESULT pass=$PASS_COUNT fail=$FAIL_COUNT warn=$WARN_COUNT"
    if (( FAIL_COUNT == 0 )); then
        exit 0
    fi
    exit 1
}

SERVER_LOG="${SERVER_LOG:-/root/scenarios/d/tls_echo_server_d_d4.log}"
EXPECTED_BUILD_ID="${EXPECTED_BUILD_ID:-scenario-d-d4-resumption-debug-v1}"
COUNTER_KEYS="accepted hs_ok hs_fail ticket_parse_ok ticket_parse_fail ticket_write_ok ticket_write_fail tee_init_ok tee_init_fail tee_selftest_ok tee_selftest_fail backend_conn_init_ok backend_conn_init_fail backend_conn_free tee_conn_open_ok tee_conn_open_fail tee_conn_close_ok tee_conn_close_fail backend_transform_import_ok backend_transform_import_fail tee_transform_import_ok tee_transform_import_fail backend_transform_free tee_transform_free_ok tee_transform_free_fail record_seal_ok record_seal_fail record_open_ok record_open_fail backend_hs_keys_ok backend_hs_keys_fail tee_hs_keys_ok tee_hs_keys_fail backend_app_keys_ok backend_app_keys_fail tee_app_keys_ok tee_app_keys_fail finished_ok finished_fail tee_finished_ok tee_finished_fail backend_server_key_share_ok backend_server_key_share_fail tee_server_key_share_ok tee_server_key_share_fail backend_resumption_master_ok backend_resumption_master_fail tee_resumption_master_ok tee_resumption_master_fail backend_resumption_psk_ok backend_resumption_psk_fail tee_resumption_psk_ok tee_resumption_psk_fail echo_responses ssl_read_fail ssl_write_fail"
EXPECTED_CONNECTIONS=2

record "Scenario D D4 resumption verification"
record "board=$BOARD_IP port=$PORT ssh=$SSH_TARGET server_log=$SERVER_LOG"

collect_server_log "$OUT_DIR/server-before.log" && pass "collected server log before test" || fail "could not collect server log before test"
capture_before "$OUT_DIR/server-before.log"
collect_remote_binary_info "$OUT_DIR/server-binary.txt" && pass "collected remote binary info" || fail "could not collect remote binary info"

client_epoch="$(date +%s)"
remote_epoch="$(get_remote_epoch || true)"
if [[ "$remote_epoch" =~ ^[0-9]+$ ]]; then
    skew=$(( client_epoch > remote_epoch ? client_epoch - remote_epoch : remote_epoch - client_epoch ))
    printf 'client_epoch=%s\nremote_epoch=%s\nabsolute_skew_sec=%s\n' "$client_epoch" "$remote_epoch" "$skew" >"$OUT_DIR/clock-skew.txt"
    if (( skew <= MAX_CLOCK_SKEW_SEC )); then pass "clock skew ${skew}s within limit"; else warn "clock skew ${skew}s exceeds limit ${MAX_CLOCK_SKEW_SEC}s"; fi
else
    warn "could not determine remote clock skew"
fi

session_file="$OUT_DIR/session.pem"
if run_client "$OUT_DIR/01-full.log" "D4 full handshake" out "$session_file" &&
   grep -q 'Verify return code: 0' "$OUT_DIR/01-full.log" &&
   grep -q 'D4 full handshake' "$OUT_DIR/01-full.log" &&
   [[ -s "$session_file" ]]; then
    pass "full handshake succeeded and session was stored"
else
    fail "full handshake/session storage failed"
fi

sleep 1
if run_client "$OUT_DIR/02-resumed.log" "D4 resumed handshake" in "$session_file" &&
   grep -q 'Verify return code: 0' "$OUT_DIR/02-resumed.log" &&
   grep -Eq 'Reused, TLSv1\.3|Reused' "$OUT_DIR/02-resumed.log" &&
   grep -q 'D4 resumed handshake' "$OUT_DIR/02-resumed.log"; then
    pass "resumed PSK-ECDHE handshake succeeded"
else
    fail "resumed PSK-ECDHE handshake failed or was not reported as reused"
fi

sleep 1
collect_server_log "$OUT_DIR/server-after.log" && pass "collected server log after test" || fail "could not collect server log after test"
manifest="$(last_manifest "$OUT_DIR/server-after.log")"
config_manifest="$(last_config_manifest "$OUT_DIR/server-after.log")"
summary_line="$(last_summary_line "$OUT_DIR/server-after.log")"
printf '%s\n' "$manifest" >"$OUT_DIR/manifest-line.txt"
printf '%s\n' "$config_manifest" >"$OUT_DIR/manifest-config-line.txt"
printf '%s\n' "$summary_line" >"$OUT_DIR/last-summary-line.txt"

[[ "$manifest" == *"stage=D4_TEE_RESUMPTION"* ]] && pass "manifest identifies D4 resumption stage" || fail "manifest does not identify D4"
[[ "$manifest" == *"build=$EXPECTED_BUILD_ID"* ]] && pass "expected D4 build id" || fail "unexpected build id"
[[ "$manifest" == *"mbedtls_l1_patch_version=$EXPECTED_L1_PATCH_VERSION"* ]] && pass "expected Mbed TLS L1 patch version" || fail "unexpected Mbed TLS L1 patch version"
[[ "$manifest" == *"crypto_backend_registered=on"* ]] && pass "backend registered" || fail "backend not registered"
[[ "$manifest" == *"crypto_backend_api_version=5"* ]] && pass "backend API version 5" || fail "backend API version not 5"
[[ "$manifest" == *"tee_lifecycle_api_version=5"* ]] && pass "TA API version 5" || fail "TA API version not 5"
[[ "$manifest" == *"ecdhe_backend=tee_ephemeral_p256"* ]] && pass "TEE ECDHE manifest" || fail "TEE ECDHE manifest missing"
[[ "$manifest" == *"resumption_backend=tee_resumption_master_and_psk"* ]] && pass "TEE resumption manifest" || fail "TEE resumption manifest missing"
[[ "$manifest" == *"keyupdate_backend=unsupported"* ]] && pass "KeyUpdate explicitly unsupported" || fail "KeyUpdate scope not explicit"
[[ "$config_manifest" == *"session_tickets=on"* ]] && pass "session tickets enabled" || fail "session tickets not enabled"
[[ "$config_manifest" == *"session_cache=off"* ]] && pass "session cache disabled" || fail "session cache not disabled"

for k in hs_fail ticket_parse_fail ticket_write_fail tee_init_fail tee_selftest_fail backend_conn_init_fail tee_conn_open_fail tee_conn_close_fail backend_transform_import_fail tee_transform_import_fail tee_transform_free_fail record_seal_fail record_open_fail backend_hs_keys_fail tee_hs_keys_fail backend_app_keys_fail tee_app_keys_fail finished_fail tee_finished_fail backend_server_key_share_fail tee_server_key_share_fail backend_resumption_master_fail tee_resumption_master_fail backend_resumption_psk_fail tee_resumption_psk_fail ssl_read_fail ssl_write_fail; do
    check_counter_eq "$k" 0 "$OUT_DIR/server-after.log"
done

check_counter_eq accepted "$EXPECTED_CONNECTIONS" "$OUT_DIR/server-after.log"
check_counter_eq hs_ok "$EXPECTED_CONNECTIONS" "$OUT_DIR/server-after.log"
check_counter_gt ticket_write_ok "$OUT_DIR/server-after.log"
check_counter_gt ticket_parse_ok "$OUT_DIR/server-after.log"
check_counter_eq backend_transform_import_ok 0 "$OUT_DIR/server-after.log"
check_counter_eq tee_transform_import_ok 0 "$OUT_DIR/server-after.log"
check_counter_eq backend_conn_init_ok "$EXPECTED_CONNECTIONS" "$OUT_DIR/server-after.log"
check_counter_eq backend_conn_free "$EXPECTED_CONNECTIONS" "$OUT_DIR/server-after.log"
check_counter_eq backend_server_key_share_ok "$EXPECTED_CONNECTIONS" "$OUT_DIR/server-after.log"
check_counter_eq tee_server_key_share_ok "$EXPECTED_CONNECTIONS" "$OUT_DIR/server-after.log"
check_counter_eq backend_hs_keys_ok "$EXPECTED_CONNECTIONS" "$OUT_DIR/server-after.log"
check_counter_eq tee_hs_keys_ok "$EXPECTED_CONNECTIONS" "$OUT_DIR/server-after.log"
check_counter_eq backend_app_keys_ok "$EXPECTED_CONNECTIONS" "$OUT_DIR/server-after.log"
check_counter_eq tee_app_keys_ok "$EXPECTED_CONNECTIONS" "$OUT_DIR/server-after.log"
check_counter_eq finished_ok $((EXPECTED_CONNECTIONS * 2)) "$OUT_DIR/server-after.log"
check_counter_eq tee_finished_ok $((EXPECTED_CONNECTIONS * 2)) "$OUT_DIR/server-after.log"
check_counter_gt backend_resumption_master_ok "$OUT_DIR/server-after.log"
check_counter_gt tee_resumption_master_ok "$OUT_DIR/server-after.log"
check_counter_gt backend_resumption_psk_ok "$OUT_DIR/server-after.log"
check_counter_gt tee_resumption_psk_ok "$OUT_DIR/server-after.log"
check_counter_gt record_seal_ok "$OUT_DIR/server-after.log"
check_counter_gt record_open_ok "$OUT_DIR/server-after.log"
check_counter_eq echo_responses "$EXPECTED_CONNECTIONS" "$OUT_DIR/server-after.log"

check_pattern_gt "backend resumption-master callbacks" 'd4_backend_resumption_master' "$OUT_DIR/server-before.log" "$OUT_DIR/server-after.log"
check_pattern_gt "backend resumption-psk callbacks" 'd4_backend_resumption_psk' "$OUT_DIR/server-before.log" "$OUT_DIR/server-after.log"
check_pattern_gt "resumed handshake passed PSK into TEE" 'd4_backend_handshake_keys .*psk_len=[1-9][0-9]*' "$OUT_DIR/server-before.log" "$OUT_DIR/server-after.log"
check_pattern_gt "full handshake passed no PSK into TEE" 'd4_backend_handshake_keys .*psk_len=0' "$OUT_DIR/server-before.log" "$OUT_DIR/server-after.log"
check_pattern_eq "handshake failures in log" 'handshake_failed' 0 "$OUT_DIR/server-before.log" "$OUT_DIR/server-after.log"

record "VERDICT: D4 verifies TLS 1.3 resumption/NewSessionTicket/PSK-ECDHE with TEE ECDHE, key schedule, Finished, and record AEAD. KeyUpdate is unsupported by this Mbed TLS tree and remains out of scope."
finalize
