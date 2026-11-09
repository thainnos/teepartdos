#!/usr/bin/env bash
set -uo pipefail

BOARD_IP="${BOARD_IP:-192.0.2.150}"
PORT="${PORT:-4433}"
SSH_TARGET="${SSH_TARGET:-root@192.0.2.150}"
CA_FILE="${CA_FILE:-CHANGE_ME_CA_CERT_PATH}"
REMOTE_DIR="${REMOTE_DIR:-/root/scenarios/e}"
SERVER_BINARY="${SERVER_BINARY:-$REMOTE_DIR/tls_echo_server_scenario_e}"
SERVER_LOG="${SERVER_LOG:-$REMOTE_DIR/tls_echo_server_e.log}"
SERVER_PID_FILE="${SERVER_PID_FILE:-$REMOTE_DIR/tls_echo_server_e.pid}"
REMOTE_CERT="${REMOTE_CERT:-/root/certs/server.crt}"
REMOTE_KEY="${REMOTE_KEY:-/root/certs/server.key}"
OUT_ROOT="${OUT_ROOT:-./functional-results}"
COMMAND_TIMEOUT_SEC="${COMMAND_TIMEOUT_SEC:-30}"
DEBUG_LEVEL="${DEBUG_LEVEL:-2}"
EXPECTED_BUILD_ID="${EXPECTED_BUILD_ID:-scenario-e-case-a-common-d4-v1}"
EXPECTED_L1_PATCH_VERSION="${EXPECTED_L1_PATCH_VERSION:-1}"

usage() {
    cat <<USAGE
Usage: $0 [options]

Starts and validates Scenario E Case A (literal B+C+D composition).

Options:
  --board-ip <ip>
  --port <port>
  --ssh-target <user@host>
  --ca-file <path>
  --out-root <dir>
  --debug-level <0-4>
  --help
USAGE
}

while (($#)); do
    case "$1" in
        --board-ip) BOARD_IP="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --ssh-target) SSH_TARGET="$2"; shift 2 ;;
        --ca-file) CA_FILE="$2"; shift 2 ;;
        --out-root) OUT_ROOT="$2"; shift 2 ;;
        --debug-level) DEBUG_LEVEL="$2"; shift 2 ;;
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
[[ -r "$CA_FILE" ]] || { echo "ERROR: CA file not readable: $CA_FILE" >&2; exit 2; }
[[ "$DEBUG_LEVEL" =~ ^[0-4]$ ]] || { echo "ERROR: invalid debug level." >&2; exit 2; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$OUT_ROOT/scenario-e-case-a-$STAMP"
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

cleanup_remote() {
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$SSH_TARGET" "
        if test -s '$SERVER_PID_FILE'; then
            pid=\$(cat '$SERVER_PID_FILE' 2>/dev/null || true)
            test -n \"\$pid\" && kill -TERM \"\$pid\" 2>/dev/null || true
            sleep 1
            test -n \"\$pid\" && kill -KILL \"\$pid\" 2>/dev/null || true
            rm -f '$SERVER_PID_FILE'
        fi
    " >/dev/null 2>&1 || true
}
trap cleanup_remote EXIT INT TERM

start_remote() {
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$SSH_TARGET" "
        set -eu
        test -x '$SERVER_BINARY'
        test -r '$REMOTE_CERT'
        test -r '$REMOTE_KEY'
        mkdir -p '$REMOTE_DIR'
        if test -s '$SERVER_PID_FILE'; then
            old=\$(cat '$SERVER_PID_FILE' 2>/dev/null || true)
            test -n \"\$old\" && kill -TERM \"\$old\" 2>/dev/null || true
            sleep 1
        fi
        : > '$SERVER_LOG'
        nohup '$SERVER_BINARY' \
            --bind-ip '$BOARD_IP' \
            --port '$PORT' \
            --cert '$REMOTE_CERT' \
            --key '$REMOTE_KEY' \
            --log-file '$SERVER_LOG' \
            --session-tickets on \
            --session-cache off \
            --strict-cert-profile on \
            --tee-ticket-protection on \
            --external-signing on \
            --crypto-backend on \
            --tee-selftest on \
            --ticket-debug-hashes on \
            --log-mode debug \
            --debug-level '$DEBUG_LEVEL' \
            > '$REMOTE_DIR/server.stdout.log' 2>&1 &
        echo \$! > '$SERVER_PID_FILE'
    "
}

wait_for_manifest() {
    local i
    for i in $(seq 1 30); do
        if ssh -o BatchMode=yes -o ConnectTimeout=5 "$SSH_TARGET" \
            "test -s '$SERVER_PID_FILE' &&
             kill -0 \$(cat '$SERVER_PID_FILE') 2>/dev/null &&
             grep -q 'manifest scenario=E ' '$SERVER_LOG'" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

run_client() {
    local output="$1" payload="$2" mode="$3" session_file="$4"
    local -a args=(
        s_client
        -connect "$BOARD_IP:$PORT"
        -tls1_3
        -ciphersuites TLS_AES_128_GCM_SHA256
        -groups P-256
        -sigalgs ecdsa_secp256r1_sha256
        -CAfile "$CA_FILE"
        -verify_ip "$BOARD_IP"
        -verify_return_error
        -prexit
    )
    if [[ "$mode" == "out" ]]; then
        args+=( -sess_out "$session_file" )
    elif [[ "$mode" == "in" ]]; then
        args+=( -sess_in "$session_file" )
    fi
    { printf '%s\n' "$payload"; sleep 1; } |
        timeout "${COMMAND_TIMEOUT_SEC}s" openssl "${args[@]}" >"$output" 2>&1
    return "${PIPESTATUS[1]}"
}

last_manifest() { grep -E 'manifest scenario=E ' "$1" | tail -n 1; }
last_config_manifest() { grep -E 'manifest bind=' "$1" | tail -n 1; }
last_summary_line() { grep -E '\] (SUMRY|FINAL) ' "$1" | tail -n 1; }

counter() {
    local key="$1" line="$2" token
    token="$(grep -oE "(^|[[:space:]])${key}=[0-9]+" <<<"$line" | tail -n 1)"
    [[ -n "$token" ]] || return 1
    printf '%s\n' "${token##*=}"
}
check_eq() {
    local key="$1" expected="$2" line="$3" value
    value="$(counter "$key" "$line" || true)"
    if [[ "$value" =~ ^[0-9]+$ ]] && (( value == expected )); then
        pass "$key=$value"
    else
        fail "$key=${value:-missing}, expected=$expected"
    fi
}
check_gt() {
    local key="$1" line="$2" value
    value="$(counter "$key" "$line" || true)"
    if [[ "$value" =~ ^[0-9]+$ ]] && (( value > 0 )); then
        pass "$key=$value greater_than=0"
    else
        fail "$key=${value:-missing}, expected greater_than=0"
    fi
}

record "Scenario E Case-A validation"
record "board=$BOARD_IP port=$PORT ssh=$SSH_TARGET debug_level=$DEBUG_LEVEL"

if start_remote; then
    pass "remote server start command completed"
else
    fail "remote server start command failed"
fi

if wait_for_manifest; then
    pass "Scenario E startup manifest observed"
else
    fail "Scenario E did not become ready"
    ssh "$SSH_TARGET" "cat '$REMOTE_DIR/server.stdout.log' '$SERVER_LOG' 2>/dev/null || true" \
        >"$OUT_DIR/startup-failure.log" 2>&1 || true
fi

session_file="$OUT_DIR/session.pem"
if run_client "$OUT_DIR/01-full.log" "E full handshake" out "$session_file" &&
   grep -q 'Verify return code: 0' "$OUT_DIR/01-full.log" &&
   grep -q 'E full handshake' "$OUT_DIR/01-full.log" &&
   [[ -s "$session_file" ]]; then
    pass "full handshake, echo and session storage succeeded"
else
    fail "full handshake, echo or session storage failed"
fi

sleep 1
if run_client "$OUT_DIR/02-resumed.log" "E resumed handshake" in "$session_file" &&
   grep -q 'Verify return code: 0' "$OUT_DIR/02-resumed.log" &&
   grep -Eq 'Reused, TLSv1\.3|Reused' "$OUT_DIR/02-resumed.log" &&
   grep -q 'E resumed handshake' "$OUT_DIR/02-resumed.log"; then
    pass "resumed PSK-ECDHE handshake and echo succeeded"
else
    fail "resumed handshake failed or was not reused"
fi

cleanup_remote
trap - EXIT INT TERM

ssh -o BatchMode=yes -o ConnectTimeout=5 "$SSH_TARGET" \
    "cat '$SERVER_LOG'" >"$OUT_DIR/server.log" 2>&1 &&
    pass "collected server log" || fail "failed to collect server log"

ssh -o BatchMode=yes -o ConnectTimeout=5 "$SSH_TARGET" "
    sha256sum \
      '$SERVER_BINARY' \
      /lib/optee_armtz/159e414d-c5b1-4652-8ec0-5d42beb160a9.ta \
      /lib/optee_armtz/2b85d8aa-7d3b-4cc3-9f6e-8f7d4a6a5c2b.ta \
      /lib/optee_armtz/8b2d21dc-b49f-469b-9200-bdf2bb42798d.ta
" >"$OUT_DIR/remote-hashes.txt" 2>&1 &&
    pass "collected binary and TA hashes" || fail "failed to collect hashes"

manifest="$(last_manifest "$OUT_DIR/server.log")"
config_manifest="$(last_config_manifest "$OUT_DIR/server.log")"
final_line="$(last_summary_line "$OUT_DIR/server.log")"
printf '%s\n' "$manifest" >"$OUT_DIR/manifest.txt"
printf '%s\n' "$config_manifest" >"$OUT_DIR/config-manifest.txt"
printf '%s\n' "$final_line" >"$OUT_DIR/final-summary.txt"

[[ "$manifest" == *"stage=CASE_A_LITERAL_B_C_D"* ]] &&
    pass "literal B+C+D stage identified" || fail "wrong Scenario E stage"
[[ "$manifest" == *"build=$EXPECTED_BUILD_ID"* ]] &&
    pass "expected build ID" || fail "unexpected build ID"
[[ "$manifest" == *"mbedtls_l1_patch_version=$EXPECTED_L1_PATCH_VERSION"* ]] &&
    pass "expected L1 patch version" || fail "unexpected L1 patch version"
[[ "$manifest" == *"ticket_protection=tee_aes_gcm_literal_scenario_b"* ]] &&
    pass "Scenario B ticket protection active" || fail "Scenario B ticket protection inactive"
[[ "$manifest" == *"certificate_verify_backend=tee"* ]] &&
    pass "Scenario C signing active" || fail "Scenario C signing inactive"
[[ "$manifest" == *"crypto_backend_registered=on"* ]] &&
    pass "Scenario D4 backend active" || fail "Scenario D4 backend inactive"
[[ "$config_manifest" == *"session_tickets=on"* &&
   "$config_manifest" == *"session_cache=off"* ]] &&
    pass "ticket/cache configuration correct" || fail "ticket/cache configuration wrong"

for key in \
    hs_fail ticket_parse_fail ticket_write_fail \
    km_init_fail km_selftest_fail km_wrap_fail km_unwrap_fail \
    sign_init_fail sign_import_fail sign_selftest_fail sign_fail \
    tee_init_fail tee_selftest_fail backend_conn_init_fail \
    tee_conn_open_fail tee_conn_close_fail backend_transform_import_fail \
    tee_transform_import_fail tee_transform_free_fail record_seal_fail \
    record_open_fail backend_hs_keys_fail tee_hs_keys_fail \
    backend_app_keys_fail tee_app_keys_fail finished_fail \
    tee_finished_fail backend_server_key_share_fail \
    tee_server_key_share_fail backend_resumption_master_fail \
    tee_resumption_master_fail backend_resumption_psk_fail \
    tee_resumption_psk_fail ssl_read_fail ssl_write_fail; do
    check_eq "$key" 0 "$final_line"
done

check_eq accepted 2 "$final_line"
check_eq hs_ok 2 "$final_line"
check_eq echo_responses 2 "$final_line"

check_eq km_init_ok 1 "$final_line"
check_eq km_selftest_ok 1 "$final_line"
check_gt km_wrap_ok "$final_line"
check_gt km_unwrap_ok "$final_line"

check_eq sign_init_ok 1 "$final_line"
check_eq sign_import_ok 1 "$final_line"
check_eq sign_selftest_ok 1 "$final_line"
check_eq sign_ok 1 "$final_line"

check_eq tee_init_ok 1 "$final_line"
check_eq tee_selftest_ok 1 "$final_line"
check_eq backend_conn_init_ok 2 "$final_line"
check_eq backend_conn_free 2 "$final_line"
check_eq backend_server_key_share_ok 2 "$final_line"
check_eq backend_hs_keys_ok 2 "$final_line"
check_eq backend_app_keys_ok 2 "$final_line"
check_eq finished_ok 4 "$final_line"
check_gt backend_resumption_master_ok "$final_line"
check_gt backend_resumption_psk_ok "$final_line"
check_gt record_seal_ok "$final_line"
check_gt record_open_ok "$final_line"

grep -q 'async_sign_start' "$OUT_DIR/server.log" &&
    pass "Scenario C callback observed" || fail "Scenario C callback not observed"
grep -q 'd4_backend_handshake_keys .*psk_len=0' "$OUT_DIR/server.log" &&
    pass "full handshake entered D4 without PSK" || fail "full D4 handshake marker missing"
grep -Eq 'd4_backend_handshake_keys .*psk_len=[1-9][0-9]*' "$OUT_DIR/server.log" &&
    pass "resumed handshake passed PSK into D4" || fail "resumed D4 PSK marker missing"
grep -q 'ticket_blob direction=write' "$OUT_DIR/server.log" &&
    pass "protected ticket write observed" || fail "protected ticket write marker missing"
grep -q 'ticket_blob direction=parse' "$OUT_DIR/server.log" &&
    pass "protected ticket parse observed" || fail "protected ticket parse marker missing"

record "RESULT pass=$PASS_COUNT fail=$FAIL_COUNT warn=$WARN_COUNT"
if (( FAIL_COUNT == 0 )); then
    record "VERDICT: Scenario E Case A passed literal B+C+D composition."
    exit 0
fi
record "VERDICT: Scenario E Case A failed."
exit 1
