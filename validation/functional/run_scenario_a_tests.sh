#!/usr/bin/env bash
set -uo pipefail

BOARD_IP="${BOARD_IP:-192.0.2.150}"
PORT="${PORT:-4433}"
CA_FILE="${CA_FILE:-CHANGE_ME_CA_CERT_PATH}"
OUT_ROOT="${OUT_ROOT:-./functional-results}"
SESSION_WAIT_SEC="${SESSION_WAIT_SEC:-5}"
STABILITY_RUNS="${STABILITY_RUNS:-10}"
COMMAND_TIMEOUT_SEC="${COMMAND_TIMEOUT_SEC:-25}"
SSH_TARGET="${SSH_TARGET:-root@192.0.2.150}"
SERVER_LOG="${SERVER_LOG:-/root/scenarios/a/tls_echo_server_a.log}"
SERVER_BINARY="${SERVER_BINARY:-/root/scenarios/tls_echo_server_scenario_a}"
MAX_CLOCK_SKEW_SEC="${MAX_CLOCK_SKEW_SEC:-5}"
EXPECTED_DEBUG_LEVEL="${EXPECTED_DEBUG_LEVEL:-3}"
EXPECTED_BUILD_ID="${EXPECTED_BUILD_ID:-scenario-a-m0-debug-v2}"

usage() {
    cat <<USAGE
Usage: $0 [options]

Options:
  --board-ip <ip>              Server IP (default: $BOARD_IP)
  --port <port>                TLS port (default: $PORT)
  --ca-file <path>             Trusted server certificate (default: $CA_FILE)
  --out-root <dir>             Parent result directory (default: $OUT_ROOT)
  --session-wait-sec <n>       Wait for TLS 1.3 NewSessionTicket (default: $SESSION_WAIT_SEC)
  --stability-runs <n>         Repeated resumption attempts (default: $STABILITY_RUNS)
  --ssh-target <user@host>     Optional target used to collect the server log
  --server-log <path>          Remote server log (default: $SERVER_LOG)
  --server-binary <path>       Remote server executable (default: $SERVER_BINARY)
  --max-clock-skew-sec <n>     Warn if board/client UTC skew exceeds this value (default: $MAX_CLOCK_SKEW_SEC)
  --expected-debug-level <0-4> Expected server debug level; mismatch is a warning (default: $EXPECTED_DEBUG_LEVEL)
  --expected-build-id <id>     Expected Scenario A build marker (default: $EXPECTED_BUILD_ID)
  --help                       Show this help

The Scenario A server must already be running with:
  --session-tickets on --session-cache off
For M0 diagnostics, also use:
  --log-mode debug --debug-level 3
USAGE
}

while (($#)); do
    case "$1" in
        --board-ip) BOARD_IP="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --ca-file) CA_FILE="$2"; shift 2 ;;
        --out-root) OUT_ROOT="$2"; shift 2 ;;
        --session-wait-sec) SESSION_WAIT_SEC="$2"; shift 2 ;;
        --stability-runs) STABILITY_RUNS="$2"; shift 2 ;;
        --ssh-target) SSH_TARGET="$2"; shift 2 ;;
        --server-log) SERVER_LOG="$2"; shift 2 ;;
        --server-binary) SERVER_BINARY="$2"; shift 2 ;;
        --max-clock-skew-sec) MAX_CLOCK_SKEW_SEC="$2"; shift 2 ;;
        --expected-debug-level) EXPECTED_DEBUG_LEVEL="$2"; shift 2 ;;
        --expected-build-id) EXPECTED_BUILD_ID="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

for cmd in openssl timeout sha256sum grep awk sed date tee seq cp mv diff; do
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
[[ "$STABILITY_RUNS" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: --stability-runs must be positive." >&2; exit 2; }
[[ "$MAX_CLOCK_SKEW_SEC" =~ ^[0-9]+$ ]] || { echo "ERROR: --max-clock-skew-sec must be non-negative." >&2; exit 2; }
[[ "$EXPECTED_DEBUG_LEVEL" =~ ^[0-4]$ ]] || { echo "ERROR: --expected-debug-level must be 0-4." >&2; exit 2; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$OUT_ROOT/scenario-a-m0-$STAMP"
SESSION="$OUT_DIR/scenario-a-session.pem"
SESSION_NEXT="$OUT_DIR/scenario-a-session-next.pem"
SUMMARY="$OUT_DIR/summary.txt"
mkdir -p "$OUT_DIR/stability"
chmod 700 "$OUT_DIR"
: > "$SUMMARY"

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
        mode="delta"
        printf '%s %s %s %s\n' "$observed" "$mode" "$before" "$after"
    else
        printf '%s absolute n/a %s\n' "$after" "$after"
    fi
}

check_counter_gt0() {
    local key="$1" file="$2" observation observed mode before after
    observation="$(counter_observation "$key" "$file" || true)"
    if [[ "$observation" =~ ^([0-9]+)[[:space:]]+(delta|absolute)[[:space:]]+([^[:space:]]+)[[:space:]]+([0-9]+)$ ]]; then
        observed="${BASH_REMATCH[1]}"; mode="${BASH_REMATCH[2]}"
        before="${BASH_REMATCH[3]}"; after="${BASH_REMATCH[4]}"
        if ((observed > 0)); then
            pass "server counter $key observed=$observed mode=$mode before=$before after=$after"
        else
            fail "server counter $key did not increase"
        fi
    else
        fail "server counter $key could not be extracted"
    fi
}

check_counter_zero() {
    local key="$1" file="$2" observation observed mode before after
    observation="$(counter_observation "$key" "$file" || true)"
    if [[ "$observation" =~ ^([0-9]+)[[:space:]]+(delta|absolute)[[:space:]]+([^[:space:]]+)[[:space:]]+([0-9]+)$ ]]; then
        observed="${BASH_REMATCH[1]}"; mode="${BASH_REMATCH[2]}"
        before="${BASH_REMATCH[3]}"; after="${BASH_REMATCH[4]}"
        if ((observed == 0)); then
            pass "server counter $key added=0 mode=$mode before=$before after=$after"
        else
            fail "server counter $key added=$observed mode=$mode before=$before after=$after"
        fi
    else
        warn "server counter $key could not be extracted"
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
record "Scenario A M0 verification"
record "UTC start: $(date -u --iso-8601=seconds)"
record "Endpoint: ${BOARD_IP}:${PORT}"
record "Output: $OUT_DIR"
record "Verification scope: common TLS profile plus normal-world ticket issuance/resumption"
record ""

{
    uname -a
    openssl version -a
    printf 'SERVER_BINARY=%s\n' "$SERVER_BINARY"
    printf 'BOARD_IP=%s\nPORT=%s\nCA_FILE=%s\nSESSION_WAIT_SEC=%s\nSTABILITY_RUNS=%s\n' \
        "$BOARD_IP" "$PORT" "$CA_FILE" "$SESSION_WAIT_SEC" "$STABILITY_RUNS"
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
        pass "remote Scenario A binary metadata collected"
    else
        warn "could not collect Scenario A binary metadata"
    fi
fi

if collect_server_log "$OUT_DIR/server-before.log"; then
    manifest="$(grep 'manifest bind=' "$OUT_DIR/server-before.log" | tail -n 1)"
    placement="$(grep 'manifest scenario=A ' "$OUT_DIR/server-before.log" | tail -n 1)"
    [[ -n "$manifest" ]] || warn "runtime manifest not found in server log"
    [[ -n "$placement" ]] || warn "placement manifest not found in server log"

    contains <(printf '%s\n' "$placement") "build=${EXPECTED_BUILD_ID}([[:space:]]|$)" &&
        pass "manifest confirms build=$EXPECTED_BUILD_ID" ||
        fail "manifest does not show build=$EXPECTED_BUILD_ID"
    contains <(printf '%s\n' "$placement") 'placement=normal_world' &&
        pass "manifest identifies the Scenario A normal-world baseline" ||
        fail "manifest does not identify Scenario A"
    contains <(printf '%s\n' "$placement") 'private_key_op=normal_world' &&
        pass "manifest confirms normal-world private-key operation" ||
        fail "manifest does not confirm normal-world private-key operation"
    contains <(printf '%s\n' "$placement") 'ticket_protection=normal_world' &&
        pass "manifest confirms normal-world ticket protection" ||
        fail "manifest does not confirm normal-world ticket protection"
    contains <(printf '%s\n' "$placement") 'tls13_kex_modes=ephemeral\+psk_ephemeral' &&
        pass "manifest confirms full and resumed ECDHE modes" ||
        fail "manifest does not show ephemeral+psk_ephemeral"

    contains <(printf '%s\n' "$manifest") 'session_tickets=on' &&
        pass "server manifest: session tickets enabled" ||
        fail "server manifest does not show session_tickets=on"
    contains <(printf '%s\n' "$manifest") 'session_cache=off' &&
        pass "server manifest: session cache disabled" ||
        fail "server manifest does not show session_cache=off"
    contains <(printf '%s\n' "$manifest") 'strict_cert_profile=on' &&
        pass "server manifest: strict certificate profile enabled" ||
        fail "server manifest does not show strict_cert_profile=on"
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

# 1. Strictly verified full handshake, profile check, echo, and served-certificate match.
if run_client "$OUT_DIR/01-full-handshake.log" "M0 A full handshake" 1 \
    "${COMMON_ARGS[@]}" -showcerts; then
    if contains "$OUT_DIR/01-full-handshake.log" '^New, TLSv1\.3, Cipher is TLS_AES_128_GCM_SHA256' &&
       contains "$OUT_DIR/01-full-handshake.log" 'Peer signature type: ECDSA' &&
       contains "$OUT_DIR/01-full-handshake.log" 'Server Temp Key: ECDH, prime256v1, 256 bits' &&
       contains "$OUT_DIR/01-full-handshake.log" 'Verify return code: 0 \(ok\)' &&
       grep -Fxq 'M0 A full handshake' "$OUT_DIR/01-full-handshake.log"; then
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

# 2. Ticket generation and metadata.
rm -f "$SESSION" "$SESSION_NEXT"
run_client "$OUT_DIR/02-ticket-seed.log" "M0 A ticket seed" "$SESSION_WAIT_SEC" \
    "${COMMON_ARGS[@]}" -sess_out "$SESSION" || true

if [[ -s "$SESSION" ]]; then
    chmod 600 "$SESSION"
    pass "TLS 1.3 session ticket saved"
    openssl sess_id -in "$SESSION" -text -noout >"$OUT_DIR/session-metadata.raw.txt" 2>&1 || true
    awk '
        /Resumption PSK:/ { print "    Resumption PSK: [REDACTED]"; next }
        /TLS session ticket:/ { print "    TLS session ticket: [REDACTED]"; redact=1; next }
        redact && /^[[:space:]]*[0-9a-fA-F]{4}[[:space:]]*-/ { next }
        redact { redact=0 }
        { print }
    ' "$OUT_DIR/session-metadata.raw.txt" >"$OUT_DIR/session-metadata-redacted.txt"
    rm -f "$OUT_DIR/session-metadata.raw.txt"
    if contains "$OUT_DIR/session-metadata-redacted.txt" 'Protocol[[:space:]]*:[[:space:]]*TLSv1\.3' &&
       contains "$OUT_DIR/session-metadata-redacted.txt" 'Cipher[[:space:]]*:[[:space:]]*TLS_AES_128_GCM_SHA256' &&
       contains "$OUT_DIR/session-metadata-redacted.txt" 'Max Early Data:[[:space:]]*0'; then
        pass "saved session matches profile and keeps 0-RTT disabled"
    else
        fail "saved session metadata does not match the expected profile"
    fi
else
    fail "no session ticket file was created"
fi

# 3. Actual resumption.
if [[ -s "$SESSION" ]]; then
    run_client "$OUT_DIR/03-resumption.log" "M0 A resumed connection" 2 \
        "${COMMON_ARGS[@]}" -sess_in "$SESSION" -sess_out "$SESSION_NEXT" || true

    contains "$OUT_DIR/03-resumption.log" '^Reused, TLSv1\.3, Cipher is TLS_AES_128_GCM_SHA256' &&
        pass "saved ticket produced actual TLS 1.3 resumption" ||
        fail "saved ticket did not produce a resumed handshake"
    grep -Fxq 'M0 A resumed connection' "$OUT_DIR/03-resumption.log" &&
        pass "echo works after resumption" ||
        fail "echo missing after resumption"
fi

# 4. Repeated resumption with ticket rotation.
stability_failures=0
if [[ -s "$SESSION" ]]; then
    current="$OUT_DIR/stability/current-session.pem"
    cp "$SESSION" "$current"
    chmod 600 "$current"
    for i in $(seq 1 "$STABILITY_RUNS"); do
        run_file="$OUT_DIR/stability/run-$(printf '%02d' "$i").log"
        next="$OUT_DIR/stability/next-session.pem"
        payload="M0 A resume $(printf '%02d' "$i")"
        rm -f "$next"
        run_client "$run_file" "$payload" 2 \
            "${COMMON_ARGS[@]}" -sess_in "$current" -sess_out "$next" || true
        if ! contains "$run_file" '^Reused, TLSv1\.3, Cipher is TLS_AES_128_GCM_SHA256' ||
           ! grep -Fxq "$payload" "$run_file"; then
            stability_failures=$((stability_failures + 1))
        fi
        if [[ -s "$next" ]]; then
            chmod 600 "$next"
            mv "$next" "$current"
        else
            stability_failures=$((stability_failures + 1))
        fi
    done
    if ((stability_failures == 0)); then
        pass "$STABILITY_RUNS resumed handshakes completed with echo and ticket rotation"
    else
        fail "$stability_failures checks failed in the resumption stability sequence"
    fi
fi

# 5. Server evidence.
if collect_server_log "$OUT_DIR/server-after.log"; then
    counter_file="$OUT_DIR/server-after.log"
    for key in hs_ok ticket_write_ok ticket_parse_ok echo_responses; do
        check_counter_gt0 "$key" "$counter_file"
    done
    for key in hs_fail ticket_write_fail ticket_parse_fail ssl_read_fail ssl_write_fail; do
        check_counter_zero "$key" "$counter_file"
    done

    if grep -Eq 'key exchange mode: psk_ephemeral|Found PSK_EPHEMERAL KEX MODE' "$counter_file"; then
        pass "Mbed TLS debug trace confirms PSK-ephemeral resumption"
    else
        warn "server debug trace does not explicitly show PSK-ephemeral mode"
    fi

    grep -E 'manifest |key exchange mode|Found PSK|\] (SUMRY|FINAL) |handshake_failed|ticket_.*failed' \
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
