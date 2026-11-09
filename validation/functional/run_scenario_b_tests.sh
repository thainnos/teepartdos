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
SERVER_LOG="${SERVER_LOG:-/root/scenarios/b/tls_echo_server_b.log}"
ALLOW_CERT_IP_MISMATCH=0
MAX_CLOCK_SKEW_SEC="${MAX_CLOCK_SKEW_SEC:-5}"
EXPECTED_DEBUG_LEVEL="${EXPECTED_DEBUG_LEVEL:-3}"

usage() {
    cat <<USAGE
Usage: $0 [options]

Options:
  --board-ip <ip>              Server IP (default: $BOARD_IP)
  --port <port>                TLS port (default: $PORT)
  --ca-file <path>             CA/server certificate (default: $CA_FILE)
  --out-root <dir>             Parent result directory (default: $OUT_ROOT)
  --session-wait-sec <n>       Wait for TLS 1.3 NewSessionTicket (default: $SESSION_WAIT_SEC)
  --stability-runs <n>         Repeated resumption attempts (default: $STABILITY_RUNS)
  --ssh-target <user@host>     Optional target used to collect the server log
  --server-log <path>          Remote server log (default: $SERVER_LOG)
  --allow-cert-ip-mismatch     Record IP mismatch as warning, not required-test failure
  --max-clock-skew-sec <n>     Warn if board/client UTC skew exceeds this value (default: $MAX_CLOCK_SKEW_SEC)
  --expected-debug-level <0-4> Expected server debug level; mismatch is a warning (default: $EXPECTED_DEBUG_LEVEL)
  --help                       Show this help

The Scenario B server must already be running with:
  --session-tickets on --session-cache off --tee-derive-on-handshake off
For the supplied debug version, also use:
  --tee-selftest on --ticket-debug-hashes on --log-mode debug --debug-level 3
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
        --allow-cert-ip-mismatch) ALLOW_CERT_IP_MISMATCH=1; shift ;;
        --max-clock-skew-sec) MAX_CLOCK_SKEW_SEC="$2"; shift 2 ;;
        --expected-debug-level) EXPECTED_DEBUG_LEVEL="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

for cmd in openssl timeout sha256sum grep awk sed date tee seq cp mv; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "ERROR: required command not found: $cmd" >&2
        exit 2
    }
done
if [[ -n "$SSH_TARGET" ]] && ! command -v ssh >/dev/null 2>&1; then
    echo "ERROR: --ssh-target requires the ssh command." >&2
    exit 2
fi
[[ -r "$CA_FILE" ]] || { echo "ERROR: certificate not readable: $CA_FILE" >&2; exit 2; }

[[ "$MAX_CLOCK_SKEW_SEC" =~ ^[0-9]+$ ]] || {
    echo "ERROR: --max-clock-skew-sec must be a non-negative integer." >&2
    exit 2
}
[[ "$EXPECTED_DEBUG_LEVEL" =~ ^[0-4]$ ]] || {
    echo "ERROR: --expected-debug-level must be between 0 and 4." >&2
    exit 2
}

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$OUT_ROOT/scenario-b-m0-$STAMP"
SESSION="$OUT_DIR/scenario-b-session.pem"
SESSION_NEXT="$OUT_DIR/scenario-b-session-next.pem"
SUMMARY="$OUT_DIR/summary.txt"
mkdir -p "$OUT_DIR/stability"
chmod 700 "$OUT_DIR"
: > "$SUMMARY"

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

record() {
    printf '%s\n' "$*" | tee -a "$SUMMARY"
}
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
        "tail -n 5000 '$SERVER_LOG'" >"$destination" 2>&1
    local rc=$?
    set -e
    return "$rc"
}

get_remote_epoch() {
    [[ -n "$SSH_TARGET" ]] || return 1
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$SSH_TARGET" 'date +%s' 2>/dev/null
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
        tee_wrap_ok tee_wrap_fail \
        tee_unwrap_ok tee_unwrap_fail \
        echo_responses; do
        value="$(extract_counter "$key" "$file" || true)"
        if [[ "$value" =~ ^[0-9]+$ ]]; then
            BEFORE_COUNTERS["$key"]="$value"
        fi
    done
}

counter_observation() {
    # Output: "<observed> <mode> <before-or-na> <after>"
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
        observed="$after"
        mode="absolute"
        printf '%s %s %s %s\n' "$observed" "$mode" "n/a" "$after"
    fi
}

set -e
record "Scenario B M0 test run"
record "UTC start: $(date -u --iso-8601=seconds)"
record "Endpoint: ${BOARD_IP}:${PORT}"
record "CA file: $CA_FILE"
record "Output: $OUT_DIR"
record "OpenSSL: $(openssl version)"
record "Expected profile: TLSv1.3 / TLS_AES_128_GCM_SHA256 / P-256 / ECDSA P-256"
record ""

{
    uname -a
    openssl version -a
    printf 'BOARD_IP=%s\nPORT=%s\nCA_FILE=%s\nSESSION_WAIT_SEC=%s\nSTABILITY_RUNS=%s\n' \
        "$BOARD_IP" "$PORT" "$CA_FILE" "$SESSION_WAIT_SEC" "$STABILITY_RUNS"
    printf 'MAX_CLOCK_SKEW_SEC=%s\nEXPECTED_DEBUG_LEVEL=%s\n' \
        "$MAX_CLOCK_SKEW_SEC" "$EXPECTED_DEBUG_LEVEL"
    sha256sum "$CA_FILE"
} > "$OUT_DIR/environment.txt" 2>&1

openssl x509 -in "$CA_FILE" -noout -subject -issuer -dates -fingerprint -sha256 \
    -ext subjectAltName > "$OUT_DIR/certificate.txt" 2>&1 || true

# Certificate identity is checked locally. This avoids creating an intentional
# failed TLS handshake that would contaminate the server's hs_fail counter.
if openssl x509 -in "$CA_FILE" -noout -checkip "$BOARD_IP" \
    >"$OUT_DIR/certificate-ip-check.txt" 2>&1; then
    pass "certificate IP identity matches $BOARD_IP"
else
    if ((ALLOW_CERT_IP_MISMATCH)); then
        warn "certificate IP identity does not match $BOARD_IP"
    else
        fail "certificate IP identity does not match $BOARD_IP"
    fi
fi

# Optional clock correlation check when SSH access is available.
if [[ -n "$SSH_TARGET" ]]; then
    client_epoch="$(date +%s)"
    board_epoch="$(get_remote_epoch || true)"
    if [[ "$board_epoch" =~ ^[0-9]+$ ]]; then
        clock_skew=$((client_epoch - board_epoch))
        ((clock_skew < 0)) && clock_skew=$((-clock_skew))
        printf 'client_epoch=%s\nboard_epoch=%s\nabsolute_skew_sec=%s\n' \
            "$client_epoch" "$board_epoch" "$clock_skew" > "$OUT_DIR/clock-skew.txt"
        if ((clock_skew <= MAX_CLOCK_SKEW_SEC)); then
            pass "board/client clock skew is ${clock_skew}s"
        else
            warn "board/client clock skew is ${clock_skew}s (limit ${MAX_CLOCK_SKEW_SEC}s)"
        fi
    else
        warn "could not read board epoch for clock-skew check"
    fi
fi

if collect_server_log "$OUT_DIR/server-before.log"; then
    manifest="$(grep 'manifest bind=' "$OUT_DIR/server-before.log" | tail -n 1)"
    if [[ -n "$manifest" ]]; then
        contains <(printf '%s\n' "$manifest") 'session_tickets=on' && pass "server manifest: session tickets enabled" || fail "server manifest does not show session_tickets=on"
        contains <(printf '%s\n' "$manifest") 'session_cache=off' && pass "server manifest: session cache disabled" || fail "server manifest does not show session_cache=off"
        contains <(printf '%s\n' "$manifest") 'tee_derive_on_handshake=off' && pass "server manifest: optional derive call disabled" || warn "server manifest does not show tee_derive_on_handshake=off"
        contains "$OUT_DIR/server-before.log" 'tls13_kex_modes=ephemeral\+psk_ephemeral' && \
            pass "server manifest: TLS 1.3 ephemeral and PSK-ephemeral modes enabled" || \
            fail "server manifest does not show tls13_kex_modes=ephemeral+psk_ephemeral"
        contains <(printf '%s\n' "$manifest") 'log_mode=debug' && \
            pass "server manifest: debug log mode enabled" || \
            warn "server manifest does not show log_mode=debug"
        if contains <(printf '%s\n' "$manifest") "debug_level=${EXPECTED_DEBUG_LEVEL}([[:space:]]|$)"; then
            pass "server manifest: debug_level=$EXPECTED_DEBUG_LEVEL"
        else
            warn "server manifest does not show debug_level=$EXPECTED_DEBUG_LEVEL"
        fi
    else
        warn "could not find startup manifest in remote server log tail"
    fi
    capture_before_counters "$OUT_DIR/server-before.log"
else
    warn "could not collect remote server log before testing; absolute counter checks will be used"
fi

COMMON_ARGS=(
    -connect "${BOARD_IP}:${PORT}"
    -tls1_3
    -ciphersuites TLS_AES_128_GCM_SHA256
    -groups P-256
    -sigalgs ecdsa_secp256r1_sha256
    -CAfile "$CA_FILE"
)

# 1. Full handshake and echo.
if run_client "$OUT_DIR/01-full-handshake.log" "M0 B full handshake" 1 "${COMMON_ARGS[@]}" -brief; then
    if contains "$OUT_DIR/01-full-handshake.log" 'Protocol version: TLSv1\.3' &&
       contains "$OUT_DIR/01-full-handshake.log" 'Ciphersuite: TLS_AES_128_GCM_SHA256' &&
       contains "$OUT_DIR/01-full-handshake.log" '^M0 B full handshake$'; then
        pass "full TLS 1.3 handshake and echo"
    else
        fail "full handshake output does not match the fixed profile or echo payload"
    fi
else
    fail "full handshake command failed"
fi

# 2. Initial connection and ticket capture.
rm -f "$SESSION" "$SESSION_NEXT"
if run_client "$OUT_DIR/03-ticket-seed.log" "ticket seed" "$SESSION_WAIT_SEC" \
    "${COMMON_ARGS[@]}" -sess_out "$SESSION"; then
    :
else
    warn "ticket-seed s_client returned non-zero; checking whether a session was still saved"
fi

if [[ -s "$SESSION" ]]; then
    chmod 600 "$SESSION"
    pass "TLS 1.3 session saved"
    sha256sum "$SESSION" > "$OUT_DIR/session.sha256"
    openssl sess_id -in "$SESSION" -text -noout > "$OUT_DIR/session-metadata.raw.txt" 2>&1 || true
    awk '
        /Resumption PSK:/ { print "    Resumption PSK: [REDACTED]"; next }
        /TLS session ticket:/ { print "    TLS session ticket: [REDACTED]"; redact=1; next }
        redact && /^[[:space:]]*[0-9a-fA-F]{4}[[:space:]]*-/ { next }
        redact { redact=0 }
        { print }
    ' "$OUT_DIR/session-metadata.raw.txt" > "$OUT_DIR/session-metadata-redacted.txt"
    rm -f "$OUT_DIR/session-metadata.raw.txt"
    if contains "$OUT_DIR/session-metadata-redacted.txt" 'Protocol[[:space:]]*:[[:space:]]*TLSv1\.3' &&
       contains "$OUT_DIR/session-metadata-redacted.txt" 'Cipher[[:space:]]*:[[:space:]]*TLS_AES_128_GCM_SHA256' &&
       contains "$OUT_DIR/session-metadata-redacted.txt" 'Max Early Data:[[:space:]]*0'; then
        pass "saved session matches profile and has 0-RTT disabled"
    else
        fail "saved session metadata does not match expected TLS profile"
    fi
else
    fail "no session PEM was created"
fi

# 3. Resumption and fresh ticket.
if [[ -s "$SESSION" ]]; then
    if run_client "$OUT_DIR/04-resumption.log" "resumed connection" 2 \
        "${COMMON_ARGS[@]}" -sess_in "$SESSION" -sess_out "$SESSION_NEXT"; then
        :
    else
        warn "resumption s_client returned non-zero; evaluating its transcript"
    fi

    if contains "$OUT_DIR/04-resumption.log" '^Reused, TLSv1\.3'; then
        pass "saved ticket produced an actual resumed TLS 1.3 handshake"
    else
        fail "ticket was presented but the handshake was new, not resumed"
    fi
    contains "$OUT_DIR/04-resumption.log" '^resumed connection$' && \
        pass "application echo works after resumption attempt" || \
        fail "application echo missing after resumption attempt"
else
    fail "resumption skipped because the session PEM is unavailable"
fi

# 4. Explicit resumed echo using quiet mode.
if [[ -s "$SESSION" ]]; then
    if run_client "$OUT_DIR/05-resumed-echo.log" "scenario B resumed echo" 1 \
        "${COMMON_ARGS[@]}" -sess_in "$SESSION" -quiet; then
        :
    fi
    contains "$OUT_DIR/05-resumed-echo.log" '^scenario B resumed echo$' && \
        pass "resumed-path echo payload returned" || \
        fail "resumed-path echo payload missing"
fi

# 5. Repeated resumption stability. Rotate to the fresh ticket issued by each run.
stability_failures=0
if [[ -s "$SESSION" ]]; then
    stability_session="$OUT_DIR/stability/current-session.pem"
    cp "$SESSION" "$stability_session"
    chmod 600 "$stability_session"
    for i in $(seq 1 "$STABILITY_RUNS"); do
        run_file="$OUT_DIR/stability/run-$(printf '%02d' "$i").log"
        next_session="$OUT_DIR/stability/next-session.pem"
        payload="resume test $(printf '%02d' "$i")"
        rm -f "$next_session"
        run_client "$run_file" "$payload" 2 \
            "${COMMON_ARGS[@]}" -sess_in "$stability_session" -sess_out "$next_session" || true
        if ! contains "$run_file" '^Reused, TLSv1\.3' || ! grep -Fxq "$payload" "$run_file"; then
            stability_failures=$((stability_failures + 1))
        fi
        if [[ -s "$next_session" ]]; then
            chmod 600 "$next_session"
            mv "$next_session" "$stability_session"
        else
            stability_failures=$((stability_failures + 1))
            warn "stability run $i did not save a replacement ticket"
        fi
    done
    if ((stability_failures == 0)); then
        pass "$STABILITY_RUNS sequential resumptions completed with echo and ticket rotation"
    else
        fail "$stability_failures stability checks failed across $STABILITY_RUNS resumption runs"
    fi
fi

# 6. Server-side counters and diagnostics.
if collect_server_log "$OUT_DIR/server-after.log"; then
    counter_file="$OUT_DIR/server-after.log"
    for key in tee_wrap_ok ticket_write_ok ticket_parse_ok tee_unwrap_ok; do
        observation="$(counter_observation "$key" "$counter_file" || true)"
        if [[ "$observation" =~ ^([0-9]+)[[:space:]]+(delta|absolute)[[:space:]]+([^[:space:]]+)[[:space:]]+([0-9]+)$ ]]; then
            observed="${BASH_REMATCH[1]}"
            mode="${BASH_REMATCH[2]}"
            before="${BASH_REMATCH[3]}"
            after="${BASH_REMATCH[4]}"
            if ((observed > 0)); then
                pass "server counter $key observed=$observed mode=$mode before=$before after=$after"
            else
                fail "server counter $key did not increase (mode=$mode before=$before after=$after)"
            fi
        else
            fail "server counter $key could not be extracted"
        fi
    done

    for key in ticket_write_fail ticket_parse_fail tee_wrap_fail tee_unwrap_fail hs_fail; do
        observation="$(counter_observation "$key" "$counter_file" || true)"
        if [[ "$observation" =~ ^([0-9]+)[[:space:]]+(delta|absolute)[[:space:]]+([^[:space:]]+)[[:space:]]+([0-9]+)$ ]]; then
            observed="${BASH_REMATCH[1]}"
            mode="${BASH_REMATCH[2]}"
            before="${BASH_REMATCH[3]}"
            after="${BASH_REMATCH[4]}"
            if ((observed == 0)); then
                pass "server counter $key added=0 mode=$mode before=$before after=$after"
            else
                fail "server counter $key added=$observed mode=$mode before=$before after=$after"
            fi
        else
            warn "server counter $key could not be extracted"
        fi
    done

    grep -E 'tee_km_selftest|tee_call_failed|ticket_blob|ticket_session_load_failed|key exchange mode|Found PSK|manifest |\] (SUMRY|FINAL) ' \
        "$counter_file" > "$OUT_DIR/server-diagnostics-filtered.log" || true

    if grep -Eq 'key exchange mode: psk_ephemeral|Found PSK_EPHEMERAL KEX MODE' "$counter_file"; then
        pass "server debug trace confirms PSK-ephemeral resumption mode"
    else
        warn "server debug trace does not explicitly show PSK-ephemeral mode; OpenSSL Reused result remains authoritative"
    fi
else
    warn "remote server log was not collected; server-side counter checks skipped"
fi

record ""
record "PASS=$PASS_COUNT FAIL=$FAIL_COUNT WARN=$WARN_COUNT"
if ((FAIL_COUNT == 0)); then
    record "VERDICT: Scenario B M0 PASS"
    exit 0
else
    record "VERDICT: Scenario B M0 NOT PASSED"
    exit 1
fi

