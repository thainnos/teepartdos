#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$ROOT/tests/.scheduler-stall"
BIN="$ROOT/bin/tls_loadgen_posix"
PORT="${TLSGEN_STALL_TEST_PORT:-19443}"
SERVER_PID=""
GEN_PID=""

cleanup() {
    if [[ -n "$GEN_PID" ]]; then
        kill -CONT "$GEN_PID" 2>/dev/null || true
        kill "$GEN_PID" 2>/dev/null || true
        wait "$GEN_PID" 2>/dev/null || true
    fi
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

rm -rf "$TMP"
mkdir -p "$TMP/results"

OSSL="$(command -v openssl)"
OSSL_CFLAGS="$(pkg-config --cflags openssl)"
OSSL_LIBS="$(pkg-config --libs openssl)"

# shellcheck disable=SC2086
cc -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Werror $OSSL_CFLAGS \
    -o "$TMP/openssl_echo_server" "$ROOT/tests/openssl_echo_server.c" $OSSL_LIBS -pthread

"$OSSL" ecparam -name prime256v1 -genkey -noout -out "$TMP/key.pem"
"$OSSL" req -new -x509 -key "$TMP/key.pem" -sha256 -days 1 \
    -subj '/CN=tls-echo-server' -addext 'subjectAltName=DNS:tls-echo-server' \
    -out "$TMP/cert.pem"

TLSGEN_TEST_ECHO_DELAY_US=500 \
    "$TMP/openssl_echo_server" "$PORT" "$TMP/cert.pem" "$TMP/key.pem" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
    grep -q '^READY ' "$TMP/server.log" && break
    kill -0 "$SERVER_PID" 2>/dev/null || { cat "$TMP/server.log" >&2; exit 1; }
    sleep 0.05
done
grep -q '^READY ' "$TMP/server.log" || { cat "$TMP/server.log" >&2; exit 1; }

cat >"$TMP/record.conf" <<CFG
target.address=127.0.0.1
target.port=$PORT
network.source_address=127.0.0.1
network.netmask=255.0.0.0
network.interface=lo
network.mtu=1500
network.tcp_nodelay=true
tls.ca_file=$TMP/cert.pem
tls.server_name=tls-echo-server
tls.verify_peer=true
tls.verify_hostname=true
tls.ciphersuite=TLS_AES_128_GCM_SHA256
tls.group=P-256
tls.signature_algorithm=ecdsa_secp256r1_sha256
run.scenario=A
run.workload=record
run.mode=benign
run.rate_per_s=3000
run.duration_s=4
run.max_inflight=64
run.max_release_burst=4096
run.drain_timeout_ms=3000
timeout.tcp_connect_ms=2000
timeout.tls_handshake_ms=2000
timeout.io_ms=2000
payload.size=1024
payload.pattern_hex=a5
full.echo_after_handshake=true
resumption.session_policy=reuse_seed
resumption.pool_size=2
resumption.wait_for_fresh_ticket=true
record.connections=32
record.max_pending_releases=4096
record.reconnect=true
record.reconnect_backoff_ms=100
output.directory=$TMP/results
output.stdout_progress=false
fstack.conf=$ROOT/config/f-stack.conf.example
fstack.proc_id=0
CFG

"$BIN" --config "$TMP/record.conf" --backend posix --run-id scheduler-stall \
    >"$TMP/generator.stdout.log" 2>"$TMP/generator.stderr.log" &
GEN_PID=$!

STATS="$TMP/results/tls_loadgen_A_record_benign_scheduler-stall/generator_stats.csv"
for _ in $(seq 1 300); do
    if [[ -s "$STATS" ]] && grep -q ',run,' "$STATS"; then
        break
    fi
    kill -0 "$GEN_PID" 2>/dev/null || {
        cat "$TMP/generator.stdout.log" >&2
        cat "$TMP/generator.stderr.log" >&2
        exit 1
    }
    sleep 0.01
done
[[ -s "$STATS" ]] && grep -q ',run,' "$STATS" || {
    echo "generator did not enter run phase" >&2
    exit 1
}

# Reproduce the high-rate catch-up condition that used to create artificial
# record local-capacity drops: pause the event loop long enough for more than
# record.connections releases to become due at 3000 transactions/s.
kill -STOP "$GEN_PID"
sleep 0.025
kill -CONT "$GEN_PID"
wait "$GEN_PID"
GEN_PID=""

python3 - "$STATS" <<'PY'
import csv
import sys

with open(sys.argv[1], newline='', encoding='utf-8') as fh:
    rows = list(csv.DictReader(fh))
assert rows, sys.argv[1]
r = rows[-1]
offered = int(r['offered_total'])
attempted = int(r['attempted_total'])
completed = int(r['completed_total'])
local_drop = int(r['local_capacity_drop_total'])
pending_now = int(r['pending_release_current'])
pending_max = int(r['pending_release_max'])
lag_us = int(r['release_lag_max_us'])
assert offered > 0, r
assert attempted == offered, r
assert completed == offered, r
assert local_drop == 0, r
assert pending_now == 0, r
assert pending_max > 0, r
assert lag_us >= 10_000, r
print(
    f'record scheduler stall regression: PASS offered={offered} '
    f'pending_max={pending_max} release_lag_max_us={lag_us}'
)
PY

# A bounded queue must not hide genuine sustained local incapacity. With only
# two persistent connections, a deliberately tiny queue, and the delayed echo
# server, this offered rate is intentionally unsustainable and must preserve a
# nonzero local-capacity-drop result.
cat >"$TMP/overload.conf" <<CFG
target.address=127.0.0.1
target.port=$PORT
network.source_address=127.0.0.1
network.netmask=255.0.0.0
network.interface=lo
network.mtu=1500
network.tcp_nodelay=true
tls.ca_file=$TMP/cert.pem
tls.server_name=tls-echo-server
tls.verify_peer=true
tls.verify_hostname=true
tls.ciphersuite=TLS_AES_128_GCM_SHA256
tls.group=P-256
tls.signature_algorithm=ecdsa_secp256r1_sha256
run.scenario=A
run.workload=record
run.mode=benign
run.rate_per_s=5000
run.duration_s=1
run.max_inflight=16
run.max_release_burst=4096
run.drain_timeout_ms=3000
timeout.tcp_connect_ms=2000
timeout.tls_handshake_ms=2000
timeout.io_ms=2000
payload.size=1024
payload.pattern_hex=a5
full.echo_after_handshake=true
resumption.session_policy=reuse_seed
resumption.pool_size=2
resumption.wait_for_fresh_ticket=true
record.connections=2
record.max_pending_releases=8
record.reconnect=true
record.reconnect_backoff_ms=100
output.directory=$TMP/results
output.stdout_progress=false
fstack.conf=$ROOT/config/f-stack.conf.example
fstack.proc_id=0
CFG

"$BIN" --config "$TMP/overload.conf" --backend posix --run-id scheduler-overload \
    >"$TMP/overload.stdout.log" 2>"$TMP/overload.stderr.log"

OVERLOAD_STATS="$TMP/results/tls_loadgen_A_record_benign_scheduler-overload/generator_stats.csv"
python3 - "$OVERLOAD_STATS" <<'PY'
import csv
import sys

with open(sys.argv[1], newline='', encoding='utf-8') as fh:
    rows = list(csv.DictReader(fh))
assert rows, sys.argv[1]
r = rows[-1]
assert int(r['local_capacity_drop_total']) > 0, r
assert int(r['pending_release_current']) == 0, r
print(
    'record scheduler sustained-overload guard: PASS '
    f"offered={r['offered_total']} attempted={r['attempted_total']} "
    f"local_drop={r['local_capacity_drop_total']}"
)
PY
