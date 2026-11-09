#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$ROOT/tests/.tmp"
BIN="$ROOT/bin/tls_loadgen_posix"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-}"
PORT="${TLSGEN_SMOKE_PORT:-18443}"
SERVER_PID=""

cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM
rm -rf "$TMP"
mkdir -p "$TMP/results"

if [[ -n "$OPENSSL_PREFIX" ]]; then
    OSSL="$OPENSSL_PREFIX/bin/openssl"
    PCDIR="$OPENSSL_PREFIX/lib/pkgconfig"
    LIBDIR="$OPENSSL_PREFIX/lib"
    export LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export OPENSSL_CONF="$TMP/openssl.cnf"
    [[ -d "$OPENSSL_PREFIX/lib/ossl-modules" ]] && export OPENSSL_MODULES="$OPENSSL_PREFIX/lib/ossl-modules"
else
    OSSL="$(command -v openssl)"
    PCDIR=""
fi

cat > "$TMP/openssl.cnf" <<'CNF'
openssl_conf = openssl_init
[openssl_init]
providers = providers
[providers]
default = default_sect
[default_sect]
activate = 1
CNF

if [[ -n "$PCDIR" ]]; then
    OSSL_CFLAGS="$(PKG_CONFIG_LIBDIR="$PCDIR" pkg-config --cflags openssl)"
    OSSL_LIBS="$(PKG_CONFIG_LIBDIR="$PCDIR" pkg-config --libs openssl) -Wl,-rpath,$OPENSSL_PREFIX/lib"
else
    OSSL_CFLAGS="$(pkg-config --cflags openssl)"
    OSSL_LIBS="$(pkg-config --libs openssl)"
fi

# shellcheck disable=SC2086
cc -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Werror $OSSL_CFLAGS \
    -o "$TMP/openssl_echo_server" "$ROOT/tests/openssl_echo_server.c" $OSSL_LIBS -pthread

"$OSSL" ecparam -name prime256v1 -genkey -noout -out "$TMP/key.pem"
"$OSSL" req -new -x509 -key "$TMP/key.pem" -sha256 -days 1 \
    -subj '/CN=tls-echo-server' -addext 'subjectAltName=DNS:tls-echo-server' \
    -out "$TMP/cert.pem"

"$TMP/openssl_echo_server" "$PORT" "$TMP/cert.pem" "$TMP/key.pem" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
    grep -q '^READY ' "$TMP/server.log" && break
    kill -0 "$SERVER_PID" 2>/dev/null || { cat "$TMP/server.log" >&2; exit 1; }
    sleep 0.1
done
grep -q '^READY ' "$TMP/server.log" || { cat "$TMP/server.log" >&2; exit 1; }

write_config() {
    local workload="$1" rate="$2"
    cat > "$TMP/$workload.conf" <<CFG
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
run.workload=$workload
run.mode=benign
run.rate_per_s=$rate
run.duration_s=2
run.max_inflight=32
run.max_release_burst=128
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
record.max_pending_releases=128
record.reconnect=true
record.reconnect_backoff_ms=100
output.directory=$TMP/results
output.stdout_progress=false
fstack.conf=$ROOT/config/f-stack.conf.example
fstack.proc_id=0
CFG
}

validate_run() {
    local workload="$1" runid="$2"
    local run_dir="$TMP/results/tls_loadgen_A_${workload}_benign_${runid}"
    local stats="$run_dir/generator_stats.csv"
    local timeline="$run_dir/generator.timeline.json"
    [[ -s "$stats" ]] || { echo "Missing stats: $stats" >&2; exit 1; }
    [[ -s "$timeline" ]] || { echo "Missing timeline: $timeline" >&2; exit 1; }
    python3 - "$workload" "$stats" "$timeline" "$runid" <<'PY'
import csv, json, sys
workload, path, timeline_path, runid = sys.argv[1:]
with open(path, newline='', encoding='utf-8') as f:
    rows=list(csv.DictReader(f))
assert rows, path
assert all(int(row['wall_time_utc_ns']) > 0 for row in rows), rows
r=rows[-1]
with open(timeline_path, encoding='utf-8') as f:
    timeline=json.load(f)
assert timeline['schema_version'] == 1, timeline
assert timeline['run_id'] == runid, timeline
assert timeline['workload'] == workload, timeline
assert timeline['generator_version'] == '0.1.5', timeline
import re
assert re.fullmatch(r'[0-9a-f]{12}', timeline['generator_git_commit']), timeline
assert timeline['current_phase'] == 'done', timeline
assert timeline['terminal'] is True, timeline
start=int(timeline['phase_run_started_utc_ns'])
deadline=int(timeline['phase_run_end_deadline_utc_ns'])
observed=int(timeline['phase_run_end_observed_utc_ns'])
finished=int(timeline['process_finished_utc_ns'])
assert start > 0 and deadline == start + 2_000_000_000, timeline
assert observed >= deadline, timeline
process_started=int(timeline['process_started_utc_ns'])
drain_finished=int(timeline['drain_finished_utc_ns'])
assert process_started > 0 and process_started <= start, timeline
assert observed >= deadline, timeline
assert drain_finished >= observed, timeline
assert finished >= drain_finished, timeline
assert max(int(row['wall_time_utc_ns']) for row in rows) <= finished, (rows, timeline)
assert timeline['run_end_reason'] == 'duration-complete', timeline
assert int(r['offered_total']) > 0, r
assert int(r['attempted_total']) == int(r['offered_total']), r
assert int(r['completed_total']) == int(r['offered_total']), r
assert int(r['pending_release_current']) == 0, r
assert int(r['pending_release_max']) >= 0, r
assert int(r['release_lag_max_us']) >= 0, r
for key in ('local_capacity_drop_total','session_unavailable_total','handshake_fail_total','profile_fail_total','app_fail_total','payload_fail_total','timeout_fail_total'):
    assert int(r[key]) == 0, (key,r[key],r)
if workload == 'full-handshake':
    assert int(r['full_handshake_ok_total']) == int(r['completed_total']), r
if workload == 'resumption':
    assert int(r['resumed_handshake_ok_total']) == int(r['completed_total']) + 1, r  # preflight
if workload == 'record':
    assert int(r['app_ok_total']) >= int(r['completed_total']) + 2, r  # setup echos
print(f'{workload}: PASS offered={r["offered_total"]} completed={r["completed_total"]}')
PY
}

write_config full-handshake 5
"$BIN" --config "$TMP/full-handshake.conf" --backend posix --run-id smoke-full
validate_run full-handshake smoke-full

write_config resumption 5
"$BIN" --config "$TMP/resumption.conf" --backend posix --run-id smoke-resume
validate_run resumption smoke-resume

write_config record 20
"$BIN" --config "$TMP/record.conf" --backend posix --run-id smoke-record
validate_run record smoke-record

echo "POSIX TLS load-generator smoke suite: PASS"
