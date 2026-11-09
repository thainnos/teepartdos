#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"
require_root
require_cmd timeout
require_cmd tee

TESTPMD="$(find_testpmd)"
TESTPMD_MAIN_LCORE="${TESTPMD_MAIN_LCORE:-0}"
TESTPMD_FWD_LCORE="${TESTPMD_FWD_LCORE:-2}"
TESTPMD_LINK_SETTLE_SECONDS="${TESTPMD_LINK_SETTLE_SECONDS:-4}"
TESTPMD_RUN_SECONDS="${TESTPMD_RUN_SECONDS:-8}"
TESTPMD_TIMEOUT_SECONDS="${TESTPMD_TIMEOUT_SECONDS:-30}"
TESTPMD_EXPECTED_SPEED_MBPS="${TESTPMD_EXPECTED_SPEED_MBPS:-1000}"

is_uint() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

cpu_online() {
    local cpu="$1"
    local online_file="/sys/devices/system/cpu/cpu${cpu}/online"
    [[ -d "/sys/devices/system/cpu/cpu${cpu}" ]] || return 1
    [[ ! -f "$online_file" || "$(cat "$online_file")" == "1" ]]
}

for value_name in \
    TESTPMD_MAIN_LCORE \
    TESTPMD_FWD_LCORE \
    TESTPMD_LINK_SETTLE_SECONDS \
    TESTPMD_RUN_SECONDS \
    TESTPMD_TIMEOUT_SECONDS \
    TESTPMD_EXPECTED_SPEED_MBPS; do
    value="${!value_name}"
    is_uint "$value" || {
        echo "$value_name must be an unsigned integer, got '$value'." >&2
        exit 1
    }
done

minimum_timeout=$((TESTPMD_LINK_SETTLE_SECONDS + TESTPMD_RUN_SECONDS + 5))
if (( TESTPMD_TIMEOUT_SECONDS < minimum_timeout )); then
    echo "TESTPMD_TIMEOUT_SECONDS must be at least $minimum_timeout for the configured settle/run periods." >&2
    exit 1
fi

[[ "$TESTPMD_MAIN_LCORE" != "$TESTPMD_FWD_LCORE" ]] || {
    echo "testpmd requires a separate forwarding lcore; main and forwarding lcores cannot both be $TESTPMD_MAIN_LCORE." >&2
    exit 1
}

cpu_online "$TESTPMD_MAIN_LCORE" || {
    echo "Main lcore CPU $TESTPMD_MAIN_LCORE is absent or offline." >&2
    exit 1
}
cpu_online "$TESTPMD_FWD_LCORE" || {
    echo "Forwarding lcore CPU $TESTPMD_FWD_LCORE is absent or offline." >&2
    exit 1
}

main_core_id="$(cat "/sys/devices/system/cpu/cpu${TESTPMD_MAIN_LCORE}/topology/core_id" 2>/dev/null || true)"
fwd_core_id="$(cat "/sys/devices/system/cpu/cpu${TESTPMD_FWD_LCORE}/topology/core_id" 2>/dev/null || true)"
if [[ -n "$main_core_id" && "$main_core_id" == "$fwd_core_id" ]]; then
    echo "WARNING: CPUs $TESTPMD_MAIN_LCORE and $TESTPMD_FWD_LCORE are SMT siblings on physical core $main_core_id." >&2
    echo "         Use different physical cores for a cleaner preflight." >&2
fi

current="$(basename "$(readlink -f "/sys/bus/pci/devices/$GENERATOR_PCI/driver" 2>/dev/null || true)")"
[[ "$current" == "vfio-pci" ]] || {
    echo "$GENERATOR_PCI is bound to '$current', not vfio-pci" >&2
    exit 1
}

mkdir -p "$PROJECT_ROOT/state"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
log_file="$PROJECT_ROOT/state/testpmd-preflight-${timestamp}.log"
file_prefix="tlsgen-testpmd-$$"

cat <<INFO
== testpmd preflight ==
binary:             $TESTPMD
PCI device:         $GENERATOR_PCI
main lcore:         $TESTPMD_MAIN_LCORE
forwarding lcore:   $TESTPMD_FWD_LCORE
link settle period: ${TESTPMD_LINK_SETTLE_SECONDS}s
run duration:       ${TESTPMD_RUN_SECONDS}s
expected speed:     ${TESTPMD_EXPECTED_SPEED_MBPS} Mbps
log:                $log_file
INFO

# The kernel interface disappears after vfio-pci binding, but the physical link
# should still be initialized and reported by the DPDK PMD. Wait before the
# first explicit status query to avoid interpreting autonegotiation/startup as a
# persistent link failure. DPDK versions emit either `Link status: up` or the
# startup form `Port 0 Link Up - speed ...`; validation below accepts both.
set +e
{
    sleep "$TESTPMD_LINK_SETTLE_SECONDS"
    printf 'show port info all\n'
    printf 'show config fwd\n'
    printf 'start\n'
    sleep "$TESTPMD_RUN_SECONDS"
    printf 'show port info all\n'
    printf 'show port stats all\n'
    printf 'stop\n'
    printf 'show port stats all\n'
    printf 'quit\n'
} | timeout --signal=INT --kill-after=3s "${TESTPMD_TIMEOUT_SECONDS}s" \
    "$TESTPMD" \
        -l "${TESTPMD_MAIN_LCORE},${TESTPMD_FWD_LCORE}" \
        --main-lcore "$TESTPMD_MAIN_LCORE" \
        -n 2 \
        -a "$GENERATOR_PCI" \
        --file-prefix="$file_prefix" \
        -- \
        -i \
        --rxq=1 \
        --txq=1 \
        --nb-cores=1 \
        --nb-ports=1 \
        --portmask=0x1 \
        --forward-mode=rxonly \
    2>&1 | tee "$log_file"
pipeline_status=("${PIPESTATUS[@]}")
set -e

testpmd_rc="${pipeline_status[1]:-1}"
tee_rc="${pipeline_status[2]:-1}"

if [[ "$tee_rc" -ne 0 ]]; then
    echo "Failed to write testpmd output to $log_file (tee status $tee_rc)." >&2
    exit "$tee_rc"
fi
if [[ "$testpmd_rc" -ne 0 ]]; then
    echo "testpmd failed with status $testpmd_rc; see $log_file" >&2
    exit "$testpmd_rc"
fi

fail=0
if ! grep -Fq "device: $GENERATOR_PCI" "$log_file"; then
    echo "PRE-FLIGHT: PMD probe for $GENERATOR_PCI was not found in testpmd output." >&2
    fail=1
fi
if grep -Eq 'No cores defined for forwarding|Cause: No cores defined for forwarding' "$log_file"; then
    echo "PRE-FLIGHT: testpmd did not obtain a forwarding lcore." >&2
    fail=1
fi

link_up_regex='Link[[:space:]]+status:[[:space:]]*up|Port[[:space:]]+[0-9]+[[:space:]]+Link[[:space:]]+Up'
if ! grep -Eqi "$link_up_regex" "$log_file"; then
    echo "PRE-FLIGHT: port link is not up." >&2
    fail=1
fi

speed_ok=0
if grep -Eqi "Link[[:space:]]+speed:[[:space:]]*${TESTPMD_EXPECTED_SPEED_MBPS}[[:space:]]*Mbps" "$log_file"; then
    speed_ok=1
elif grep -Eqi "Port[[:space:]]+[0-9]+[[:space:]]+Link[[:space:]]+Up[[:space:]]*-[[:space:]]*speed[[:space:]]+${TESTPMD_EXPECTED_SPEED_MBPS}[[:space:]]+Mbps" "$log_file"; then
    speed_ok=1
elif [[ "$TESTPMD_EXPECTED_SPEED_MBPS" == "1000" ]] && \
     grep -Eqi 'Link[[:space:]]+speed:[[:space:]]*1([.]0+)?[[:space:]]*Gbps|Port[[:space:]]+[0-9]+[[:space:]]+Link[[:space:]]+Up[[:space:]]*-[[:space:]]*speed[[:space:]]+1([.]0+)?[[:space:]]+Gbps' "$log_file"; then
    speed_ok=1
fi
if [[ "$speed_ok" -ne 1 ]]; then
    echo "PRE-FLIGHT: expected ${TESTPMD_EXPECTED_SPEED_MBPS} Mbps link speed was not confirmed." >&2
    fail=1
fi

if ! grep -Eqi '(io|rxonly|RX-only)[[:space:]]+packet forwarding' "$log_file"; then
    echo "PRE-FLIGHT: forwarding configuration was not confirmed in testpmd output." >&2
    fail=1
fi

if [[ "$fail" -ne 0 ]]; then
    echo "Relevant link-status lines from testpmd:" >&2
    grep -Ei 'Checking link|Port[[:space:]]+[0-9]+[[:space:]]+Link|Link[[:space:]]+status|Link[[:space:]]+speed|duplex|Configuring Port' "$log_file" >&2 || true
    echo "testpmd preflight: FAIL; inspect $log_file" >&2
    exit 1
fi

echo "testpmd preflight: PASS"
echo "The Intel PMD initialized, one forwarding core was assigned, and the ${TESTPMD_EXPECTED_SPEED_MBPS} Mbps link was up."
echo "Inspect RX/TX/error counters in $log_file before continuing."
