#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"
require_root
require_cmd arping
require_cmd ip

ip link show "$GENERATOR_IF" >/dev/null 2>&1 || {
    echo "Interface $GENERATOR_IF is not available to Linux." >&2
    echo "Restore $GENERATOR_PCI to $LINUX_DRIVER before running this kernel-path check." >&2
    exit 1
}

expected="$(printf '%s' "$DUT_MAC" | tr '[:upper:]' '[:lower:]')"

set +e
arping_output="$(arping -I "$GENERATOR_IF" -c 3 -w 5 "$DUT_IP" 2>&1)"
arping_rc=$?
set -e
printf '%s\n' "$arping_output"

if [[ "$arping_rc" -ne 0 ]]; then
    echo "ARP probe to $DUT_IP through $GENERATOR_IF failed (status $arping_rc)." >&2
    exit "$arping_rc"
fi

# arping sends and receives ARP frames directly and does not reliably populate
# the Linux neighbour table. Parse the responder MAC from arping's own output;
# treat `ip neigh` as optional supporting information only.
observed="$({
    printf '%s\n' "$arping_output" |
        sed -nE 's/.*[Ff][Rr][Oo][Mm][[:space:]]+(([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}).*/\1/p'
} | head -n 1 | tr '[:upper:]' '[:lower:]')"

if [[ -z "$observed" ]]; then
    echo "ARP replies were reported, but the responder MAC could not be parsed." >&2
    exit 1
fi

echo "Expected DUT MAC: $expected"
echo "Observed DUT MAC: $observed"
[[ "$observed" == "$expected" ]] || {
    echo "DUT ARP responder MAC mismatch" >&2
    exit 1
}

# Populate or refresh the kernel neighbour table where possible, then display it
# as diagnostic information. Failure here does not override a validated arping
# response because raw arping traffic is the authoritative check above.
ping -I "$GENERATOR_IF" -c 1 -W 1 "$DUT_IP" >/dev/null 2>&1 || true
neighbor_line="$(ip neigh show to "$DUT_IP" dev "$GENERATOR_IF" | head -n 1 || true)"
if [[ -n "$neighbor_line" ]]; then
    echo "Kernel neighbour entry: $neighbor_line"
else
    echo "Kernel neighbour entry: none (ARP responder validation still passed)"
fi

if command -v nc >/dev/null 2>&1; then
    nc -vz -w 2 "$DUT_IP" "$TLS_PORT" || true
fi

echo "DUT neighbour validation: PASS"
