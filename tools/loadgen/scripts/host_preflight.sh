#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"
require_cmd lspci
require_cmd ethtool

fail=0
echo "== Host =="
uname -a
lscpu -e=CPU,CORE,SOCKET,NODE,ONLINE

echo "== Generator NIC =="
lspci -nnk -s "$GENERATOR_PCI" || fail=1
if [[ -e "/sys/bus/pci/devices/$GENERATOR_PCI/iommu_group" ]]; then
    group_path="$(readlink -f "/sys/bus/pci/devices/$GENERATOR_PCI/iommu_group")"
    echo "IOMMU group: ${group_path##*/}"
    for dev in "$group_path"/devices/*; do
        bdf="${dev##*/}"
        class="$(cat "$dev/class")"
        printf '  %s class=%s ' "$bdf" "$class"
        lspci -s "$bdf" | head -1
        if [[ "$bdf" != "$GENERATOR_PCI" && "$class" != 0x0604* && "$class" != 0x0600* ]]; then
            echo "Unsafe non-bridge peer in the target IOMMU group: $bdf" >&2
            fail=1
        fi
    done
else
    echo "No IOMMU group for $GENERATOR_PCI" >&2
    fail=1
fi

if ip link show "$GENERATOR_IF" >/dev/null 2>&1; then
    ethtool -i "$GENERATOR_IF"
    ethtool "$GENERATOR_IF" || true
    echo "MTU: $(cat "/sys/class/net/$GENERATOR_IF/mtu")"
    ip -d link show dev "$GENERATOR_IF"
else
    echo "$GENERATOR_IF is not a kernel interface (it may already be VFIO-bound)."
fi

echo "== IOMMU kernel evidence =="
if [[ $EUID -eq 0 ]]; then
    dmesg | grep -Ei 'DMAR|IOMMU' | tail -50 || true
else
    sudo dmesg | grep -Ei 'DMAR|IOMMU' | tail -50 || true
fi

echo "== Hugepages =="
grep -i huge /proc/meminfo

if [[ $fail -ne 0 ]]; then
    echo "PRE-FLIGHT: FAIL" >&2
    exit 1
fi
echo "PRE-FLIGHT: PASS (link state and DUT reachability are separate checks)"
