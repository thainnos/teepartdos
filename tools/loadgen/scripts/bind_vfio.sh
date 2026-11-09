#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"
require_root
DEV_BIND="$(find_devbind)"

if [[ -n "${SSH_CONNECTION:-}" ]]; then
    remote_ip="${SSH_CONNECTION%% *}"
    route_dev="$(ip route get "$remote_ip" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)"
    if [[ "$route_dev" == "$GENERATOR_IF" ]]; then
        echo "Refusing to VFIO-bind the interface carrying the current SSH session." >&2
        exit 1
    fi
fi

group_path="$(readlink -f "/sys/bus/pci/devices/$GENERATOR_PCI/iommu_group")"
for dev in "$group_path"/devices/*; do
    bdf="${dev##*/}"
    class="$(cat "$dev/class")"
    if [[ "$bdf" != "$GENERATOR_PCI" && "$class" != 0x0604* && "$class" != 0x0600* ]]; then
        echo "Refusing: IOMMU group contains non-bridge peer $bdf class=$class" >&2
        exit 1
    fi
done

ip link set dev "$GENERATOR_IF" down 2>/dev/null || true
modprobe vfio-pci
python3 "$DEV_BIND" --bind=vfio-pci "$GENERATOR_PCI"
python3 "$DEV_BIND" --status
lspci -nnk -s "$GENERATOR_PCI"
