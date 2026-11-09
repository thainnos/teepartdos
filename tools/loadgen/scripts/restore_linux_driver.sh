#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"
require_root
DEV_BIND="$(find_devbind)"
modprobe "$LINUX_DRIVER"
python3 "$DEV_BIND" --bind="$LINUX_DRIVER" "$GENERATOR_PCI"
sleep 1
lspci -nnk -s "$GENERATOR_PCI"
ip link show "$GENERATOR_IF" >/dev/null 2>&1 && ip link set dev "$GENERATOR_IF" up || true
