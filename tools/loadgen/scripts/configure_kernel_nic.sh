#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"
require_root

modprobe "$LINUX_DRIVER"
ip link set dev "$GENERATOR_IF" down
ip addr flush dev "$GENERATOR_IF"
ip addr add "$SOURCE_CIDR" dev "$GENERATOR_IF"
ip link set dev "$GENERATOR_IF" mtu 1500
ip link set dev "$GENERATOR_IF" up
sleep 2
ip -br addr show dev "$GENERATOR_IF"
ethtool "$GENERATOR_IF"
echo "MTU=$(cat "/sys/class/net/$GENERATOR_IF/mtu")"
