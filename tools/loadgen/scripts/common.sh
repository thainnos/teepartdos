#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATOR_PCI="${GENERATOR_PCI:-0000:01:00.0}"
GENERATOR_IF="${GENERATOR_IF:-enp1s0}"
LINUX_DRIVER="${LINUX_DRIVER:-e1000e}"
FSTACK_PATH="${FSTACK_PATH:-/opt/f-stack-v1.25}"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-/opt/openssl-3.5.7}"
HUGEPAGE_MOUNT="${HUGEPAGE_MOUNT:-/mnt/huge}"
HUGEPAGES_2M="${HUGEPAGES_2M:-512}"
SOURCE_CIDR="${SOURCE_CIDR:-172.10.10.50/24}"
DUT_IP="${DUT_IP:-172.10.10.150}"
DUT_MAC="${DUT_MAC:-00:04:9f:09:68:bd}"
TLS_PORT="${TLS_PORT:-4433}"

require_root() {
    if [[ ${EUID} -ne 0 ]]; then
        echo "This script must run as root (use sudo -E)." >&2
        exit 1
    fi
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1" >&2; exit 1; }
}

find_devbind() {
    local candidates=(
        "$FSTACK_PATH/dpdk/usertools/dpdk-devbind.py"
        "$FSTACK_PATH/dpdk/install/bin/dpdk-devbind.py"
        "$(command -v dpdk-devbind.py 2>/dev/null || true)"
    )
    local c
    for c in "${candidates[@]}"; do
        [[ -n "$c" && -f "$c" ]] && { printf '%s\n' "$c"; return 0; }
    done
    echo "dpdk-devbind.py not found; install F-Stack/DPDK first." >&2
    return 1
}

find_testpmd() {
    local candidates=(
        "$FSTACK_PATH/dpdk/install/bin/dpdk-testpmd"
        "$FSTACK_PATH/dpdk/build/app/dpdk-testpmd"
        "$(command -v dpdk-testpmd 2>/dev/null || true)"
    )
    local c
    for c in "${candidates[@]}"; do
        [[ -n "$c" && -x "$c" ]] && { printf '%s\n' "$c"; return 0; }
    done
    echo "dpdk-testpmd not found." >&2
    return 1
}
