#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${CONFIG:-$ROOT/config/generator.conf}"
FSTACK_CONF="${FSTACK_CONF:-$ROOT/config/f-stack.conf}"
WORKLOAD="${1:-full-handshake}"
MODE="${2:-benign}"
RATE="${3:-10}"
DURATION="${4:-30}"
SCENARIO="${SCENARIO:-A}"

[[ $EUID -eq 0 ]] || { echo "First F-Stack pilots should be run with sudo -E." >&2; exit 1; }
ulimit -n 1048576
exec "$ROOT/bin/tls_loadgen_fstack" \
    --config "$CONFIG" --backend fstack --fstack-conf "$FSTACK_CONF" \
    --scenario "$SCENARIO" --workload "$WORKLOAD" --mode "$MODE" \
    --rate "$RATE" --duration "$DURATION"
