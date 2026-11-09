#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${CONFIG:-$ROOT/config/generator.conf}"
WORKLOAD="${1:-full-handshake}"
MODE="${2:-benign}"
RATE="${3:-10}"
DURATION="${4:-30}"
SCENARIO="${SCENARIO:-A}"
exec "$ROOT/bin/tls_loadgen_posix" \
    --config "$CONFIG" --backend posix \
    --scenario "$SCENARIO" --workload "$WORKLOAD" --mode "$MODE" \
    --rate "$RATE" --duration "$DURATION"
