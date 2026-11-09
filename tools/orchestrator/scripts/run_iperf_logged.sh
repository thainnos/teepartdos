#!/bin/bash
set -euo pipefail
[[ $# -eq 1 ]] || { echo "Usage: $0 CONFIG" >&2; exit 2; }
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 "$ROOT/orchestrate.py" iperf --config "$1"
