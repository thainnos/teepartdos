#!/bin/bash
set -euo pipefail
[[ $# -ge 2 ]] || { echo "Usage: $0 CONFIG posix|fstack [pilot-debug|measurement] [--functional-check]" >&2; exit 2; }
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONFIG=$1; BACKEND=$2; PROFILE=${3:-measurement}; shift $(( $# >= 3 ? 3 : 2 ))
exec python3 "$ROOT/orchestrate.py" init --config "$CONFIG" --backend "$BACKEND" --profile "$PROFILE" "$@"
