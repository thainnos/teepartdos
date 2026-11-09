#!/bin/bash
set -euo pipefail
[[ $# -ge 1 && $# -le 2 ]] || { echo "Usage: $0 config/campaign.local.toml [dut|loadgen]" >&2; exit 2; }
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ARGS=(ssh-check --config "$1")
[[ $# -eq 2 ]] && ARGS+=(--host "$2")
exec python3 "$ROOT/orchestrate.py" "${ARGS[@]}"
