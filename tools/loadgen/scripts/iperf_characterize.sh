#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/common.sh"

usage() {
    echo "Usage: $0 server | client SERVER_IP [SECONDS] [PARALLEL]" >&2
    exit 2
}
[[ $# -ge 1 ]] || usage
case "$1" in
    server)
        exec iperf3 -s
        ;;
    client)
        [[ $# -ge 2 ]] || usage
        seconds="${3:-30}"
        parallel="${4:-1}"
        echo "TCP throughput"
        iperf3 -c "$2" -t "$seconds" -P "$parallel" --get-server-output
        echo "Reverse TCP throughput"
        iperf3 -c "$2" -t "$seconds" -P "$parallel" -R --get-server-output
        echo "UDP characterization at 950 Mbit/s (loss/jitter validity check)"
        iperf3 -c "$2" -u -b 950M -t "$seconds" --get-server-output
        ;;
    *) usage ;;
esac
