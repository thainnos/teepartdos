#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential git curl ca-certificates tar xz-utils \
    meson ninja-build pkg-config gawk \
    python3 python3-venv python3-pip python3-pyelftools python3-setuptools python3-wheel \
    libnuma-dev numactl libpcap-dev libbsd-dev libelf-dev libarchive-dev libsystemd-dev \
    linux-headers-"$(uname -r)" \
    pciutils ethtool iproute2 iputils-ping arping netcat-openbsd iperf3 jq bc \
    openssl

echo "Dependency installation complete. The generator itself will use the side-by-side OpenSSL 3.5.7 installation."
