#!/usr/bin/env bash
set -euo pipefail

TAG="${FSTACK_TAG:-v1.25}"
DEST="${FSTACK_PATH:-/opt/f-stack-v1.25}"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-/opt/openssl-3.5.7}"
OWNER="${SUDO_USER:-$USER}"

OPENSSL_PCDIR="$OPENSSL_PREFIX/lib/pkgconfig"
OPENSSL_HEADER="$OPENSSL_PREFIX/include/openssl/rand.h"

sudo apt-get update
sudo apt-get install -y git build-essential meson ninja-build pkg-config gawk \
    python3 python3-pyelftools python3-setuptools libnuma-dev libpcap-dev \
    libbsd-dev libelf-dev libarchive-dev

# F-Stack's ff_host_interface.c directly includes <openssl/rand.h> and calls
# RAND_bytes().  Build it against the same side-by-side OpenSSL installation
# used by the TLS generator rather than silently using Ubuntu's system headers.
if [[ ! -f "$OPENSSL_HEADER" ]]; then
    echo "Missing $OPENSSL_HEADER" >&2
    echo "Install the dedicated OpenSSL first or set OPENSSL_PREFIX explicitly." >&2
    exit 1
fi
if [[ ! -f "$OPENSSL_PCDIR/openssl.pc" ]]; then
    echo "Missing $OPENSSL_PCDIR/openssl.pc" >&2
    echo "The OpenSSL development installation is incomplete." >&2
    exit 1
fi

OPENSSL_VERSION="$(PKG_CONFIG_LIBDIR="$OPENSSL_PCDIR" pkg-config --modversion openssl)"
OPENSSL_CFLAGS="$(PKG_CONFIG_LIBDIR="$OPENSSL_PCDIR" pkg-config --cflags openssl)"
python3 - "$OPENSSL_VERSION" <<'PY_VERSION'
import sys
parts = sys.argv[1].split('.')
try:
    version = tuple(int(x) for x in parts[:2])
except ValueError:
    raise SystemExit(f"Unable to parse OpenSSL version: {sys.argv[1]}")
if version < (3, 5):
    raise SystemExit(f"OpenSSL >= 3.5 is required; found {sys.argv[1]}")
PY_VERSION

echo "F-Stack OpenSSL headers: $OPENSSL_PREFIX/include"
echo "F-Stack OpenSSL version: $OPENSSL_VERSION"

if [[ -e "$DEST" && ! -d "$DEST/.git" ]]; then
    echo "$DEST exists but is not a Git checkout; refusing to overwrite it." >&2
    exit 1
fi
if [[ ! -d "$DEST/.git" ]]; then
    sudo mkdir -p "$DEST"
    sudo chown "$OWNER":"$(id -gn "$OWNER")" "$DEST"
    git clone --depth 1 --branch "$TAG" https://github.com/F-Stack/f-stack.git "$DEST"
fi

git -C "$DEST" fetch --tags --force
git -C "$DEST" checkout --detach "$TAG"
[[ "$(git -C "$DEST" describe --tags --exact-match)" == "$TAG" ]] || {
    echo "F-Stack checkout is not exactly tag $TAG" >&2; exit 1;
}
git -C "$DEST" submodule update --init --recursive

cd "$DEST/dpdk"
rm -rf build install
meson setup build \
    --prefix="$DEST/dpdk/install" \
    --libdir=lib \
    -Dexamples= \
    -Dtests=false \
    -Ddisable_drivers=crypto/openssl
ninja -C build
ninja -C build install

DPDK_PCDIR="$DEST/dpdk/install/lib/pkgconfig"
if [[ ! -f "$DPDK_PCDIR/libdpdk.pc" ]]; then
    echo "Missing $DPDK_PCDIR/libdpdk.pc after DPDK installation." >&2
    exit 1
fi
DPDK_VERSION="$(PKG_CONFIG_PATH="$DPDK_PCDIR" pkg-config --modversion libdpdk)"
echo "Bundled DPDK version: $DPDK_VERSION"

# CONF_CFLAGS is consumed by F-Stack's lib/Makefile and appended to the host
# compilation flags.  This supplies the dedicated OpenSSL include directory
# while PKG_CONFIG_PATH continues to identify the bundled DPDK installation.
make -C "$DEST/lib" clean || true
PKG_CONFIG_PATH="$DPDK_PCDIR" \
    make -C "$DEST/lib" -j"$(nproc)" \
    CONF_CFLAGS="$OPENSSL_CFLAGS"

test -f "$DEST/lib/libfstack.a"
{
    echo "tag=$TAG"
    echo "commit=$(git -C "$DEST" rev-parse HEAD)"
    echo "dpdk=$DPDK_VERSION"
    echo "openssl=$OPENSSL_VERSION"
    echo "openssl_prefix=$OPENSSL_PREFIX"
    echo "openssl_cflags=$OPENSSL_CFLAGS"
    echo "built_utc=$(date -u +%FT%TZ)"
} | tee "$DEST/INSTALL_MANIFEST.txt"

echo "F-Stack installation/build complete at $DEST"
