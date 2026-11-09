#!/usr/bin/env bash
set -euo pipefail

VERSION="3.5.7"
PREFIX="${OPENSSL_PREFIX:-/opt/openssl-${VERSION}}"
WORKDIR="${WORKDIR:-$HOME/src}"
ARCHIVE="openssl-${VERSION}.tar.gz"
BASE_URL="https://github.com/openssl/openssl/releases/download/openssl-${VERSION}"

sudo apt-get update
sudo apt-get install -y build-essential perl pkg-config curl ca-certificates
mkdir -p "$WORKDIR"
cd "$WORKDIR"
curl -fL --retry 3 -o "$ARCHIVE" "$BASE_URL/$ARCHIVE"
curl -fL --retry 3 -o "$ARCHIVE.sha256" "$BASE_URL/$ARCHIVE.sha256"
sha256sum -c "$ARCHIVE.sha256"
rm -rf "openssl-${VERSION}"
tar xf "$ARCHIVE"
cd "openssl-${VERSION}"
./Configure linux-x86_64 --prefix="$PREFIX" --openssldir="$PREFIX/ssl" --libdir=lib shared
make -j"$(nproc)"
make test
sudo make install_sw

# install_sw may not install a configuration file. Keep this local installation self-contained.
sudo install -d -m 0755 "$PREFIX/ssl"
if [[ ! -f "$PREFIX/ssl/openssl.cnf" ]]; then
    sudo tee "$PREFIX/ssl/openssl.cnf" >/dev/null <<'CNF'
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect

[default_sect]
activate = 1
CNF
fi

LD_LIBRARY_PATH="$PREFIX/lib" OPENSSL_CONF="$PREFIX/ssl/openssl.cnf" \
    "$PREFIX/bin/openssl" version -a
PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig" pkg-config --modversion openssl

echo "Installed OpenSSL ${VERSION} under $PREFIX without replacing the Ubuntu system libraries."
