#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-}"
OPENSSL_LIBDIR="${OPENSSL_LIBDIR:-}"

# Resolve the selected OpenSSL executable first.  The reference-client setup
# intentionally keeps its OpenSSL installation separate from the distribution
# copy, so the smoke test must not accidentally execute /usr/bin/openssl.
if [[ "${OPENSSL_BIN}" == */* ]]; then
  if [[ ! -x "${OPENSSL_BIN}" ]]; then
    echo "ERROR: OpenSSL executable not found or not executable: ${OPENSSL_BIN}" >&2
    exit 1
  fi
  OPENSSL_BIN="$(readlink -f "${OPENSSL_BIN}")"
else
  OPENSSL_BIN="$(command -v "${OPENSSL_BIN}" || true)"
  if [[ -z "${OPENSSL_BIN}" ]]; then
    echo "ERROR: OpenSSL executable not found in PATH." >&2
    exit 1
  fi
fi

# If no prefix was supplied, derive it from <prefix>/bin/openssl.
if [[ -z "${OPENSSL_PREFIX}" ]]; then
  OPENSSL_PREFIX="$(cd "$(dirname "${OPENSSL_BIN}")/.." && pwd)"
fi

# Prefer an explicitly supplied library directory.  Otherwise locate the
# side-by-side OpenSSL libraries below the selected prefix.
if [[ -z "${OPENSSL_LIBDIR}" ]]; then
  for candidate in "${OPENSSL_PREFIX}/lib" "${OPENSSL_PREFIX}/lib64"; do
    if [[ -e "${candidate}/libssl.so.3" && -e "${candidate}/libcrypto.so.3" ]]; then
      OPENSSL_LIBDIR="${candidate}"
      break
    fi
  done
fi

if [[ -z "${OPENSSL_LIBDIR}" ]]; then
  echo "ERROR: Could not locate libssl.so.3/libcrypto.so.3 below ${OPENSSL_PREFIX}." >&2
  echo "Set OPENSSL_LIBDIR explicitly if this OpenSSL installation uses another layout." >&2
  exit 1
fi

# The locally installed openssl executable has no global loader configuration
# by design.  Force it to use the libraries that belong to the selected prefix.
export LD_LIBRARY_PATH="${OPENSSL_LIBDIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

# OpenSSL 'make install_sw' does not necessarily populate OPENSSLDIR with an
# openssl.cnf.  Generate a minimal, self-contained configuration for the smoke
# test instead of depending on /opt/.../ssl/openssl.cnf or the distribution
# configuration.  The default provider is sufficient for the P-256/TLS 1.3
# operations exercised here.
TMP="$(mktemp -d)"
SPID=""
cleanup() {
  if [[ -n "${SPID}" ]]; then
    kill "${SPID}" 2>/dev/null || true
    wait "${SPID}" 2>/dev/null || true
  fi
  rm -rf "${TMP}"
}
trap cleanup EXIT

cat > "${TMP}/openssl.cnf" <<'CNF'
openssl_conf = openssl_init
config_diagnostics = 1

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect

[default_sect]
activate = 1
CNF
export OPENSSL_CONF="${TMP}/openssl.cnf"

# If the installation contains dynamically loadable providers, keep provider
# lookup inside the same OpenSSL prefix as well.
if [[ -d "${OPENSSL_LIBDIR}/ossl-modules" ]]; then
  export OPENSSL_MODULES="${OPENSSL_LIBDIR}/ossl-modules"
fi

# Fail early if the selected executable still resolves against another
# OpenSSL installation.  This catches exactly the mixed 3.5 executable / 3.0
# system-library situation that would otherwise produce symbol-version errors.
ssl_path="$(ldd "${OPENSSL_BIN}" | awk '/libssl\.so\.3/{print $3; exit}')"
crypto_path="$(ldd "${OPENSSL_BIN}" | awk '/libcrypto\.so\.3/{print $3; exit}')"
case "${ssl_path}" in
  "${OPENSSL_LIBDIR}"/*) ;;
  *)
    echo "ERROR: ${OPENSSL_BIN} resolves libssl outside ${OPENSSL_LIBDIR}: ${ssl_path:-<not found>}" >&2
    exit 1
    ;;
esac
case "${crypto_path}" in
  "${OPENSSL_LIBDIR}"/*) ;;
  *)
    echo "ERROR: ${OPENSSL_BIN} resolves libcrypto outside ${OPENSSL_LIBDIR}: ${crypto_path:-<not found>}" >&2
    exit 1
    ;;
esac

OPENSSL_VERSION="$(${OPENSSL_BIN} version)"
printf '%-24s %s\n' "Smoke OpenSSL:" "${OPENSSL_VERSION}"
printf '%-24s %s\n' "OpenSSL executable:" "${OPENSSL_BIN}"
printf '%-24s %s\n' "Resolved libssl:" "${ssl_path}"
printf '%-24s %s\n' "Resolved libcrypto:" "${crypto_path}"
printf '%-24s %s\n' "Smoke config:" "${OPENSSL_CONF}"

"${OPENSSL_BIN}" ecparam -name prime256v1 -genkey -noout -out "${TMP}/key.pem"
"${OPENSSL_BIN}" req -new -x509 -key "${TMP}/key.pem" -sha256 -days 1 \
  -subj '/CN=tls-echo-server' \
  -addext 'subjectAltName=DNS:tls-echo-server' \
  -out "${TMP}/cert.pem"

cp "${ROOT}/reference_client.conf" "${TMP}/test.conf"
sed -i "s#tls.ca_file=.*#tls.ca_file=${TMP}/cert.pem#" "${TMP}/test.conf"
sed -i 's/run.duration_s=300/run.duration_s=2/' "${TMP}/test.conf"
sed -i 's/run.probe_interval_ms=1000/run.probe_interval_ms=500/' "${TMP}/test.conf"
sed -i 's/payload.size_bytes=1024/payload.size_bytes=32/' "${TMP}/test.conf"
# openssl s_server -rev is line-oriented; repeated newline bytes are unchanged
# by reversal and therefore act as an exact echo for this smoke test.
sed -i 's/payload.pattern_hex=a5/payload.pattern_hex=0a/' "${TMP}/test.conf"
sed -i "s#output.directory=.*#output.directory=${TMP}/results#" "${TMP}/test.conf"

"${OPENSSL_BIN}" s_server -accept 19443 -cert "${TMP}/cert.pem" -key "${TMP}/key.pem" \
  -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups P-256 \
  -num_tickets 1 -rev -quiet >"${TMP}/server.log" 2>&1 &
SPID=$!

# Wait until the local test server is listening instead of assuming a fixed
# startup delay.  /dev/tcp is a Bash feature and does not add a new dependency.
server_ready=0
for _ in {1..50}; do
  if (exec 3<>/dev/tcp/127.0.0.1/19443) 2>/dev/null; then
    exec 3>&- 3<&-
    server_ready=1
    break
  fi
  if ! kill -0 "${SPID}" 2>/dev/null; then
    echo "ERROR: local OpenSSL s_server exited during startup." >&2
    cat "${TMP}/server.log" >&2 || true
    exit 1
  fi
  sleep 0.1
done
if [[ "${server_ready}" -ne 1 ]]; then
  echo "ERROR: local OpenSSL s_server did not become ready." >&2
  cat "${TMP}/server.log" >&2 || true
  exit 1
fi

common=(--config "${TMP}/test.conf" --scenario A --repetition 1 --server 127.0.0.1 --port 19443)
"${ROOT}/tls_reference_client" "${common[@]}" --workload full-handshake --run-id smoke-full
"${ROOT}/tls_reference_client" "${common[@]}" --workload resumption --run-id smoke-resume-reuse
"${ROOT}/tls_reference_client" "${common[@]}" --workload record --run-id smoke-record

sed -i 's/resumption.session_policy=reuse_seed/resumption.session_policy=chain/' "${TMP}/test.conf"
"${ROOT}/tls_reference_client" "${common[@]}" --workload resumption --run-id smoke-resume-chain

python3 - "${TMP}/results" <<'PY'
import csv, glob, json, os, sys
root = sys.argv[1]
files = sorted(glob.glob(os.path.join(root, '*.csv')))
assert len(files) == 4, files
for path in files:
    with open(path, newline='') as fp:
        rows = list(csv.DictReader(fp))
    assert rows, path
    assert all(r['result_code'] == '0' for r in rows), (path, rows)
    if 'resumption' in path or 'resume' in os.path.basename(path):
        assert all(r['session_reused'] == 'true' for r in rows), path
for path in glob.glob(os.path.join(root, '*.metadata.json')):
    with open(path) as fp:
        json.load(fp)
print('local OpenSSL smoke: PASS')
PY
