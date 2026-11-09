#!/usr/bin/env bash
# Initialize the common Scenario A-E build environment for the D4 SDK.
#
# Source this file from a fresh Bash login shell:
#   source ./init.sh
#
# Optional overrides before sourcing:
#   export TLSECHO_SDK_ENV="/path/to/sdk/environment-setup-armv8a-poky-linux"
#   export TLSECHO_ROOT="/path/to/TeePartDos/implementation/tlsecho"
#   export OPTEE_TA_VENV="/path/to/your/optee-python-venv"
#   export TA_DEV_KIT_DIR="/path/to/yocto/optee-os-tadevkit/build/export-ta_arm64"
#   export TLSECHO_EXPECTED_L1_PATCH_VERSION=1
#
# The script deliberately refuses to layer the L1 SDK over another active
# Yocto SDK or a different Python virtual environment.

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "ERROR: this script must be sourced so the SDK and venv remain active." >&2
    echo "Use: source $0" >&2
    exit 1
fi

TLSECHO_SDK_ENV="${TLSECHO_SDK_ENV:-}"
TLSECHO_ROOT="${TLSECHO_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)}"
TA_DEV_KIT_DIR="${TA_DEV_KIT_DIR:-}"
TLSECHO_EXPECTED_L1_PATCH_VERSION="${TLSECHO_EXPECTED_L1_PATCH_VERSION:-1}"

if [[ ! "$TLSECHO_EXPECTED_L1_PATCH_VERSION" =~ ^[0-9]+$ ]]; then
    echo "ERROR: TLSECHO_EXPECTED_L1_PATCH_VERSION must be an integer." >&2
    return 1
fi

if [[ ! -r "$TLSECHO_SDK_ENV" ]]; then
    echo "ERROR: TLSECHO_SDK_ENV must point to a readable target SDK environment script:" >&2
    echo "  $TLSECHO_SDK_ENV" >&2
    return 1
fi

_tlsecho_sdk_root="$(cd -- "$(dirname -- "$TLSECHO_SDK_ENV")" && pwd -P)"
_tlsecho_active_target_sysroot="${SDKTARGETSYSROOT:-${OECORE_TARGET_SYSROOT:-}}"
_tlsecho_sdk_already_active=0

# Refuse to mix SDK installations in one shell. Re-sourcing this script with
# the already active L1 SDK is allowed and only revalidates the environment.
if [[ -n "$_tlsecho_active_target_sysroot" ]]; then
    if [[ ! -d "$_tlsecho_active_target_sysroot" ]]; then
        echo "ERROR: the active Yocto target sysroot does not exist:" >&2
        echo "  $_tlsecho_active_target_sysroot" >&2
        return 1
    fi

    _tlsecho_active_target_sysroot="$(
        cd -- "$_tlsecho_active_target_sysroot" && pwd -P
    )"

    case "$_tlsecho_active_target_sysroot" in
        "$_tlsecho_sdk_root"/sysroots/*)
            _tlsecho_sdk_already_active=1
            ;;
        *)
            echo "ERROR: a different Yocto SDK is already active:" >&2
            echo "  active target sysroot: $_tlsecho_active_target_sysroot" >&2
            echo "  required SDK root:     $_tlsecho_sdk_root" >&2
            echo "Open a fresh shell and source this script again." >&2
            return 1
            ;;
    esac
fi

if (( !_tlsecho_sdk_already_active )); then
    # shellcheck disable=SC1090
    source "$TLSECHO_SDK_ENV" || {
        echo "ERROR: failed to source the L1 SDK environment." >&2
        return 1
    }
fi

TLSECHO_ACTIVE_TARGET_SYSROOT="${SDKTARGETSYSROOT:-${OECORE_TARGET_SYSROOT:-}}"
if [[ -z "$TLSECHO_ACTIVE_TARGET_SYSROOT" ]] ||
   [[ ! -d "$TLSECHO_ACTIVE_TARGET_SYSROOT" ]]; then
    echo "ERROR: the L1 SDK did not provide a valid target sysroot." >&2
    echo "  SDKTARGETSYSROOT=${SDKTARGETSYSROOT:-<unset>}" >&2
    echo "  OECORE_TARGET_SYSROOT=${OECORE_TARGET_SYSROOT:-<unset>}" >&2
    return 1
fi

TLSECHO_ACTIVE_TARGET_SYSROOT="$(
    cd -- "$TLSECHO_ACTIVE_TARGET_SYSROOT" && pwd -P
)"

case "$TLSECHO_ACTIVE_TARGET_SYSROOT" in
    "$_tlsecho_sdk_root"/sysroots/*)
        ;;
    *)
        echo "ERROR: active target sysroot is not part of the selected L1 SDK:" >&2
        echo "  active target sysroot: $TLSECHO_ACTIVE_TARGET_SYSROOT" >&2
        echo "  selected SDK root:     $_tlsecho_sdk_root" >&2
        return 1
        ;;
esac

# Resolve the OP-TEE TA Python environment without overwriting a user-provided
# path. Prefer the project-local venv.
if [[ -z "${OPTEE_TA_VENV:-}" ]]; then
    _tlsecho_venv_candidates=(
        "$TLSECHO_ROOT/.venv-optee-ta"
        "$HOME/.venv-optee-ta"
    )

    for _tlsecho_candidate in "${_tlsecho_venv_candidates[@]}"; do
        if [[ -r "$_tlsecho_candidate/bin/activate" ]]; then
            OPTEE_TA_VENV="$_tlsecho_candidate"
            break
        fi
    done
fi

if [[ -z "${OPTEE_TA_VENV:-}" ]] ||
   [[ ! -r "$OPTEE_TA_VENV/bin/activate" ]]; then
    echo "ERROR: OP-TEE TA Python venv was not found." >&2
    echo "Set its path before sourcing this script:" >&2
    echo "  export OPTEE_TA_VENV=/absolute/path/to/the/venv" >&2
    return 1
fi

OPTEE_TA_VENV="$(cd -- "$OPTEE_TA_VENV" && pwd -P)"

if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    _tlsecho_active_venv="$(cd -- "$VIRTUAL_ENV" && pwd -P)"
    if [[ "$_tlsecho_active_venv" != "$OPTEE_TA_VENV" ]]; then
        echo "ERROR: a different Python virtual environment is already active:" >&2
        echo "  active:   $_tlsecho_active_venv" >&2
        echo "  required: $OPTEE_TA_VENV" >&2
        echo "Run 'deactivate' or open a fresh shell, then source this script again." >&2
        return 1
    fi
else
    # shellcheck disable=SC1090
    source "$OPTEE_TA_VENV/bin/activate" || {
        echo "ERROR: failed to activate the OP-TEE TA Python venv." >&2
        return 1
    }
fi

if [[ ! -d "$TA_DEV_KIT_DIR" ]]; then
    echo "ERROR: TA_DEV_KIT_DIR must point to an OP-TEE TA development kit:" >&2
    echo "  $TA_DEV_KIT_DIR" >&2
    return 1
fi

TA_DEV_KIT_DIR="$(cd -- "$TA_DEV_KIT_DIR" && pwd -P)"

if [[ ! -r "$TA_DEV_KIT_DIR/mk/ta_dev_kit.mk" ]]; then
    echo "ERROR: directory does not look like an OP-TEE TA development kit:" >&2
    echo "  missing: $TA_DEV_KIT_DIR/mk/ta_dev_kit.mk" >&2
    return 1
fi

TLSECHO_MBEDTLS_CONFIG="$TLSECHO_ACTIVE_TARGET_SYSROOT/usr/include/mbedtls/mbedtls_config.h"
TLSECHO_MBEDTLS_SSL_HEADER="$TLSECHO_ACTIVE_TARGET_SYSROOT/usr/include/mbedtls/ssl.h"

if [[ ! -r "$TLSECHO_MBEDTLS_CONFIG" ]]; then
    echo "ERROR: Mbed TLS configuration header not found:" >&2
    echo "  $TLSECHO_MBEDTLS_CONFIG" >&2
    return 1
fi

if [[ ! -r "$TLSECHO_MBEDTLS_SSL_HEADER" ]]; then
    echo "ERROR: Mbed TLS SSL header not found:" >&2
    echo "  $TLSECHO_MBEDTLS_SSL_HEADER" >&2
    return 1
fi

_tlsecho_require_define() {
    local header="$1"
    local macro="$2"

    if ! grep -Eq \
        "^[[:space:]]*#define[[:space:]]+${macro}([[:space:]]|$)" \
        "$header"; then
        echo "ERROR: active SDK does not enable ${macro}." >&2
        echo "  Header: $header" >&2
        return 1
    fi
}

_tlsecho_require_define_value() {
    local header="$1"
    local macro="$2"
    local expected="$3"

    if ! grep -Eq \
        "^[[:space:]]*#define[[:space:]]+${macro}[[:space:]]+${expected}([[:space:]]|$)" \
        "$header"; then
        echo "ERROR: active SDK does not provide ${macro}=${expected}." >&2
        echo "  Header: $header" >&2
        return 1
    fi
}

_tlsecho_require_define \
    "$TLSECHO_MBEDTLS_CONFIG" \
    MBEDTLS_SSL_PROTO_TLS1_3 || return 1

_tlsecho_require_define \
    "$TLSECHO_MBEDTLS_CONFIG" \
    MBEDTLS_SSL_ASYNC_PRIVATE || return 1

_tlsecho_require_define \
    "$TLSECHO_MBEDTLS_CONFIG" \
    MBEDTLS_SSL_TLS1_3_SERVER_EXTERNAL_SIGNING || return 1

_tlsecho_require_define \
    "$TLSECHO_MBEDTLS_CONFIG" \
    MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND || return 1

_tlsecho_require_define_value \
    "$TLSECHO_MBEDTLS_SSL_HEADER" \
    MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND_API_VERSION \
    5u || return 1

_tlsecho_require_define_value \
    "$TLSECHO_MBEDTLS_CONFIG" \
    MBEDTLS_SSL_L1_PATCH_VERSION \
    "$TLSECHO_EXPECTED_L1_PATCH_VERSION" || return 1

_tlsecho_require_define \
    "$TLSECHO_MBEDTLS_CONFIG" \
    MBEDTLS_SSL_SRV_C || return 1

_tlsecho_require_define \
    "$TLSECHO_MBEDTLS_CONFIG" \
    MBEDTLS_X509_CRT_PARSE_C || return 1

_tlsecho_require_sdk_library() {
    local library_stem="$1"
    local directory

    for directory in \
        "$TLSECHO_ACTIVE_TARGET_SYSROOT/usr/lib" \
        "$TLSECHO_ACTIVE_TARGET_SYSROOT/lib"; do
        [[ -d "$directory" ]] || continue

        if compgen -G "$directory/${library_stem}.so*" >/dev/null ||
           [[ -f "$directory/${library_stem}.a" ]]; then
            return 0
        fi
    done

    echo "ERROR: required target library is missing from the L1 SDK:" >&2
    echo "  ${library_stem}.so or ${library_stem}.a" >&2
    return 1
}

_tlsecho_require_sdk_library libmbedtls || return 1
_tlsecho_require_sdk_library libmbedx509 || return 1
_tlsecho_require_sdk_library libmbedcrypto || return 1
_tlsecho_require_sdk_library libteec || return 1

if [[ -z "${CC:-}" ]]; then
    echo "ERROR: the L1 SDK did not set CC." >&2
    return 1
fi

read -r -a _tlsecho_cc_argv <<< "$CC"
_tlsecho_cc="${_tlsecho_cc_argv[0]:-}"

if [[ -z "$_tlsecho_cc" ]] ||
   ! command -v "$_tlsecho_cc" >/dev/null 2>&1; then
    echo "ERROR: SDK compiler is not available: ${CC:-<unset>}" >&2
    return 1
fi

_tlsecho_compiler_target="$("${_tlsecho_cc_argv[@]}" -dumpmachine 2>/dev/null)"
case "$_tlsecho_compiler_target" in
    aarch64*)
        ;;
    *)
        echo "ERROR: unexpected SDK compiler target:" >&2
        echo "  $_tlsecho_compiler_target" >&2
        echo "Expected an AArch64 compiler." >&2
        return 1
        ;;
esac

TA_CROSS_COMPILE="${TA_CROSS_COMPILE:-${TARGET_PREFIX:-aarch64-poky-linux-}}"
if ! command -v "${TA_CROSS_COMPILE}gcc" >/dev/null 2>&1; then
    echo "ERROR: TA cross-compiler is not available:" >&2
    echo "  ${TA_CROSS_COMPILE}gcc" >&2
    return 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is unavailable after venv activation." >&2
    return 1
fi

export TLSECHO_SDK_ENV
export TLSECHO_ROOT
export OPTEE_TA_VENV
export TA_DEV_KIT_DIR
export TA_CROSS_COMPILE
export TLSECHO_EXPECTED_L1_PATCH_VERSION
export TLSECHO_ACTIVE_TARGET_SYSROOT
export TLSECHO_MBEDTLS_CONFIG
export TLSECHO_MBEDTLS_SSL_HEADER

# Convenience helper retained in the current shell.
tlsecho-env-status() {
    local compiler_target="<unavailable>"
    local -a cc_argv=()

    if [[ -n "${CC:-}" ]]; then
        read -r -a cc_argv <<< "$CC"
        if [[ ${#cc_argv[@]} -gt 0 ]]; then
            compiler_target="$("${cc_argv[@]}" -dumpmachine 2>/dev/null || true)"
        fi
    fi

    printf 'TLSECHO_ROOT=%s\n' "$TLSECHO_ROOT"
    printf 'TLSECHO_SDK_ENV=%s\n' "$TLSECHO_SDK_ENV"
    printf 'TLSECHO_ACTIVE_TARGET_SYSROOT=%s\n' "$TLSECHO_ACTIVE_TARGET_SYSROOT"
    printf 'OPTEE_TA_VENV=%s\n' "$OPTEE_TA_VENV"
    printf 'TA_DEV_KIT_DIR=%s\n' "$TA_DEV_KIT_DIR"
    printf 'TA_CROSS_COMPILE=%s\n' "$TA_CROSS_COMPILE"
    printf 'CC=%s\n' "$CC"
    printf 'compiler_target=%s\n' "$compiler_target"
    printf 'Python=%s\n' "$(command -v python3)"
    printf 'MBEDTLS_SSL_PROTO_TLS1_3=enabled\n'
    printf 'MBEDTLS_SSL_ASYNC_PRIVATE=enabled\n'
    printf 'MBEDTLS_SSL_TLS1_3_SERVER_EXTERNAL_SIGNING=enabled\n'
    printf 'MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND=enabled\n'
    printf 'MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND_API_VERSION=5u\n'
    printf 'MBEDTLS_SSL_L1_PATCH_VERSION=%s\n' \
        "$TLSECHO_EXPECTED_L1_PATCH_VERSION"
}

unset _tlsecho_sdk_root
unset _tlsecho_active_target_sysroot
unset _tlsecho_sdk_already_active
unset _tlsecho_venv_candidates
unset _tlsecho_candidate
unset _tlsecho_active_venv
unset _tlsecho_cc_argv
unset _tlsecho_cc
unset _tlsecho_compiler_target
unset -f _tlsecho_require_define
unset -f _tlsecho_require_define_value
unset -f _tlsecho_require_sdk_library

echo "TLS echo common D4 build environment initialized."
tlsecho-env-status
