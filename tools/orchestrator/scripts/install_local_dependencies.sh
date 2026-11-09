#!/bin/bash
set -euo pipefail

# Reference-client/orchestrator host (Armbian/Debian family).
# Includes package validation, reference-client build, and plotting dependencies.
# Password SSH is the reference default. Set INSTALL_SSHPASS=0 only for
# explicitly configured public-key-only deployments.
optional_sshpass=()
if [[ "${INSTALL_SSHPASS:-1}" == "1" ]]; then optional_sshpass+=(sshpass); fi
sudo apt-get update
sudo apt-get install -y \
    python3 python3-numpy python3-pandas python3-matplotlib \
    openssh-client "${optional_sshpass[@]}" iproute2 git ca-certificates libcap2-bin \
    build-essential pkg-config make tar

python3 - <<'PY_CHECK'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11 or newer is required")
for module in ("numpy", "pandas", "matplotlib"):
    __import__(module)
print(sys.version)
PY_CHECK

for command_name in ssh scp "${optional_sshpass[@]}" ip git getcap make cc pkg-config tar; do
    if command -v "$command_name" >/dev/null 2>&1; then
        continue
    fi
    if [[ $command_name == getcap && -x /usr/sbin/getcap ]]; then
        continue
    fi
    echo "Missing required local command after package installation: $command_name" >&2
    exit 1
done
