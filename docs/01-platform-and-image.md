# 01 — Platform and firmware image

This procedure reconstructs the NXP Yocto firmware, patched Mbed TLS 3.6.1, target SDK and OP-TEE development kit used for the TLS scenarios.

## Reference platform

| Item | Configuration |
| --- | --- |
| Development board | NXP i.MX 8M Plus EVK, SCH-46370 REV B2; SoC board 700-46370 REV B |
| Build host | Ubuntu 22.04 (x86-64); BitBake 2.9.1 |
| NXP BSP | LF6.12.3_1.0.0, Yocto/Poky styhead |
| Machine | `imx8mp-lpddr4-evk` |
| Distribution | `fsl-imx-wayland` |
| Image recipe | `imx-image-multimedia` |
| Linux | NXP Linux 6.12.3-based kernel |
| OP-TEE | `optee-os`, `optee-client`, `optee-test` 4.4.0.imx |
| Mbed TLS | 3.6.1 with the patches in `platform/meta-tlsecho` |
| Image package format | `package_deb` |

The exact upstream project revisions are recorded in [`platform/yocto/pinned-manifest.xml`](../platform/yocto/pinned-manifest.xml). Do not substitute a later BSP release when reproducing the results.

## 0. Build-host prerequisites

The recorded build used **Ubuntu 22.04 x86-64**. Install the required tools using the NXP Yocto Project User's Guide; on Ubuntu 22.04, an initial package set is:

```bash
sudo apt-get update
sudo apt-get install -y repo git bzip2 chrpath diffstat g++ gcc lz4 make build-essential gawk
```

Configure a Git identity for the build user if `repo` requires one. Do not use a repository author's identity as an environment default.

## 1. Obtain the BSP

Install the build-host dependencies and Google's `repo` tool as described by the [NXP i.MX Yocto Project User's Guide](https://www.nxp.com/docs/en/user-guide/UG10164.pdf). Allow sufficient disk space for the BSP, download cache and build artifacts.

In a new BSP directory (with the TeePartDos checkout available separately):

```bash
mkdir -p "$HOME/yocto-imx8mp"
cd "$HOME/yocto-imx8mp"
repo init -u https://github.com/nxp-imx/imx-manifest.git \
  -b imx-linux-styhead -m imx-6.12.3-1.0.0.xml
repo sync
repo manifest -r -o resolved-manifest.xml
```

Compare the project paths and revision hashes in `resolved-manifest.xml` against `/absolute/path/to/TeePartDos/platform/yocto/pinned-manifest.xml`. Ensure the checked-out projects match the pinned revisions before building; the NXP release manifest name alone does not guarantee a fixed commit for every upstream layer. The experimental `meta-tlsecho` layer is supplied separately in this repository.

## 2. Configure Yocto

From the BSP root:

```bash
MACHINE=imx8mp-lpddr4-evk DISTRO=fsl-imx-wayland \
  source ./imx-setup-release.sh -b build
```

In `build/conf/local.conf`, retain the distribution's generated configuration and add the following if not already present:

```bitbake
PACKAGE_CLASSES = "package_deb"
EXTRA_IMAGE_FEATURES += "package-management"
IMAGE_INSTALL:append = " mbedtls"
TOOLCHAIN_TARGET_TASK:append = " mbedtls-dev mbedtls-staticdev"
ASSUME_PROVIDED:remove = "tar-native"

# Optional conservative settings for RAM-constrained build VMs:
BB_NUMBER_THREADS = "1"
BB_NUMBER_PARSE_THREADS = "1"
PARALLEL_MAKE = "-j1"
PARALLEL_MAKE:pn-vulkan-validation-layers = "-j1"
```

The conservative parallelism values prioritize avoiding observed out-of-memory failures; increase only after testing available RAM and task concurrency. They are not functional requirements of the image. Inspect free memory, swap, disk space and inodes (`free -h`, `swapon --show`, `df -h`, `df -i`) before a long build; no universally validated minimum RAM/swap size is available for this exact reference image. Check the effective configuration with `bitbake -p`.

Accept the NXP EULA according to the NXP setup process; the reference build used `ACCEPT_FSL_EULA = "1"`. The original image also used the default NXP OP-TEE package group (`packagegroup-fsl-optee-imx`). Retain the BSP's OP-TEE configuration.

Add the experimental BitBake layer from this checkout:

```bash
bitbake-layers add-layer /absolute/path/to/TeePartDos/platform/meta-tlsecho
bitbake-layers show-layers
bitbake-layers show-appends
bitbake-layers show-recipes mbedtls
```

Verify that the layer is enabled once, that the Mbed TLS 3.6.1 recipe is selected, and that both `mbedtls_%.bbappend` and `mbedtls_3.6.1.bbappend` apply. The latter includes packaging compatibility adjustments used by the reference build; retain them unchanged.

### 2.1 Recorded preferred-version warnings

In the recorded NXP BSP build, BitBake reported that preferred `gst-devtools` version `1.24.0.imx` and preferred `xen` version `4.18.imx+stable` were unavailable; available alternatives were `1.22.5.imx`/`1.24.6` and `4.18.2+stable`/`4.19.0+stable`/`4.20+git`, respectively. These are **configuration-version warnings**, not proof of a failed build or of compatibility of the alternatives. They remain unresolved in the supplied provenance, so independently verify the effective selections:

```bash
bitbake-layers show-recipes gst-devtools
bitbake-layers show-recipes xen
bitbake -e gst-devtools | grep -E '^(PV|FILE|PREFERRED_VERSION_gst-devtools)='
bitbake -e xen | grep -E '^(PV|FILE|PREFERRED_VERSION_xen)='
grep -RIn --include='*.conf' --include='*.inc' \
  -e 'PREFERRED_VERSION.*gst-devtools' \
  -e 'PREFERRED_VERSION.*xen' ../sources conf
```

Inspect the complete BitBake variable histories if the originating preferences are unclear. Prefer the revisions in `platform/yocto/pinned-manifest.xml`; do **not** silently change preferred versions or assert compatibility without verification. Record any effective-version deviation in the reproduction notes.

## 3. Verify the Mbed TLS integration

```bash
bitbake -e mbedtls > mbedtls-effective.txt
grep -E '^(PV|SRC_URI|S)=' mbedtls-effective.txt
bitbake -c patch mbedtls
```

The effective recipe must select version 3.6.1 and list the asynchronous-private patch plus the TLS 1.3 signing and crypto-backend patch series (`0001`–`0010`). The patch task must finish successfully. Resolve missing or rejected patches before proceeding. This repository's two Mbed TLS bbappends include reference packaging workarounds for tar/pseudo behavior; keep their functional contents when reproducing the image.

## 4. Build the image and SDK

```bash
bitbake imx-image-multimedia
bitbake imx-image-multimedia -c populate_sdk
bitbake optee-os-tadevkit
```

An interrupted build can normally be resumed using the same `bitbake imx-image-multimedia` invocation; BitBake reuses completed tasks and cached build artifacts rather than requiring a full clean rebuild.

The image is deployed under `build/tmp/deploy/images/imx8mp-lpddr4-evk/`. The reference build produced a compressed WIC image (`.wic.zst`), a matching `.wic.bmap`, a root filesystem archive (`.tar.zst`) and a package manifest (`.manifest`). Check the new manifest for `mbedtls`, `optee-os`, `optee-client`, and `optee-test`.

Install the generated SDK from `build/tmp/deploy/sdk/`. Locate the matching OP-TEE `export-ta_arm64` development kit produced by the BSP. Record the image and SDK filenames and checksums.

## 5. Install and verify the target

Write the generated image using the NXP-supported procedure for the EVK's **selected boot medium**, then boot the board. Confirm that Linux, OP-TEE and the patched Mbed TLS runtime are present. Use the correct device/boot-switch settings for that medium; the image filename alone does not determine the flashing command.

When the SDK is installed, verify its active sysroot headers using the repository's `implementation/tlsecho/init.sh`: set `TLSECHO_SDK_ENV`, `TA_DEV_KIT_DIR`, and `OPTEE_TA_VENV`, source `./init.sh` from `implementation/tlsecho/`, then run `tlsecho-env-status` as described in [02 — TLS scenarios](02-tls-scenarios.md). The script checks the required build flags, API values, and target libraries; it is not sufficient to inspect an arbitrary host header. The required flags and values are:

```text
MBEDTLS_SSL_PROTO_TLS1_3
MBEDTLS_SSL_ASYNC_PRIVATE
MBEDTLS_SSL_TLS1_3_SERVER_EXTERNAL_SIGNING
MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND
MBEDTLS_SSL_L1_PATCH_VERSION = 1
MBEDTLS_SSL_TLS1_3_CRYPTO_BACKEND_API_VERSION = 5u
```

The application build environment in [02 — TLS scenarios](02-tls-scenarios.md) checks these definitions and the required target libraries.

**Completion criterion:** The firmware builds and boots, the image contains the specified packages, and the matching SDK and TA development kit are available for scenario compilation.
