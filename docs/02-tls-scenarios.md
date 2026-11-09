# 02 — TLS scenarios: build and deployment

The implementation in `implementation/tlsecho/` provides five TLS 1.3 echo-server scenarios. All server binaries run in the normal world; B, C and D additionally invoke OP-TEE trusted applications (TAs).

| Scenario | Cryptographic placement |
| --- | --- |
| A | Mbed TLS entirely in the normal world |
| B | TEE-backed TLS session-ticket/secret protection |
| C | TEE-backed server identity-key signing |
| D | TEE-backed key schedule, ECDHE, Finished, record AEAD and resumption |
| E | Combined B, C and D (Case A) |

Scenario E reuses the **three existing TAs**; it has no fourth TA. On a resumed PSK-ECDHE handshake, TLS 1.3 does not perform CertificateVerify, so the signing path is relevant to full handshakes.

## 1. Initialize the cross-compilation environment

Use a fresh shell and the SDK/devkit generated in [01 — Platform and firmware image](01-platform-and-image.md):

```bash
cd /absolute/path/to/TeePartDos/implementation/tlsecho
export TLSECHO_SDK_ENV=/absolute/path/to/sdk/environment-setup-armv8a-poky-linux
export TA_DEV_KIT_DIR=/absolute/path/to/export-ta_arm64
export OPTEE_TA_VENV=/absolute/path/to/optee-python-venv

source ./init.sh
tlsecho-env-status
```

The OP-TEE Python virtual environment must contain the dependencies required by the selected TA devkit. `init.sh` checks the SDK target, Mbed TLS configuration/API and target libraries. Adjust the paths to the local installation.

## 2. Compile

```bash
make all
```

This builds five normal-world executables and the three B/C/D TAs. Alternatively, `make host` builds only the servers and `make tas` builds the three TAs. The scenario Makefiles support individual builds.

Expected normal-world binaries:

```text
scenarioa/tls_echo_server_scenario_a
scenariob/tls_echo_server_scenario_b
scenarioc/tls_echo_server_scenario_c
scenariod/tls_echo_server_scenario_d
scenarioe/tls_echo_server_scenario_e
```

Expected TAs:

| Scenario | TA UUID |
| --- | --- |
| B | `159e414d-c5b1-4652-8ec0-5d42beb160a9` |
| C | `2b85d8aa-7d3b-4cc3-9f6e-8f7d4a6a5c2b` |
| D | `8b2d21dc-b49f-469b-9200-bdf2bb42798d` |

The build outputs the signed `<UUID>.ta` files inside the corresponding `ta/` directories.

## 3. Install on the DUT

Transfer the five executable files to a directory of choice on the target, preserving their executable permissions. The reference paths expected by the supplied validation and orchestration configuration are:

```text
/root/scenarios/a/tls_echo_server_scenario_a
/root/scenarios/b/tls_echo_server_scenario_b
/root/scenarios/c/tls_echo_server_scenario_c
/root/scenarios/d/tls_echo_server_scenario_d
/root/scenarios/e/tls_echo_server_scenario_e
```

Install the three B/C/D `<UUID>.ta` files under the target's OP-TEE TA directory (the reference platform uses `/lib/optee_armtz/`). A different deployment path is possible, provided that the test and orchestrator configuration is updated accordingly.

Generate a P-256/ECDSA test certificate and private key appropriate for the DUT's IP address (include the service address in the subjectAltName). Install the server files at the paths selected for the tests, for example `/root/certs/server.crt` and `/root/certs/server.key`. Distribute the corresponding trust certificate to the measurement host. Do not publish private keys.

## 4. Runtime configuration

The servers support options for bind address, port, certificate/key paths, session tickets, logging and scenario-specific TEE operations. Inspect each server's `--help` output and the reference settings used by the validation suite. The evaluation's TLS profile uses TLS 1.3 with `TLS_AES_128_GCM_SHA256`, P-256 and ECDSA P-256/SHA-256; 0-RTT is disabled.

Proceed with [03 — Functional validation](03-functional-validation.md) to verify full handshakes, resumption, signing controls and backend operation.
