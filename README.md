# TeePartDos

Research artifact accompanying **Trust vs. Robustness: Denial-of-Service Impact on TLS Partitioning Strategies using TrustZone for Arm Cortex-A**, 31st Nordic Conference on Secure IT Systems (NordSec).

TeePartDos evaluates TLS 1.3 cryptographic partitioning and network-load robustness on an NXP i.MX 8M Plus EVK using OP-TEE and an extended Mbed TLS 3.6.1 implementation. The repository provides scenario source code, a Yocto integration layer, functional tests, experiment tooling, campaign configurations and the recorded measurement data.

| Scenario | Cryptographic placement |
| --- | --- |
| A | Normal-world TLS |
| B | TEE-backed ticket/session secret protection |
| C | TEE-backed server identity signing |
| D | TEE-backed handshake, key-schedule and record cryptography |
| E | Combined B, C and D |

## Reproduction guide

The five documents below form a sequential procedure, from firmware construction to evaluation:

1. [Platform and firmware image](docs/01-platform-and-image.md) — NXP BSP, Yocto image, OP-TEE, patched Mbed TLS and SDK.
2. [TLS scenarios](docs/02-tls-scenarios.md) — A–E source code, TAs, compilation and installation.
3. [Functional validation](docs/03-functional-validation.md) — protocol-level regression and control tests.
4. [Experiment configuration and execution](docs/04-experiments.md) — measurement setup, orchestrator, generators and published campaign matrices.
5. [Results and evaluation](docs/05-results-and-evaluation.md) — recorded data, selection metadata and PDF/JSON/CSV evaluation.

## Repository contents

```text
platform/meta-tlsecho/       Mbed TLS BitBake layer and patches
platform/yocto/              Pinned NXP/Yocto upstream manifest
implementation/tlsecho/      TLS echo servers A–E and OP-TEE TAs
validation/functional/       Functional acceptance tests
tools/orchestrator/          Campaign control and configurations
tools/loadgen/               TLS traffic generator
tools/evaluator/             Measurement evaluation
results/raw/                 Original experimental data and manifests
docs/                        Numbered reproduction instructions
```

## Citation and licensing

Please cite the associated NordSec paper when using this artifact; see [`CITATION.cff`](CITATION.cff). Original project code is distributed under [MIT](LICENSE), subject to the separate terms and notices applicable to third-party components and source-derived patches.

This implementation is a research testbed, not a production TLS stack.
