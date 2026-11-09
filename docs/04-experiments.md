# 04 — Experiment configuration and execution

The reference experiments use three roles: an NXP i.MX 8M Plus EVK running a TLS echo server (DUT), a reference/measurement host running the native reference client and orchestrator, and a separate traffic-generator host. The DUT's measurement path and the SSH/control-and-collection path use distinct network interfaces.

## Reference software and hardware

| Component | Reference configuration |
| --- | --- |
| DUT | NXP i.MX 8M Plus EVK with Yocto, OP-TEE and patched Mbed TLS |
| Reference host | Armbian; native OpenSSL-based reference client |
| Generator host | Ubuntu Server 24.04 |
| Reference-client TLS library | OpenSSL 3.5.7 |
| Generator | POSIX or F-Stack/DPDK TLS traffic generator; Intel 82574L NIC with VFIO/hugepages for F-Stack |
| Orchestration | Python controller and remote DUT/generator agents |

## 1. Build the reference client

From `tools/orchestrator/reference_client/`:

```bash
make OPENSSL_PREFIX=/path/to/openssl
make check
make smoke
```

The reference client records scheduled probe attempts, latency, TLS negotiation and outcome metadata. Configure the trust certificate and the measurement interface for the local environment.

## 2. Build the generator

From `tools/loadgen/`, for a POSIX build:

```bash
make OPENSSL_PREFIX=/path/to/openssl posix check smoke-posix
```

For F-Stack, install the matching F-Stack/DPDK prerequisites, configure hugepages and the dedicated PCI NIC, and build with:

```bash
make OPENSSL_PREFIX=/path/to/openssl \
  FSTACK_PATH=/path/to/f-stack fstack
```

The provided `tools/loadgen/scripts/` utilities assist with the toolchain and interface preflights. Binding a NIC to VFIO removes it from the normal kernel-network path. Validate NIC configuration, neighbor reachability and CPU assignment before a measurement.

## 3. Configure orchestration

From `tools/orchestrator/`, copy `config/campaign.example.toml` to the untracked `config/campaign.local.toml` and replace all `CHANGE_ME` values. Supply the three hosts' addresses, interfaces, certificate paths, server binary locations, generator executable and agent paths. Use the reference campaign parameters from `config/paper/`.

The recorded reference setup used **password-based SSH authentication**, which is the default in `config/campaign.example.toml` and `orchestrate.py`. Install `sshpass` on the reference host (the dependency script installs it by default), and set `dut.ssh_password` and `loadgen.ssh_password` in the **untracked**, permission-restricted `campaign.local.toml`. Public-key authentication remains an available alternative when `ssh.auth = "key"`, but it has not been verified against the recorded reference setup. Do not commit passwords or private test keys.

Verify readiness and deploy the remote experiment agents:

```bash
make check
python3 orchestrate.py validate-config --config config/campaign.local.toml
python3 orchestrate.py ssh-check --config config/campaign.local.toml
python3 orchestrate.py deploy --config config/campaign.local.toml
python3 orchestrate.py init --config config/campaign.local.toml \
  --backend fstack --profile measurement
```

Use the POSIX backend where appropriate; the published TLS experiment matrices specify their generator backend. The measurement configuration uses two independent network paths and synchronized clocks.

## 4. Execute campaign matrices

The final campaign TOMLs are under `tools/orchestrator/config/paper/`. The folders `benign/`, `tls-medium/`, `tls-high/` and `tcp-syn/` each contain matrices `A.toml` through `E.toml`.

From `tools/orchestrator/`:

```bash
python3 campaignctl.py run --config config/campaign.local.toml \
  --matrix config/paper/benign/A.toml
```

Repeat with the required scenario and campaign matrices. These retain the recorded rates, repetitions and phases. A reference run covers 300 s, including a 20 s pre-generation period and 120 s generator interval; see each TOML and its recorded timeline for exact parameters.

The `tcp-syn/` matrices invoke an external traffic generator: their `rates = [0.0]` is a control sentinel, **not** a zero-intensity experiment. The exact external command/version must be configured separately in `tools/loadgen/config/external_tool.toml` before reproducing that campaign. The public `tools/loadgen/config/external_tool.example.toml` intentionally contains a benign placeholder and does **not** encode the recorded flood. For provenance, the command used in a recorded run is retained in that run's `generator/output/.../external_tool.command.txt`; review the historical measurement metadata and tool version before constructing your own local configuration. Do not treat the example command as the published workload.

## 5. Verify campaign records

```bash
python3 campaignctl.py verify \
  --results-root /path/to/results \
  --overall-campaign-id ABCDE-tls-benign-final-v1
```

Maintain the campaign/run manifests and their `selected`/`superseded` state. Runs must be selected by the manifest metadata, not simply by filename or timestamp. The evaluator and original campaign identifiers are documented in [05 — Results and evaluation](05-results-and-evaluation.md).
