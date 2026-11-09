# 03 — Functional validation

The canonical regression suite is in `validation/functional/`. It checks the compiled and deployed TLS servers and OP-TEE TAs against the protocol behaviors required by Scenarios A–E.

## Tests

| Test | Verification |
| --- | --- |
| A | Normal-world TLS handshakes and resumption |
| B | TEE-backed ticket protection and resumption |
| C | External server identity signing |
| C negative control | Expected behavior when external signing is unavailable |
| D | Active TEE cryptographic backend and resumption |
| D disabled control | Expected behavior without the backend |
| E | Combined ticket, signing, handshake and record operations |

The historical acceptance results are available in `validation/functional/reference/results.tsv`.

## Run the regression suite

Configure target connectivity, the trust certificate and server credential locations. From the repository root:

```bash
bash validation/functional/run_all_checks.sh \
  --board-ip <dut-service-ip> \
  --ssh-target <user@dut> \
  --ca-file /absolute/path/to/ca.crt \
  --remote-cert /root/certs/server.crt \
  --remote-key /root/certs/server.key \
  --out-root /absolute/path/to/validation-results
```

Use `--help` for repetition counts, readiness timeout and additional options. The suite controls the corresponding remote servers and runs seven scenario-specific checks. Review each check's logs and the aggregate result.

The suite assumes the executable layout described in [02 — TLS scenarios](02-tls-scenarios.md). Change the deployed paths and script settings together if the target uses a different layout. The tests require that the service address and certificate match.

**Completion criterion:** All seven checks pass, including the negative/backend-disabled controls. Save the logs and test configuration alongside the run metadata.
