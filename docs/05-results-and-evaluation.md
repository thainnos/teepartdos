# 05 — Results and evaluation

The recorded measurement data are under `results/raw/`. Each run retains reference-client, generator and DUT outputs and the corresponding campaign/run metadata. The evaluator in `tools/evaluator/` produces a self-contained PDF report, machine-readable JSON and flat CSV summary.

## Recorded campaigns

| Campaign | Overall campaign ID | Selected runs |
| --- | --- | ---: |
| Benign TLS | `ABCDE-tls-benign-final-v1` | 75 |
| Medium TLS load | `ABCDE-tls-flood-medium-final-v1` | 75 |
| High TLS load | `ABCDE-tls-flood-high-final-v1` | 75 |
| External TCP stress | `ABCDE-external-tcp-final-20260813-01` | 25 |
| **Total** | | **250** |

The historical manifests mark 250 selected validated runs and 18 superseded runs. Superseded measurements are retained but excluded from the selected-set analysis.

## Evaluate an overall campaign

From `tools/evaluator/`:

```bash
python3 -m pip install -r requirements.txt
python3 -m pytest tests
python3 evaluate_campaign.py \
  --results-root ../../results/raw \
  --overall-campaign-id ABCDE-tls-benign-final-v1 \
  --output-dir ../../results-local/benign
```

Repeat with the other overall campaign IDs. `evaluator_config.toml` defines analysis and validity thresholds. The evaluator reconstructs expected reference opportunities over baseline, load and recovery phases, uses only selected run repetitions, and reports external network load using observed packet/s and Mbit/s.

Generated reports are outputs, not canonical input data. Keep measurement values, time series, selections and run/campaign identifiers unchanged. Before publication, machine-specific usernames in raw logs may be replaced with stable, explicit pseudonyms solely for privacy. Such sanitized files are **not byte-identical** to the original collected artifacts. Historical checksum records, where retained, describe the original archived material, not necessarily the published redacted bytes; a mismatch must not be interpreted as proof of measurement tampering or as successful verification of the redacted version. For byte-integrity checks of the public release, generate and publish a separate manifest of hashes computed from the final public bytes, without overwriting historical records.

## External-TCP D/E identifier mapping

Two original scenario-campaign **names** are interchanged. Their actual scenario metadata and the normalized campaign matrices remain authoritative:

| Original campaign ID | Scenario represented |
| --- | --- |
| `D-external-tcp-final-20260812-01` | E |
| `E-external-tcp-final-20260812-01` | D |

Use the `scenario`, point/run identifiers and overall campaign manifest for correct associations. Do not rename the original raw records.

## Dataset interpretation

The original campaign index is `results/raw/_campaigns/index.json`. Results may be compared with newly collected data by retaining their recorded test conditions, run validity, selected repetition state and time phases. Report the platform and traffic-generation differences whenever comparisons use a different experimental environment.
