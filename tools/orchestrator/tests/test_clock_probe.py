#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("orchestrate", root / "orchestrate.py")
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

probe_script = r'''
printf 'READY\n'
while IFS= read -r probe_id; do
    now=$(date +%s%N)
    printf '%s %s\n' "$probe_id" "$now"
done
'''

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    cfg_path = td / "campaign.toml"
    cfg_path.write_text("[experiment]\nclock_samples = 5\n", encoding="utf-8")
    cfg = module.CampaignConfig(cfg_path, {"experiment": {"clock_samples": 5}})

    original_argv = module._clock_probe_argv
    original_password = module.ssh_password
    module._clock_probe_argv = lambda _cfg, _host, _fd: ["/bin/sh", "-c", probe_script]
    module.ssh_password = lambda _cfg, _host: "unused"
    try:
        result = module.measure_clock(cfg, "dut")
    finally:
        module._clock_probe_argv = original_argv
        module.ssh_password = original_password

assert result["method"] == "established-ssh-request-reply"
assert len(result["samples"]) == 5
assert result["uncertainty_ms"] < 100.0, result
assert abs(result["offset_ms"]) < 100.0, result
assert abs(result["round_trip_ms"] - 2 * result["uncertainty_ms"]) < 1e-9
print("clock probe transport: PASS")
