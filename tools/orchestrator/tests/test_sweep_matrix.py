#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("orchestrate_sweep", root / "orchestrate.py")
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    cfg = td / "campaign.toml"
    cfg.write_text("""\
[experiment]
reference_duration_s=300
generator_duration_s=120
pre_generation_s=20
start_delay_s=15
[defaults.generator]
max_inflight=512
record_connections=32
""", encoding="utf-8")

    bad = td / "bad.toml"
    bad.write_text("""\
[[runs]]
scenario="Z"
rates=[]
""", encoding="utf-8")
    args = argparse.Namespace(
        config=cfg, matrix=bad, continue_on_failure=False, confirm_flood=False
    )
    try:
        module.command_sweep(args)
    except module.OrchestratorError as exc:
        message = str(exc)
        assert "missing keys" in message
    else:
        raise AssertionError("invalid sweep matrix was accepted")

    good = td / "good.toml"
    good.write_text("""\
[[runs]]
scenario="A"
profile="pilot-debug"
reference_workload="full-handshake"
generator_backend="posix"
generator_workload="full-handshake"
generator_mode="benign"
rates=[1, 2.5]
repetitions=2
reference_duration_s=10
generator_duration_s=3
pre_generation_s=2
start_delay_s=5
max_inflight=64
record_connections=8
""", encoding="utf-8")
    captured = []
    module.command_tls_run = lambda ns: captured.append(ns) or 0
    args.matrix = good
    assert module.command_sweep(args) == 0
    assert len(captured) == 4
    assert [item.generator_rate for item in captured] == [1.0, 1.0, 2.5, 2.5]
    assert [item.repetition for item in captured] == [1, 2, 1, 2]

print("sweep matrix validation: PASS")
