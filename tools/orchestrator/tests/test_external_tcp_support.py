#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

orch = load("orchestrate_external_tcp_test", ROOT / "orchestrate.py")
ctl = load("campaignctl_external_tcp_test", ROOT / "campaignctl.py")

args = argparse.Namespace(
    scenario="A", profile="measurement", reference_workload="full-handshake",
    reference_duration=300, generator_backend="posix", generator_workload="tcp-syn",
    generator_mode="flood", generator_rate=0.0, generator_duration=120,
    generator_max_inflight=4096, generator_connections=32, repetition=1,
    pre_generation=20, start_delay=15,
)
assert orch.validate_tls_arguments(args) == []
args.generator_rate = 1.0
assert any("exactly 0" in e for e in orch.validate_tls_arguments(args))
args.generator_rate = 0.0; args.generator_backend = "fstack"
assert any("posix" in e for e in orch.validate_tls_arguments(args))
args.generator_backend = "posix"; args.reference_workload = "record"
assert any("full-handshake" in e for e in orch.validate_tls_arguments(args))

config = {
    "experiment": {"reference_duration_s": 300, "generator_duration_s": 120, "pre_generation_s": 20, "start_delay_s": 15},
    "defaults": {"generator": {"max_inflight": 4096, "record_connections": 32}},
}
matrix = {"runs": [{
    "scenario": "A", "profile": "measurement", "reference_workload": "full-handshake",
    "generator_backend": "posix", "generator_workload": "tcp-syn", "generator_mode": "flood",
    "rates": [0.0], "repetitions": 5,
}]}
points = ctl.expand_points(matrix, config)
assert len(points) == 5 and all(point.generator_rate == 0.0 for point in points)
assert [point.repetition for point in points] == [1, 2, 3, 4, 5]
for key, value in (("generator_backend", "fstack"), ("generator_mode", "benign"), ("reference_workload", "resumption")):
    bad = {"runs": [dict(matrix["runs"][0], **{key: value})]}
    try:
        ctl.expand_points(bad, config)
    except ctl.CampaignError:
        pass
    else:
        raise AssertionError(f"tcp-syn invalid combination accepted: {key}={value}")
print("orchestrator/campaign external TCP workload support test: PASS")
