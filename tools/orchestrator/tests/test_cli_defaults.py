#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("orchestrate_module", root / "orchestrate.py")
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

subprocess.run(
    ["python3", str(root / "orchestrate.py"), "--help"],
    check=True,
    stdout=subprocess.DEVNULL,
)

args = module.parser().parse_args([
    "tls-run",
    "--config", str(root / "config" / "campaign.example.toml"),
    "--scenario", "A",
    "--reference-workload", "full-handshake",
    "--generator-backend", "posix",
    "--generator-workload", "full-handshake",
    "--generator-mode", "benign",
    "--generator-rate", "1",
    "--repetition", "1",
])
assert args.reference_duration is None
assert args.generator_duration is None
assert args.generator_max_inflight is None
assert args.generator_connections is None
assert args.pre_generation is None
assert args.start_delay is None

cfg = module.load_config(root / "config" / "campaign.example.toml")
module.resolve_tls_defaults(cfg, args)
assert args.reference_duration == 300
assert args.generator_duration == 120
assert args.generator_max_inflight == 512
assert args.generator_connections == 32
assert args.pre_generation == 20
assert args.start_delay == 15
print("CLI parser and central defaults: PASS")
