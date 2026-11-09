#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import multiprocessing
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("orchestrate_module", root / "orchestrate.py")
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def try_lock(state_root: str, queue: multiprocessing.Queue[str]) -> None:
    cfg = module.CampaignConfig(Path("/tmp/test.toml"), {
        "repository": {"state_root": state_root}
    })
    try:
        with module.campaign_lock(cfg, "second"):
            queue.put("unexpected-success")
    except module.OrchestratorError:
        queue.put("blocked")


with tempfile.TemporaryDirectory() as td:
    cfg = module.CampaignConfig(Path(td) / "test.toml", {
        "repository": {"state_root": td}
    })
    with module.campaign_lock(cfg, "first"):
        queue: multiprocessing.Queue[str] = multiprocessing.Queue()
        proc = multiprocessing.Process(target=try_lock, args=(td, queue))
        proc.start()
        proc.join(5)
        assert proc.exitcode == 0
        assert queue.get(timeout=1) == "blocked"
    with module.campaign_lock(cfg, "after-release"):
        pass
print("campaign lock: PASS")
