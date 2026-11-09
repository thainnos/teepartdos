from pathlib import Path
from tee_tls_eval.config import load_config

def test_defaults():
    c=load_config(None)
    assert c.ref_saturated_fraction == 0.05
    assert c.latency_relative == 0.10
    assert c.baseline_windows == 4
