from tee_tls_eval.analysis import aggregate_runs
from tee_tls_eval.config import load_config


def run(scenario: str, success: float, pps: float):
    return {
        "run_id": f"{scenario}-syn", "scenario": scenario, "workload": "tcp-syn", "rate": 0.0,
        "rate_semantics": "tool-controlled-observed-interface-rate", "performance_verdict": "VALID / DEGRADED",
        "phases": {"load": {"success_rate": success, "metrics": {
            "probe_total_us":{"median_ms":10.0}, "app_rtt_us":{"median_ms":1.0},
            "connection_establishment_us":{"median_ms":9.0}}}},
        "generator": {"completion_ratio": None, "external_observed_tx_pps": pps, "external_observed_tx_mbps": pps * 0.0025},
        "recovery_assessment":{"status":"recovered"},
    }


def test_tcp_syn_aggregate():
    cfg=load_config(None)
    agg=aggregate_runs([run("A",1.0,100000),run("E",0.8,95000)],cfg,"pilot")
    pts=[p for p in agg["points"] if p["workload"]=="tcp-syn"]
    assert len(pts)==2
    assert all(p["median_generator_completion"] is None for p in pts)
    assert pts[0]["median_external_observed_tx_pps"] is not None
    assert pts[0]["median_external_observed_tx_mbps"] is not None
    knees=[k for k in agg["knees"] if k["workload"]=="tcp-syn"]
    assert knees and all(k["applicable"] is False for k in knees)
    comp=next(c for c in agg["comparisons_to_A"] if c["scenario"]=="E")
    assert comp["generator_completion_delta_pp"] is None
    assert comp["external_observed_tx_pps_ratio_to_A"] == 0.95
