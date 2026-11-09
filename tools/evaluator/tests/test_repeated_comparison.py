from tee_tls_eval.analysis import aggregate_runs
from tee_tls_eval.config import load_config


def _run(scenario, rep, probe_ms):
    return {
        "run_id": f"{scenario}-{rep}", "scenario": scenario, "workload": "full-handshake", "rate": 60.0,
        "rate_semantics": "configured_offered_rate", "performance_verdict": "VALID / NO DEGRADATION",
        "phases": {"load": {"success_rate": 1.0, "metrics": {
            "probe_total_us":{"median_ms":probe_ms},
            "app_rtt_us":{"median_ms":1.0},
            "connection_establishment_us":{"median_ms":probe_ms-1.0},
        }}},
        "generator": {"completion_ratio": 1.0, "external_observed_tx_pps": None, "external_observed_tx_mbps": None},
        "recovery_assessment":{"status":"recovered"},
    }


def test_scenario_a_comparison_uses_point_medians_not_last_repetition():
    cfg=load_config(None)
    runs=[]
    # Medians are A=20 and B=40, hence ratio 2.  The deliberately extreme
    # final repetitions ensure a dictionary-overwrite implementation fails.
    for rep,value in enumerate([19,20,20,21,100],1): runs.append(_run("A",rep,value))
    for rep,value in enumerate([39,40,40,41,1],1): runs.append(_run("B",rep,value))
    agg=aggregate_runs(runs,cfg,"repeated")
    comp=next(c for c in agg["comparisons_to_A"] if c["scenario"]=="B")
    assert comp["probe_total_us_load_median_ratio_to_A"] == 2.0


def test_repeated_latency_comparison_requires_run_level_metric_support():
    cfg=load_config(None)
    runs=[]
    for rep in range(1,6):
        a=_run("A",rep,20.0)
        b=_run("B",rep,40.0)
        if rep >= 2:
            # Only one A repetition has a successful load latency observation.
            for metric in ("probe_total_us","app_rtt_us","connection_establishment_us"):
                a["phases"]["load"]["metrics"][metric]["median_ms"]=None
        runs.extend([a,b])
    agg=aggregate_runs(runs,cfg,"repeated")
    comp=next(c for c in agg["comparisons_to_A"] if c["scenario"]=="B")
    assert comp["probe_total_us_load_median_ratio_to_A"] is None
    assert comp["probe_total_us_comparison_run_support"]["scenario_A"] == 1
    assert comp["probe_total_us_comparison_run_support"]["scenario_A_required"] == 4
