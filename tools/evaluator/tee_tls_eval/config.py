from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import tomllib

@dataclass(frozen=True)
class EvalConfig:
    latency_relative: float = 0.10
    latency_iqr_fraction: float = 0.50
    latency_abs_default_ms: float = 1.0
    latency_abs_app_ms: float = 0.10
    ref_degraded_fraction: float = 1e-7
    ref_saturated_fraction: float = 0.05
    gen_healthy_completion: float = 0.99
    gen_saturated_completion: float = 0.95
    baseline_windows: int = 4
    baseline_spread: float = 0.20
    recovery_relative: float = 0.10
    recovery_success_pp: float = 1.0
    recovery_final_fraction: float = 0.25
    recovery_min_target_s: float = 30.0
    repeated_support: float = 0.80
    appendix_time_series: bool = True


def load_config(path: Path | None) -> EvalConfig:
    if path is None:
        return EvalConfig()
    with path.open("rb") as fh:
        d = tomllib.load(fh)
    return EvalConfig(
        latency_relative=float(d.get("latency", {}).get("relative_increase", 0.10)),
        latency_iqr_fraction=float(d.get("latency", {}).get("iqr_fraction", 0.50)),
        latency_abs_default_ms=float(d.get("latency", {}).get("default_absolute_guard_ms", 1.0)),
        latency_abs_app_ms=float(d.get("latency", {}).get("app_rtt_absolute_guard_ms", 0.10)),
        ref_degraded_fraction=float(d.get("failures", {}).get("reference_degraded_fraction", 1e-7)),
        ref_saturated_fraction=float(d.get("failures", {}).get("reference_saturated_fraction", 0.05)),
        gen_healthy_completion=float(d.get("failures", {}).get("generator_healthy_completion", 0.99)),
        gen_saturated_completion=float(d.get("failures", {}).get("generator_saturated_completion", 0.95)),
        baseline_windows=int(d.get("baseline", {}).get("window_count", 4)),
        baseline_spread=float(d.get("baseline", {}).get("max_window_median_spread_fraction", 0.20)),
        recovery_relative=float(d.get("recovery", {}).get("relative_tolerance", 0.10)),
        recovery_success_pp=float(d.get("recovery", {}).get("success_rate_tolerance_pp", 1.0)),
        recovery_final_fraction=float(d.get("recovery", {}).get("final_fraction", 0.25)),
        recovery_min_target_s=float(d.get("recovery", {}).get("minimum_target_seconds", 30.0)),
        repeated_support=float(d.get("knee", {}).get("repeated_support_fraction", 0.80)),
        appendix_time_series=bool(d.get("report", {}).get("appendix_time_series", True)),
    )
