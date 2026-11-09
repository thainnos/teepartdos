#!/usr/bin/env python3
"""
Plot and summarize TLS reference-client CSV results.

Designed for the native C/OpenSSL reference client used by the TEE/TLS study.

Examples:
    python3 plot_reference_client.py run.csv
    python3 plot_reference_client.py run.csv --output-dir ./plots
    python3 plot_reference_client.py run.csv --rolling-window-s 5 --formats png pdf

The script:
- validates basic CSV/metadata consistency,
- prints and writes a run summary,
- generates workload-relevant timing plots,
- does not pool repetitions or perform cross-run statistical comparison.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


IDENTITY_FIELDS = ("run_id", "scenario", "workload", "repetition")
TIMING_FIELDS = (
    "tcp_connect_us",
    "tls_handshake_us",
    "connection_establishment_us",
    "send_us",
    "time_to_first_byte_us",
    "recv_us",
    "app_rtt_us",
    "tls_shutdown_us",
    "probe_total_us",
    "schedule_lag_us",
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Plot TLS reference-client result CSV")
    p.add_argument("csv", type=Path, help="Reference-client CSV file")
    p.add_argument("--metadata", type=Path, default=None,
                   help="Metadata JSON; default: <csv stem>.metadata.json")
    p.add_argument("--output-dir", type=Path, default=None,
                   help="Output directory; default: <csv stem>_plots")
    p.add_argument("--rolling-window-s", type=float, default=5.0,
                   help="Rolling-average window in seconds (default: 5)")
    p.add_argument("--formats", nargs="+", choices=("png", "pdf"), default=("png",),
                   help="Plot formats (default: png)")
    p.add_argument("--dpi", type=int, default=180, help="PNG DPI (default: 180)")
    return p.parse_args()


def one_value(df: pd.DataFrame, column: str):
    if column not in df.columns:
        return None
    vals = df[column].dropna().unique()
    if len(vals) == 1:
        return vals[0]
    if len(vals) == 0:
        return None
    return list(vals)


def load_metadata(path: Path | None) -> dict | None:
    if path is None or not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def metadata_default(csv_path: Path) -> Path:
    if csv_path.name.endswith(".csv"):
        return csv_path.with_name(csv_path.name[:-4] + ".metadata.json")
    return csv_path.with_suffix(".metadata.json")


def validate_identity(df: pd.DataFrame, meta: dict | None) -> list[str]:
    warnings: list[str] = []
    for field in IDENTITY_FIELDS:
        value = one_value(df, field)
        if isinstance(value, list):
            warnings.append(f"CSV contains multiple values for identity field {field}: {value}")
        if meta is not None and field in meta and not isinstance(value, list) and value is not None:
            csv_text = str(value)
            meta_text = str(meta[field])
            if csv_text != meta_text:
                warnings.append(
                    f"CSV/metadata mismatch for {field}: CSV={csv_text!r}, metadata={meta_text!r}"
                )
    return warnings


def to_numeric(df: pd.DataFrame) -> None:
    numeric_candidates = set(TIMING_FIELDS) | {
        "elapsed_run_us",
        "scheduled_elapsed_us",
        "missed_slots_before",
        "result_code",
        "bytes_sent",
        "bytes_received",
        "probe_id",
        "connection_id",
    }
    for c in numeric_candidates:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")


def bool_series(series: pd.Series) -> pd.Series:
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False)
    return series.astype(str).str.lower().map(
        {"true": True, "false": False, "1": True, "0": False}
    )


def metric_stats(series: pd.Series) -> dict | None:
    s = pd.to_numeric(series, errors="coerce").dropna()
    if len(s) == 0:
        return None
    return {
        "n": int(len(s)),
        "min": float(s.min()),
        "q1": float(s.quantile(0.25)),
        "median": float(s.median()),
        "q3": float(s.quantile(0.75)),
        "max": float(s.max()),
        "mean": float(s.mean()),
    }


def fmt_ms(us: float) -> str:
    return f"{us / 1000.0:.3f} ms"


def summary_text(df: pd.DataFrame, meta: dict | None, warnings: list[str]) -> str:
    lines: list[str] = []
    lines.append("TLS reference-client run summary")
    lines.append("=" * 32)

    for field in IDENTITY_FIELDS:
        lines.append(f"{field}: {one_value(df, field)}")

    lines.append(f"rows: {len(df)}")

    if "elapsed_run_us" in df.columns and df["elapsed_run_us"].notna().any():
        elapsed = df["elapsed_run_us"].dropna()
        lines.append(f"measured time span: {elapsed.min()/1e6:.6f} .. {elapsed.max()/1e6:.6f} s")

    if meta is not None:
        if "configured_duration_s" in meta:
            lines.append(f"configured duration: {meta['configured_duration_s']} s")
        if "configured_probe_interval_ms" in meta:
            lines.append(f"configured probe interval: {meta['configured_probe_interval_ms']} ms")
        if "openssl_runtime_version" in meta:
            lines.append(f"OpenSSL runtime: {meta['openssl_runtime_version']}")

    if "result_code" in df.columns:
        success = int((df["result_code"] == 0).sum())
        lines.append(f"successful probes: {success}/{len(df)} ({100.0*success/max(len(df),1):.1f}%)")

    if "missed_slots_before" in df.columns:
        missed = int(df["missed_slots_before"].fillna(0).sum())
        lines.append(f"missed scheduling slots: {missed}")

    if "session_reused" in df.columns:
        valid = df["session_reused"].notna()
        if valid.any():
            reused = bool_series(df.loc[valid, "session_reused"])
            lines.append(
                f"session_reused=true: {int(reused.sum())}/{len(reused)} "
                f"({100.0*reused.mean():.1f}%)"
            )

    if "payload_match" in df.columns:
        valid = df["payload_match"].notna()
        if valid.any():
            match = bool_series(df.loc[valid, "payload_match"])
            lines.append(
                f"payload_match=true: {int(match.sum())}/{len(match)} "
                f"({100.0*match.mean():.1f}%)"
            )

    lines.append("")
    lines.append("Timing statistics")
    lines.append("-----------------")
    for field in (
        "tcp_connect_us",
        "tls_handshake_us",
        "connection_establishment_us",
        "app_rtt_us",
        "probe_total_us",
        "schedule_lag_us",
    ):
        if field in df.columns:
            st = metric_stats(df[field])
            if st:
                lines.append(
                    f"{field}: median={fmt_ms(st['median'])}, "
                    f"IQR={fmt_ms(st['q1'])}..{fmt_ms(st['q3'])}, "
                    f"min={fmt_ms(st['min'])}, max={fmt_ms(st['max'])}, n={st['n']}"
                )

    if warnings:
        lines.append("")
        lines.append("Warnings")
        lines.append("--------")
        lines.extend(f"- {w}" for w in warnings)

    if len(df) < 10:
        lines.append("")
        lines.append(
            "NOTE: fewer than 10 measured probes are present; plots/statistics are suitable "
            "for functional/pilot inspection only, not inferential or campaign-level conclusions."
        )

    return "\n".join(lines) + "\n"


def elapsed_seconds(df: pd.DataFrame) -> pd.Series:
    if "elapsed_run_us" in df.columns:
        return df["elapsed_run_us"] / 1e6
    return pd.Series(np.arange(len(df)), index=df.index, dtype=float)


def rolling_samples(df: pd.DataFrame, window_s: float) -> int:
    if window_s <= 0 or len(df) < 2 or "elapsed_run_us" not in df.columns:
        return 1
    t = df["elapsed_run_us"].dropna().sort_values().to_numpy() / 1e6
    if len(t) < 2:
        return 1
    deltas = np.diff(t)
    deltas = deltas[deltas > 0]
    if len(deltas) == 0:
        return 1
    period = float(np.median(deltas))
    return max(1, int(round(window_s / period)))


def save_figure(fig: plt.Figure, stem: Path, formats: list[str], dpi: int) -> None:
    for fmt in formats:
        out = stem.with_suffix("." + fmt)
        if fmt == "png":
            fig.savefig(out, dpi=dpi, bbox_inches="tight")
        else:
            fig.savefig(out, bbox_inches="tight")
    plt.close(fig)


def add_identity_title(ax: plt.Axes, df: pd.DataFrame, suffix: str) -> None:
    scenario = one_value(df, "scenario")
    workload = one_value(df, "workload")
    repetition = one_value(df, "repetition")
    ax.set_title(f"Scenario {scenario} — {workload}, repetition {repetition}: {suffix}")


def plot_handshake(df: pd.DataFrame, outdir: Path, formats: list[str], dpi: int) -> None:
    wanted = [c for c in ("tcp_connect_us", "tls_handshake_us", "connection_establishment_us")
              if c in df.columns and df[c].notna().any()]
    if not wanted:
        return
    x = elapsed_seconds(df)
    fig, ax = plt.subplots()
    for c in wanted:
        ax.plot(x, df[c] / 1000.0, marker="o", label=c.removesuffix("_us").replace("_", " "))
    ax.set_xlabel("Elapsed run time (s)")
    ax.set_ylabel("Latency (ms)")
    add_identity_title(ax, df, "connection and handshake timing")
    ax.grid(True)
    ax.legend()
    save_figure(fig, outdir / "01_connection_handshake_latency", formats, dpi)


def plot_app_rtt(df: pd.DataFrame, outdir: Path, formats: list[str], dpi: int,
                 rolling_window_s: float) -> None:
    if "app_rtt_us" not in df.columns or not df["app_rtt_us"].notna().any():
        return
    x = elapsed_seconds(df)
    y = df["app_rtt_us"] / 1000.0
    n = rolling_samples(df, rolling_window_s)

    fig, ax = plt.subplots()
    ax.plot(x, y, marker="o", label="application RTT")
    if n > 1:
        rolling = y.rolling(window=n, min_periods=1).mean()
        ax.plot(x, rolling, label=f"rolling mean (~{rolling_window_s:g} s)")
    ax.set_xlabel("Elapsed run time (s)")
    ax.set_ylabel("Application echo RTT (ms)")
    add_identity_title(ax, df, "application RTT")
    ax.grid(True)
    ax.legend()
    save_figure(fig, outdir / "02_application_rtt", formats, dpi)


def plot_probe_total(df: pd.DataFrame, outdir: Path, formats: list[str], dpi: int) -> None:
    if "probe_total_us" not in df.columns or not df["probe_total_us"].notna().any():
        return
    x = elapsed_seconds(df)
    fig, ax = plt.subplots()
    ax.plot(x, df["probe_total_us"] / 1000.0, marker="o", label="probe total")
    ax.set_xlabel("Elapsed run time (s)")
    ax.set_ylabel("Probe duration (ms)")
    add_identity_title(ax, df, "total probe duration")
    ax.grid(True)
    ax.legend()
    save_figure(fig, outdir / "03_probe_total", formats, dpi)


def plot_schedule(df: pd.DataFrame, outdir: Path, formats: list[str], dpi: int) -> None:
    if "schedule_lag_us" not in df.columns or not df["schedule_lag_us"].notna().any():
        return
    x = elapsed_seconds(df)
    fig, ax = plt.subplots()
    ax.plot(x, df["schedule_lag_us"] / 1000.0, marker="o", label="schedule lag")
    ax.set_xlabel("Elapsed run time (s)")
    ax.set_ylabel("Scheduling lag (ms)")
    add_identity_title(ax, df, "reference-client scheduling")
    ax.grid(True)
    ax.legend()
    save_figure(fig, outdir / "04_schedule_lag", formats, dpi)


def main() -> int:
    args = parse_args()
    if not args.csv.exists():
        print(f"CSV not found: {args.csv}", file=sys.stderr)
        return 2

    metadata_path = args.metadata if args.metadata is not None else metadata_default(args.csv)
    output_dir = args.output_dir if args.output_dir is not None else Path(
        str(args.csv.with_suffix("")) + "_plots"
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(args.csv)
    if df.empty:
        print("CSV contains no data rows.", file=sys.stderr)
        return 2

    to_numeric(df)
    meta = load_metadata(metadata_path)
    warnings = validate_identity(df, meta)

    summary = summary_text(df, meta, warnings)
    print(summary, end="")
    (output_dir / "run_summary.txt").write_text(summary, encoding="utf-8")

    formats = list(args.formats)
    plot_handshake(df, output_dir, formats, args.dpi)
    plot_app_rtt(df, output_dir, formats, args.dpi, args.rolling_window_s)
    plot_probe_total(df, output_dir, formats, args.dpi)
    plot_schedule(df, output_dir, formats, args.dpi)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
