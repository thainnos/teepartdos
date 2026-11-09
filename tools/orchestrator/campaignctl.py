#!/usr/bin/env python3
"""Automated campaign tracking for the TEE/TLS measurement orchestrator.

This companion command keeps the existing single-run orchestrator unchanged.
It expands one scenario-specific matrix, invokes ``orchestrate.py tls-run`` for
one point at a time, annotates every raw run with campaign identities, and
maintains portable campaign and overall-campaign manifests below the single
configured results root.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit("Python 3.11 or newer is required (tomllib missing).") from exc

SCHEMA_VERSION = 1
CAMPAIGN_TYPES = {"pilot", "repeated"}
SCENARIOS = set("ABCDE")
BACKENDS = {"posix", "fstack"}
MODES = {"benign", "flood"}
REFERENCE_WORKLOADS = {"full-handshake", "resumption", "record"}
GENERATOR_WORKLOADS = REFERENCE_WORKLOADS | {"tcp-syn"}
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class CampaignError(RuntimeError):
    pass


@dataclass(frozen=True)
class Point:
    point_id: str
    scenario: str
    profile: str
    reference_workload: str
    reference_duration_s: int
    generator_backend: str
    generator_workload: str
    generator_mode: str
    generator_rate: float
    generator_duration_s: int
    generator_max_inflight: int
    generator_connections: int
    repetition: int
    pre_generation_s: int
    start_delay_s: int


def utc_iso_ns(epoch_ns: int | None = None) -> str:
    if epoch_ns is None:
        epoch_ns = time.time_ns()
    sec, ns = divmod(epoch_ns, 1_000_000_000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sec)) + f".{ns:09d}Z"


def atomic_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CampaignError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CampaignError(f"JSON root must be an object: {path}")
    return value


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as fh:
            value = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise CampaignError(f"cannot read TOML {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CampaignError(f"TOML root must be a table: {path}")
    return value


def nested(data: dict[str, Any], dotted: str, default: Any = None) -> Any:
    cur: Any = data
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def resolve_path(raw: Any, *, relative_to: Path) -> Path:
    text = os.path.expanduser(str(raw))
    path = Path(text)
    if not path.is_absolute():
        path = relative_to / path
    return path.resolve()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_id(name: str, value: str) -> str:
    if not SAFE_ID.fullmatch(value):
        raise CampaignError(
            f"{name} must match {SAFE_ID.pattern!r} and be at most 128 characters: {value!r}"
        )
    return value


def rate_token(rate: float) -> str:
    return format(rate, ".12g").replace("-", "m").replace(".", "p")


def point_identity(spec: dict[str, Any], rate: float, repetition: int) -> str:
    return "__".join(
        [
            str(spec["scenario"]),
            str(spec["reference_workload"]),
            str(spec["generator_workload"]),
            str(spec.get("generator_mode", "benign")),
            str(spec["generator_backend"]),
            f"rate_{rate_token(rate)}",
            f"rep_{repetition}",
        ]
    )


def require_positive_int(value: Any, label: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise CampaignError(f"{label} must be an integer") from exc
    if number <= 0:
        raise CampaignError(f"{label} must be positive")
    return number


def require_nonnegative_int(value: Any, label: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise CampaignError(f"{label} must be an integer") from exc
    if number < 0:
        raise CampaignError(f"{label} must be non-negative")
    return number


def expand_points(matrix: dict[str, Any], config: dict[str, Any]) -> list[Point]:
    runs = matrix.get("runs")
    if not isinstance(runs, list) or not runs:
        raise CampaignError("matrix must contain at least one [[runs]] table")

    defaults = {
        "reference_duration_s": nested(config, "experiment.reference_duration_s", 300),
        "generator_duration_s": nested(config, "experiment.generator_duration_s", 120),
        "pre_generation_s": nested(config, "experiment.pre_generation_s", 20),
        "start_delay_s": nested(config, "experiment.start_delay_s", 15),
        "max_inflight": nested(config, "defaults.generator.max_inflight", 512),
        "record_connections": nested(config, "defaults.generator.record_connections", 32),
    }

    points: list[Point] = []
    seen: set[str] = set()
    required = {
        "scenario",
        "profile",
        "reference_workload",
        "generator_backend",
        "generator_workload",
        "rates",
        "repetitions",
    }
    for index, raw in enumerate(runs, start=1):
        if not isinstance(raw, dict):
            raise CampaignError(f"runs[{index}] must be a table")
        missing = sorted(required - raw.keys())
        if missing:
            raise CampaignError(f"runs[{index}] missing keys: {', '.join(missing)}")
        scenario = str(raw["scenario"])
        backend = str(raw["generator_backend"])
        mode = str(raw.get("generator_mode", "benign"))
        ref_workload = str(raw["reference_workload"])
        gen_workload = str(raw["generator_workload"])
        if scenario not in SCENARIOS:
            raise CampaignError(f"runs[{index}] invalid scenario: {scenario}")
        if backend not in BACKENDS:
            raise CampaignError(f"runs[{index}] invalid backend: {backend}")
        if mode not in MODES:
            raise CampaignError(f"runs[{index}] invalid generator_mode: {mode}")
        if ref_workload not in REFERENCE_WORKLOADS:
            raise CampaignError(f"runs[{index}] invalid reference workload: {ref_workload}")
        if gen_workload not in GENERATOR_WORKLOADS:
            raise CampaignError(f"runs[{index}] invalid generator workload: {gen_workload}")
        if gen_workload == "tcp-syn":
            if backend != "posix":
                raise CampaignError(f"runs[{index}] tcp-syn requires generator_backend=posix")
            if mode != "flood":
                raise CampaignError(f"runs[{index}] tcp-syn requires generator_mode=flood")
            if ref_workload != "full-handshake":
                raise CampaignError(f"runs[{index}] tcp-syn requires reference_workload=full-handshake")
        rates = raw["rates"]
        if not isinstance(rates, list) or not rates:
            raise CampaignError(f"runs[{index}].rates must be a non-empty array")
        repetitions = require_positive_int(raw["repetitions"], f"runs[{index}].repetitions")
        reference_duration = require_positive_int(
            raw.get("reference_duration_s", defaults["reference_duration_s"]),
            f"runs[{index}].reference_duration_s",
        )
        generator_duration = require_positive_int(
            raw.get("generator_duration_s", defaults["generator_duration_s"]),
            f"runs[{index}].generator_duration_s",
        )
        pre_generation = require_nonnegative_int(
            raw.get("pre_generation_s", defaults["pre_generation_s"]),
            f"runs[{index}].pre_generation_s",
        )
        start_delay = require_positive_int(
            raw.get("start_delay_s", defaults["start_delay_s"]),
            f"runs[{index}].start_delay_s",
        )
        max_inflight = require_positive_int(
            raw.get("max_inflight", defaults["max_inflight"]),
            f"runs[{index}].max_inflight",
        )
        record_connections = require_positive_int(
            raw.get("record_connections", defaults["record_connections"]),
            f"runs[{index}].record_connections",
        )
        if pre_generation + generator_duration > reference_duration:
            raise CampaignError(
                f"runs[{index}] generated interval exceeds reference duration"
            )
        for rate_raw in rates:
            try:
                rate = float(rate_raw)
            except (TypeError, ValueError) as exc:
                raise CampaignError(f"runs[{index}] invalid rate: {rate_raw!r}") from exc
            if gen_workload == "tcp-syn":
                if rate != 0.0:
                    raise CampaignError(f"runs[{index}] tcp-syn rate must be exactly 0")
            elif not (rate > 0.0):
                raise CampaignError(f"runs[{index}] rate must be positive")
            for repetition in range(1, repetitions + 1):
                pid = point_identity(raw, rate, repetition)
                if pid in seen:
                    raise CampaignError(f"duplicate matrix point: {pid}")
                seen.add(pid)
                points.append(
                    Point(
                        point_id=pid,
                        scenario=scenario,
                        profile=str(raw["profile"]),
                        reference_workload=ref_workload,
                        reference_duration_s=reference_duration,
                        generator_backend=backend,
                        generator_workload=gen_workload,
                        generator_mode=mode,
                        generator_rate=rate,
                        generator_duration_s=generator_duration,
                        generator_max_inflight=max_inflight,
                        generator_connections=record_connections,
                        repetition=repetition,
                        pre_generation_s=pre_generation,
                        start_delay_s=start_delay,
                    )
                )
    return points


def validate_homogeneous(points: list[Point]) -> tuple[str, str, str]:
    scenarios = {point.scenario for point in points}
    backends = {point.generator_backend for point in points}
    modes = {point.generator_mode for point in points}
    if len(scenarios) != 1:
        raise CampaignError(
            "one campaign must contain exactly one scenario; create separate A-E campaigns"
        )
    if len(backends) != 1:
        raise CampaignError("backend mixing inside a campaign is rejected")
    if len(modes) != 1:
        raise CampaignError("benign and flood workloads must use separate campaigns")
    return next(iter(scenarios)), next(iter(backends)), next(iter(modes))


def results_root_from_config(config_path: Path, config: dict[str, Any]) -> Path:
    raw = nested(config, "repository.results_root")
    if raw is None:
        raise CampaignError("missing configuration key repository.results_root")
    return resolve_path(raw, relative_to=config_path.parent)


def campaign_paths(results_root: Path, overall_id: str, campaign_id: str) -> tuple[Path, Path, Path]:
    meta_root = results_root / "_campaigns"
    overall_dir = meta_root / overall_id
    campaign_dir = overall_dir / "campaigns" / campaign_id
    return meta_root, overall_dir, campaign_dir


def manifest_point(point: Point) -> dict[str, Any]:
    return {
        "point_id": point.point_id,
        "scenario": point.scenario,
        "profile": point.profile,
        "reference_workload": point.reference_workload,
        "reference_duration_s": point.reference_duration_s,
        "generator_backend": point.generator_backend,
        "generator_workload": point.generator_workload,
        "generator_mode": point.generator_mode,
        "generator_rate": point.generator_rate,
        "generator_duration_s": point.generator_duration_s,
        "generator_max_inflight": point.generator_max_inflight,
        "generator_connections": point.generator_connections,
        "repetition": point.repetition,
        "pre_generation_s": point.pre_generation_s,
        "start_delay_s": point.start_delay_s,
    }


def point_command(
    *,
    orchestrate: Path,
    config_path: Path,
    point: Point,
    confirm_flood: bool,
) -> list[str]:
    command = [
        sys.executable,
        str(orchestrate),
        "tls-run",
        "--config",
        str(config_path),
        "--scenario",
        point.scenario,
        "--profile",
        point.profile,
        "--reference-workload",
        point.reference_workload,
        "--reference-duration",
        str(point.reference_duration_s),
        "--generator-backend",
        point.generator_backend,
        "--generator-workload",
        point.generator_workload,
        "--generator-mode",
        point.generator_mode,
        "--generator-rate",
        format(point.generator_rate, ".12g"),
        "--generator-duration",
        str(point.generator_duration_s),
        "--generator-max-inflight",
        str(point.generator_max_inflight),
        "--generator-connections",
        str(point.generator_connections),
        "--repetition",
        str(point.repetition),
        "--pre-generation",
        str(point.pre_generation_s),
        "--start-delay",
        str(point.start_delay_s),
    ]
    if point.generator_mode == "flood":
        if not confirm_flood:
            raise CampaignError("flood campaign requires --confirm-flood")
        command.append("--confirm-flood")
    return command


def snapshot_runs(results_root: Path) -> set[Path]:
    if not results_root.exists():
        return set()
    return {path.resolve() for path in results_root.glob("scenario_*/**/run_manifest.json")}


def relative_result_dir(results_root: Path, manifest_path: Path) -> str:
    try:
        return manifest_path.parent.resolve().relative_to(results_root.resolve()).as_posix()
    except ValueError as exc:
        raise CampaignError(f"run is outside results root: {manifest_path}") from exc


def read_validation(run_dir: Path) -> tuple[str, list[str], list[str]]:
    path = run_dir / "validation.json"
    if not path.exists():
        return "MISSING", ["validation.json missing"], []
    value = load_json(path)
    return (
        str(value.get("status", "UNKNOWN")),
        [str(item) for item in value.get("errors", [])],
        [str(item) for item in value.get("warnings", [])],
    )


def annotate_run(
    manifest_path: Path,
    *,
    campaign_id: str,
    overall_id: str,
    campaign_type: str,
    point: Point,
    matrix_sha256: str,
) -> dict[str, Any]:
    value = load_json(manifest_path)
    expected = {
        "scenario": point.scenario,
        "reference_workload": point.reference_workload,
        "generator_workload": point.generator_workload,
        "generator_mode": point.generator_mode,
        "generator_backend": point.generator_backend,
        "repetition": point.repetition,
    }
    for key, wanted in expected.items():
        if str(value.get(key)) != str(wanted):
            raise CampaignError(
                f"new run manifest {manifest_path} has {key}={value.get(key)!r}, expected {wanted!r}"
            )
    value.update(
        {
            "campaign_schema_version": SCHEMA_VERSION,
            "campaign_id": campaign_id,
            "overall_campaign_id": overall_id,
            "campaign_type": campaign_type,
            "campaign_point_id": point.point_id,
            "campaign_matrix_sha256": matrix_sha256,
        }
    )
    atomic_json(manifest_path, value)
    return value


def selected_by_point(manifest: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    selected: dict[str, list[dict[str, Any]]] = {}
    for run in manifest.get("runs", []):
        if run.get("selection") == "selected":
            selected.setdefault(str(run.get("point_id")), []).append(run)
    return selected


def recompute_campaign(manifest: dict[str, Any]) -> None:
    expected = {str(item["point_id"]) for item in manifest.get("expected_points", [])}
    selected = selected_by_point(manifest)
    ambiguous = sorted(pid for pid, entries in selected.items() if len(entries) > 1)
    complete = sorted(pid for pid, entries in selected.items() if len(entries) == 1)
    missing = sorted(expected - set(complete))
    invalid_runs = sum(1 for run in manifest.get("runs", []) if run.get("selection") == "invalid")
    superseded_runs = sum(1 for run in manifest.get("runs", []) if run.get("selection") == "superseded")
    if ambiguous:
        status = "ambiguous"
    elif not missing:
        status = "complete"
    elif manifest.get("execution_finished", False):
        status = "incomplete"
    else:
        status = "running"
    manifest["status"] = status
    manifest["summary"] = {
        "expected_points": len(expected),
        "selected_points": len(complete),
        "missing_points": len(missing),
        "invalid_runs": invalid_runs,
        "superseded_runs": superseded_runs,
        "ambiguous_points": len(ambiguous),
    }
    manifest["missing_point_ids"] = missing
    manifest["ambiguous_point_ids"] = ambiguous
    manifest["updated_utc"] = utc_iso_ns()


def load_or_create_campaign(
    campaign_path: Path,
    *,
    campaign_id: str,
    overall_id: str,
    campaign_type: str,
    description: str,
    scenario: str,
    backend: str,
    mode: str,
    matrix_path: Path,
    matrix_sha256: str,
    points: list[Point],
    resume: bool,
) -> dict[str, Any]:
    if campaign_path.exists():
        if not resume:
            raise CampaignError(
                f"campaign already exists: {campaign_id}; use --resume only after reviewing its manifest"
            )
        manifest = load_json(campaign_path)
        checks = {
            "campaign_id": campaign_id,
            "overall_campaign_id": overall_id,
            "campaign_type": campaign_type,
            "scenario": scenario,
            "generator_backend": backend,
            "generator_mode": mode,
            "matrix_sha256": matrix_sha256,
        }
        for key, expected in checks.items():
            if str(manifest.get(key)) != str(expected):
                raise CampaignError(
                    f"cannot resume campaign: {key}={manifest.get(key)!r}, expected {expected!r}"
                )
        old_points = {item["point_id"] for item in manifest.get("expected_points", [])}
        new_points = {point.point_id for point in points}
        if old_points != new_points:
            raise CampaignError("cannot resume campaign with a changed expanded matrix")
        manifest["execution_finished"] = False
        manifest["status"] = "running"
        manifest["updated_utc"] = utc_iso_ns()
        return manifest

    return {
        "schema_version": SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "overall_campaign_id": overall_id,
        "campaign_type": campaign_type,
        "description": description,
        "scenario": scenario,
        "generator_backend": backend,
        "generator_mode": mode,
        "matrix_file": "campaign_matrix.toml",
        "matrix_sha256": matrix_sha256,
        "created_utc": utc_iso_ns(),
        "updated_utc": utc_iso_ns(),
        "status": "running",
        "execution_finished": False,
        "expected_points": [manifest_point(point) for point in points],
        "runs": [],
        "missing_point_ids": [point.point_id for point in points],
        "ambiguous_point_ids": [],
        "summary": {
            "expected_points": len(points),
            "selected_points": 0,
            "missing_points": len(points),
            "invalid_runs": 0,
            "superseded_runs": 0,
            "ambiguous_points": 0,
        },
    }


def register_run(
    manifest: dict[str, Any],
    *,
    point: Point,
    run_manifest: dict[str, Any],
    relative_path: str,
    validation_status: str,
    validation_errors: list[str],
    validation_warnings: list[str],
    command_returncode: int,
) -> None:
    entries = [
        run
        for run in manifest.get("runs", [])
        if str(run.get("point_id")) == point.point_id
    ]
    selected = [run for run in entries if run.get("selection") == "selected"]
    if selected:
        raise CampaignError(
            f"matrix point already has a selected run: {point.point_id}; "
            "do not create multiple valid runs for the same repetition"
        )

    for old in entries:
        if old.get("selection") == "invalid":
            old["selection"] = "superseded"
            old["superseded_utc"] = utc_iso_ns()
            old["superseded_by_run_id"] = run_manifest.get("run_id")

    selection = "selected" if validation_status == "PASS" and command_returncode == 0 else "invalid"
    manifest.setdefault("runs", []).append(
        {
            "run_id": run_manifest.get("run_id"),
            "point_id": point.point_id,
            "result_path": relative_path,
            "validation_status": validation_status,
            "validation_errors": validation_errors,
            "validation_warnings": validation_warnings,
            "command_returncode": command_returncode,
            "selection": selection,
            "recorded_utc": utc_iso_ns(),
        }
    )
    recompute_campaign(manifest)


def overall_manifest_path(overall_dir: Path) -> Path:
    return overall_dir / "overall_campaign_manifest.json"


def update_overall(
    *,
    overall_dir: Path,
    results_root: Path,
    campaign_manifest: dict[str, Any],
    expected_scenarios: list[str],
) -> dict[str, Any]:
    path = overall_manifest_path(overall_dir)
    if path.exists():
        overall = load_json(path)
        for key in ("campaign_type", "generator_backend", "generator_mode"):
            expected = campaign_manifest[key]
            if str(overall.get(key)) != str(expected):
                raise CampaignError(
                    f"overall campaign rejects mixed {key}: {overall.get(key)!r} versus {expected!r}"
                )
        old_expected = set(str(item) for item in overall.get("expected_scenarios", []))
        if old_expected != set(expected_scenarios):
            raise CampaignError("overall campaign expected-scenario set changed")
    else:
        overall = {
            "schema_version": SCHEMA_VERSION,
            "overall_campaign_id": campaign_manifest["overall_campaign_id"],
            "campaign_type": campaign_manifest["campaign_type"],
            "generator_backend": campaign_manifest["generator_backend"],
            "generator_mode": campaign_manifest["generator_mode"],
            "expected_scenarios": expected_scenarios,
            "created_utc": utc_iso_ns(),
            "campaigns": {},
        }

    scenario = str(campaign_manifest["scenario"])
    existing = overall.setdefault("campaigns", {}).get(scenario)
    if existing and existing.get("campaign_id") != campaign_manifest["campaign_id"]:
        raise CampaignError(
            f"overall campaign already has a different Scenario {scenario} campaign: "
            f"{existing.get('campaign_id')}"
        )
    campaign_path = (
        results_root
        / "_campaigns"
        / campaign_manifest["overall_campaign_id"]
        / "campaigns"
        / campaign_manifest["campaign_id"]
        / "campaign_manifest.json"
    )
    overall["campaigns"][scenario] = {
        "campaign_id": campaign_manifest["campaign_id"],
        "manifest_path": campaign_path.relative_to(results_root).as_posix(),
        "status": campaign_manifest["status"],
        "updated_utc": campaign_manifest["updated_utc"],
    }
    complete_scenarios = sorted(
        scenario_name
        for scenario_name, value in overall["campaigns"].items()
        if value.get("status") == "complete"
    )
    missing = sorted(set(expected_scenarios) - set(complete_scenarios))
    overall["complete_scenarios"] = complete_scenarios
    overall["missing_or_incomplete_scenarios"] = missing
    overall["status"] = "complete" if not missing else "incomplete"
    overall["updated_utc"] = utc_iso_ns()
    atomic_json(path, overall)
    return overall


def update_index(results_root: Path) -> dict[str, Any]:
    meta_root = results_root / "_campaigns"
    overall_items: list[dict[str, Any]] = []
    campaign_items: list[dict[str, Any]] = []
    if meta_root.exists():
        for path in sorted(meta_root.glob("*/overall_campaign_manifest.json")):
            manifest = load_json(path)
            overall_items.append(
                {
                    "overall_campaign_id": manifest.get("overall_campaign_id"),
                    "manifest_path": path.relative_to(results_root).as_posix(),
                    "status": manifest.get("status"),
                    "campaign_type": manifest.get("campaign_type"),
                    "generator_backend": manifest.get("generator_backend"),
                    "generator_mode": manifest.get("generator_mode"),
                }
            )
        for path in sorted(meta_root.glob("*/campaigns/*/campaign_manifest.json")):
            manifest = load_json(path)
            campaign_items.append(
                {
                    "campaign_id": manifest.get("campaign_id"),
                    "overall_campaign_id": manifest.get("overall_campaign_id"),
                    "scenario": manifest.get("scenario"),
                    "manifest_path": path.relative_to(results_root).as_posix(),
                    "status": manifest.get("status"),
                    "campaign_type": manifest.get("campaign_type"),
                    "generator_backend": manifest.get("generator_backend"),
                    "generator_mode": manifest.get("generator_mode"),
                }
            )
    index = {
        "schema_version": SCHEMA_VERSION,
        "updated_utc": utc_iso_ns(),
        "overall_campaigns": overall_items,
        "campaigns": campaign_items,
    }
    atomic_json(meta_root / "index.json", index)
    return index


def expected_scenarios_from_args(raw: str) -> list[str]:
    values = [item.strip().upper() for item in raw.split(",") if item.strip()]
    if not values or any(value not in SCENARIOS for value in values):
        raise CampaignError("--expected-scenarios must be a comma-separated subset of A,B,C,D,E")
    if len(values) != len(set(values)):
        raise CampaignError("--expected-scenarios contains duplicates")
    return values


def resolve_campaign_fields(args: argparse.Namespace, matrix: dict[str, Any]) -> tuple[str, str, str, str]:
    table = matrix.get("campaign")
    if table is None:
        table = {}
    if not isinstance(table, dict):
        raise CampaignError("[campaign] must be a TOML table")
    campaign_id = args.campaign_id or table.get("campaign_id")
    overall_id = args.overall_campaign_id or table.get("overall_campaign_id")
    campaign_type = args.campaign_type or table.get("campaign_type")
    description = args.description if args.description is not None else table.get("description", "")
    if not campaign_id or not overall_id or not campaign_type:
        raise CampaignError(
            "campaign_id, overall_campaign_id and campaign_type are required via CLI or [campaign]"
        )
    campaign_id = safe_id("campaign_id", str(campaign_id))
    overall_id = safe_id("overall_campaign_id", str(overall_id))
    campaign_type = str(campaign_type)
    if campaign_type not in CAMPAIGN_TYPES:
        raise CampaignError("campaign_type must be pilot or repeated")
    return campaign_id, overall_id, campaign_type, str(description)



def run_matches_point(manifest: dict[str, Any], point: Point) -> bool:
    expected = {
        "scenario": point.scenario,
        "reference_workload": point.reference_workload,
        "generator_workload": point.generator_workload,
        "generator_mode": point.generator_mode,
        "generator_backend": point.generator_backend,
        "repetition": point.repetition,
    }
    for key, wanted in expected.items():
        if str(manifest.get(key)) != str(wanted):
            return False
    try:
        return abs(float(manifest.get("generator_rate")) - point.generator_rate) <= 1e-12
    except (TypeError, ValueError):
        return False


def recover_pending_run(
    *,
    pending_path: Path,
    results_root: Path,
    manifest: dict[str, Any],
    campaign_path: Path,
    campaign_id: str,
    overall_id: str,
    campaign_type: str,
    matrix_sha: str,
    points_by_id: dict[str, Point],
) -> None:
    if not pending_path.exists():
        return
    pending = load_json(pending_path)
    point_id = str(pending.get("point_id", ""))
    point = points_by_id.get(point_id)
    if point is None:
        raise CampaignError(f"pending point is not present in the current matrix: {point_id}")
    before = {
        (results_root / str(item)).resolve()
        for item in pending.get("before_manifests", [])
    }
    candidates: list[Path] = []
    for path in sorted(snapshot_runs(results_root) - before):
        raw = load_json(path)
        if raw.get("campaign_id") not in (None, ""):
            continue
        if run_matches_point(raw, point):
            candidates.append(path)
    if len(candidates) > 1:
        raise CampaignError(
            f"pending point {point_id} has {len(candidates)} unclaimed raw runs; manual review is required"
        )
    if not candidates:
        manifest.setdefault("execution_errors", []).append(
            {
                "point_id": point_id,
                "error": "pending command ended without an identifiable raw run",
                "recorded_utc": utc_iso_ns(),
            }
        )
        pending_path.unlink()
        recompute_campaign(manifest)
        atomic_json(campaign_path, manifest)
        return

    raw_manifest_path = candidates[0]
    raw_manifest = annotate_run(
        raw_manifest_path,
        campaign_id=campaign_id,
        overall_id=overall_id,
        campaign_type=campaign_type,
        point=point,
        matrix_sha256=matrix_sha,
    )
    run_dir = raw_manifest_path.parent
    status, errors, warnings = read_validation(run_dir)
    register_run(
        manifest,
        point=point,
        run_manifest=raw_manifest,
        relative_path=relative_result_dir(results_root, raw_manifest_path),
        validation_status=status,
        validation_errors=errors,
        validation_warnings=warnings,
        command_returncode=0 if status == "PASS" else 1,
    )
    pending_path.unlink()
    recompute_campaign(manifest)
    atomic_json(campaign_path, manifest)


def run_campaign(args: argparse.Namespace) -> int:
    config_path = args.config.resolve()
    matrix_path = args.matrix.resolve()
    orchestrate = args.orchestrate.resolve()
    if not orchestrate.is_file():
        raise CampaignError(f"orchestrator not found: {orchestrate}")
    config = load_toml(config_path)
    matrix = load_toml(matrix_path)
    campaign_id, overall_id, campaign_type, description = resolve_campaign_fields(args, matrix)
    points = expand_points(matrix, config)
    scenario, backend, mode = validate_homogeneous(points)
    expected_scenarios = expected_scenarios_from_args(args.expected_scenarios)
    if scenario not in expected_scenarios:
        raise CampaignError(
            f"Scenario {scenario} is not listed in --expected-scenarios={args.expected_scenarios}"
        )

    results_root = results_root_from_config(config_path, config)
    results_root.mkdir(parents=True, exist_ok=True)
    _, overall_dir, campaign_dir = campaign_paths(results_root, overall_id, campaign_id)
    campaign_dir.mkdir(parents=True, exist_ok=True)
    matrix_sha = sha256_file(matrix_path)
    matrix_copy = campaign_dir / "campaign_matrix.toml"
    if matrix_copy.exists() and sha256_file(matrix_copy) != matrix_sha:
        raise CampaignError(f"stored campaign matrix differs: {matrix_copy}")
    if not matrix_copy.exists():
        shutil.copy2(matrix_path, matrix_copy)

    campaign_path = campaign_dir / "campaign_manifest.json"
    manifest = load_or_create_campaign(
        campaign_path,
        campaign_id=campaign_id,
        overall_id=overall_id,
        campaign_type=campaign_type,
        description=description,
        scenario=scenario,
        backend=backend,
        mode=mode,
        matrix_path=matrix_path,
        matrix_sha256=matrix_sha,
        points=points,
        resume=args.resume,
    )
    atomic_json(campaign_path, manifest)
    pending_path = campaign_dir / "pending_run.json"
    recover_pending_run(
        pending_path=pending_path,
        results_root=results_root,
        manifest=manifest,
        campaign_path=campaign_path,
        campaign_id=campaign_id,
        overall_id=overall_id,
        campaign_type=campaign_type,
        matrix_sha=matrix_sha,
        points_by_id={point.point_id: point for point in points},
    )
    update_overall(
        overall_dir=overall_dir,
        results_root=results_root,
        campaign_manifest=manifest,
        expected_scenarios=expected_scenarios,
    )
    update_index(results_root)

    failures = 0
    try:
        for point in points:
            already = [
                run
                for run in manifest.get("runs", [])
                if run.get("point_id") == point.point_id and run.get("selection") == "selected"
            ]
            if already:
                if args.resume:
                    print(f"SKIP selected point {point.point_id}")
                    continue
                raise CampaignError(f"point already selected: {point.point_id}")

            before = snapshot_runs(results_root)
            atomic_json(
                pending_path,
                {
                    "schema_version": SCHEMA_VERSION,
                    "point_id": point.point_id,
                    "started_utc": utc_iso_ns(),
                    "before_manifests": [
                        path.relative_to(results_root.resolve()).as_posix()
                        for path in sorted(before)
                    ],
                },
            )
            command = point_command(
                orchestrate=orchestrate,
                config_path=config_path,
                point=point,
                confirm_flood=args.confirm_flood,
            )
            print(f"RUN  {point.point_id}")
            completed = subprocess.run(command, check=False)
            after = snapshot_runs(results_root)
            created = sorted(after - before)
            if len(created) != 1:
                manifest.setdefault("execution_errors", []).append(
                    {
                        "point_id": point.point_id,
                        "error": f"expected one new raw run, found {len(created)}",
                        "recorded_utc": utc_iso_ns(),
                        "command_returncode": completed.returncode,
                    }
                )
                failures += 1
                pending_path.unlink(missing_ok=True)
                recompute_campaign(manifest)
                atomic_json(campaign_path, manifest)
                if not args.continue_on_failure:
                    break
                continue

            raw_manifest_path = created[0]
            raw_manifest = annotate_run(
                raw_manifest_path,
                campaign_id=campaign_id,
                overall_id=overall_id,
                campaign_type=campaign_type,
                point=point,
                matrix_sha256=matrix_sha,
            )
            run_dir = raw_manifest_path.parent
            validation_status, validation_errors, validation_warnings = read_validation(run_dir)
            register_run(
                manifest,
                point=point,
                run_manifest=raw_manifest,
                relative_path=relative_result_dir(results_root, raw_manifest_path),
                validation_status=validation_status,
                validation_errors=validation_errors,
                validation_warnings=validation_warnings,
                command_returncode=completed.returncode,
            )
            pending_path.unlink(missing_ok=True)
            atomic_json(campaign_path, manifest)
            update_overall(
                overall_dir=overall_dir,
                results_root=results_root,
                campaign_manifest=manifest,
                expected_scenarios=expected_scenarios,
            )
            update_index(results_root)

            if completed.returncode != 0 or validation_status != "PASS":
                failures += 1
                if not args.continue_on_failure:
                    break
    finally:
        manifest["execution_finished"] = True
        manifest["finished_utc"] = utc_iso_ns()
        recompute_campaign(manifest)
        atomic_json(campaign_path, manifest)
        update_overall(
            overall_dir=overall_dir,
            results_root=results_root,
            campaign_manifest=manifest,
            expected_scenarios=expected_scenarios,
        )
        update_index(results_root)

    print(f"Campaign ID: {campaign_id}")
    print(f"Overall campaign ID: {overall_id}")
    print(f"Campaign manifest: {campaign_path}")
    print(f"Campaign status: {manifest['status']}")
    return 0 if manifest["status"] == "complete" and failures == 0 else 1


def find_campaign_manifest(results_root: Path, campaign_id: str) -> Path:
    matches = list(results_root.glob(f"_campaigns/*/campaigns/{campaign_id}/campaign_manifest.json"))
    if len(matches) != 1:
        raise CampaignError(
            f"expected exactly one campaign_id={campaign_id!r}, found {len(matches)}"
        )
    return matches[0]


def find_overall_manifest(results_root: Path, overall_id: str) -> Path:
    path = results_root / "_campaigns" / overall_id / "overall_campaign_manifest.json"
    if not path.is_file():
        raise CampaignError(f"overall campaign not found: {overall_id}")
    return path


def verify_campaign(results_root: Path, manifest_path: Path) -> list[str]:
    errors: list[str] = []
    manifest = load_json(manifest_path)
    expected = {str(item.get("point_id")) for item in manifest.get("expected_points", [])}
    selected = selected_by_point(manifest)
    for point_id, entries in selected.items():
        if len(entries) != 1:
            errors.append(f"point {point_id} has {len(entries)} selected runs")
        for entry in entries:
            path = results_root / str(entry.get("result_path", ""))
            raw_manifest = path / "run_manifest.json"
            validation = path / "validation.json"
            if not path.is_dir():
                errors.append(f"selected run directory missing: {path}")
                continue
            if not raw_manifest.is_file():
                errors.append(f"run manifest missing: {raw_manifest}")
                continue
            raw = load_json(raw_manifest)
            for key in ("campaign_id", "overall_campaign_id", "campaign_point_id"):
                expected_value = {
                    "campaign_id": manifest.get("campaign_id"),
                    "overall_campaign_id": manifest.get("overall_campaign_id"),
                    "campaign_point_id": point_id,
                }[key]
                if str(raw.get(key)) != str(expected_value):
                    errors.append(f"{raw_manifest}: {key} mismatch")
            if not validation.is_file() or load_json(validation).get("status") != "PASS":
                errors.append(f"selected run is not PASS: {path}")
    missing = expected - set(selected)
    if missing:
        errors.append(f"missing selected points: {len(missing)}")
    return errors


def command_verify(args: argparse.Namespace) -> int:
    results_root = args.results_root.resolve()
    if bool(args.campaign_id) == bool(args.overall_campaign_id):
        raise CampaignError("select exactly one of --campaign-id or --overall-campaign-id")
    errors: list[str] = []
    if args.campaign_id:
        path = find_campaign_manifest(results_root, safe_id("campaign_id", args.campaign_id))
        errors.extend(verify_campaign(results_root, path))
    else:
        path = find_overall_manifest(
            results_root, safe_id("overall_campaign_id", args.overall_campaign_id)
        )
        overall = load_json(path)
        seen_backend = {overall.get("generator_backend")}
        seen_mode = {overall.get("generator_mode")}
        if len(seen_backend) != 1 or len(seen_mode) != 1:
            errors.append("overall campaign has mixed backend or generator mode")
        for value in overall.get("campaigns", {}).values():
            campaign_path = results_root / str(value.get("manifest_path", ""))
            if not campaign_path.is_file():
                errors.append(f"campaign manifest missing: {campaign_path}")
                continue
            errors.extend(verify_campaign(results_root, campaign_path))
        if overall.get("status") != "complete":
            errors.append(f"overall campaign status is {overall.get('status')}, not complete")
    if errors:
        print("Campaign verification: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("Campaign verification: PASS")
    return 0


def command_list(args: argparse.Namespace) -> int:
    index_path = args.results_root.resolve() / "_campaigns" / "index.json"
    if not index_path.is_file():
        raise CampaignError(f"campaign index not found: {index_path}")
    index = load_json(index_path)
    print("Overall campaigns:")
    for item in index.get("overall_campaigns", []):
        print(
            f"  {item.get('overall_campaign_id')} status={item.get('status')} "
            f"type={item.get('campaign_type')} backend={item.get('generator_backend')} "
            f"mode={item.get('generator_mode')}"
        )
    print("Campaigns:")
    for item in index.get("campaigns", []):
        print(
            f"  {item.get('campaign_id')} overall={item.get('overall_campaign_id')} "
            f"scenario={item.get('scenario')} status={item.get('status')}"
        )
    return 0


def parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parent
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="execute and automatically manifest one scenario campaign")
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--matrix", type=Path, required=True)
    run.add_argument("--orchestrate", type=Path, default=root / "orchestrate.py")
    run.add_argument("--campaign-id")
    run.add_argument("--overall-campaign-id")
    run.add_argument("--campaign-type", choices=sorted(CAMPAIGN_TYPES))
    run.add_argument("--description")
    run.add_argument("--expected-scenarios", default="A,B,C,D,E")
    run.add_argument("--continue-on-failure", action="store_true")
    run.add_argument("--confirm-flood", action="store_true")
    run.add_argument("--resume", action="store_true")

    verify = sub.add_parser("verify", help="verify a copied campaign or overall campaign")
    verify.add_argument("--results-root", type=Path, required=True)
    verify.add_argument("--campaign-id")
    verify.add_argument("--overall-campaign-id")

    listing = sub.add_parser("list", help="list evaluator-selectable campaign identities")
    listing.add_argument("--results-root", type=Path, required=True)
    return p


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "run":
            return run_campaign(args)
        if args.command == "verify":
            return command_verify(args)
        if args.command == "list":
            return command_list(args)
        raise AssertionError(args.command)
    except CampaignError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
