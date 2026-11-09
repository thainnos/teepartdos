#!/usr/bin/env python3
"""Run one time-bounded external tool and emit generator-compatible artifacts.

The runner intentionally does not construct network traffic or interpret
protocol-specific command-line arguments. The command is supplied verbatim in a
private TOML file by the experiment operator. The runner only provides process
lifecycle control, exact phase timestamps, interface-counter observations, and
artifacts compatible with the existing TEE/TLS orchestration/evaluation path.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import time
import tomllib
from typing import Any

TLSGEN_VERSION = "0.1.5"
EXTERNAL_RUNNER_VERSION = "0.1.0"
SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SCENARIOS = set("ABCDE")
STOP_REQUESTED = False
STOP_SIGNAL: int | None = None


def utc_ns() -> int:
    return time.time_ns()


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(value, fh, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def repo_git_commit(root: Path) -> str:
    try:
        cp = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"], cwd=root,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=True,
        )
        value = cp.stdout.strip()
        if re.fullmatch(r"[0-9a-f]{12}", value):
            dirty = subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=no"], cwd=root,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                check=False,
            ).stdout.strip()
            return value + ("-dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        pass
    return "unknown"


def load_flat_config(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def cfg_int(cfg: dict[str, str], key: str) -> int:
    try:
        return int(cfg[key])
    except (KeyError, ValueError) as exc:
        raise SystemExit(f"ERROR: generator config {key} is missing or invalid") from exc


def cfg_bool(cfg: dict[str, str], key: str) -> bool:
    value = cfg.get(key, "").lower()
    if value not in {"true", "false"}:
        raise SystemExit(f"ERROR: generator config {key} is missing or invalid")
    return value == "true"


def read_external_config(path: Path) -> dict[str, Any]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SystemExit(f"ERROR: unable to read external tool config: {exc}") from exc
    section = data.get("external")
    if not isinstance(section, dict):
        raise SystemExit("ERROR: external tool config requires [external]")
    command = section.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(x, str) and x for x in command):
        raise SystemExit("ERROR: external.command must be a non-empty array of strings")
    label = section.get("label", "tcp-syn")
    if not isinstance(label, str) or not SAFE_ID.fullmatch(label):
        raise SystemExit("ERROR: external.label must match [A-Za-z0-9._-]{1,128}")
    interface = section.get("interface")
    if not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", interface):
        raise SystemExit("ERROR: external.interface is missing or invalid")
    stop_signal = section.get("stop_signal", "SIGINT")
    if stop_signal not in {"SIGINT", "SIGTERM"}:
        raise SystemExit("ERROR: external.stop_signal must be SIGINT or SIGTERM")
    stop_grace_s = section.get("stop_grace_s", 5.0)
    if not isinstance(stop_grace_s, (int, float)) or not (0.1 <= float(stop_grace_s) <= 30.0):
        raise SystemExit("ERROR: external.stop_grace_s must be between 0.1 and 30 seconds")
    require_tx_packets = section.get("require_tx_packets", True)
    if not isinstance(require_tx_packets, bool):
        raise SystemExit("ERROR: external.require_tx_packets must be boolean")
    cwd = section.get("cwd")
    if cwd is not None and (not isinstance(cwd, str) or not cwd):
        raise SystemExit("ERROR: external.cwd must be a non-empty string when set")
    return {
        "label": label,
        "command": command,
        "interface": interface,
        "stop_signal": stop_signal,
        "stop_grace_s": float(stop_grace_s),
        "require_tx_packets": require_tx_packets,
        "cwd": cwd,
    }


def validate_args(a: argparse.Namespace) -> None:
    if not SAFE_ID.fullmatch(a.run_id):
        raise SystemExit("ERROR: invalid --run-id")
    if a.scenario not in SCENARIOS:
        raise SystemExit("ERROR: invalid --scenario")
    if a.duration <= 0:
        raise SystemExit("ERROR: --duration must be positive")
    if a.rate != 0.0:
        raise SystemExit("ERROR: external tool workload uses --rate 0 as the tool-controlled-rate sentinel")
    if a.max_inflight <= 0 or a.record_connections <= 0:
        raise SystemExit("ERROR: --max-inflight and --record-connections must remain positive run-identity values")
    if not a.generator_config.is_file():
        raise SystemExit("ERROR: --generator-config is missing")
    if not a.config.is_file():
        raise SystemExit("ERROR: --config is missing")
    if a.output_dir.exists() and not a.output_dir.is_dir():
        raise SystemExit("ERROR: --output-dir exists but is not a directory")


def read_counter(sysfs_root: Path, interface: str, name: str) -> int:
    path = sysfs_root / interface / "statistics" / name
    return int(path.read_text(encoding="ascii").strip())


def interface_counters(sysfs_root: Path, interface: str) -> dict[str, int]:
    names = ("tx_packets", "tx_bytes", "rx_packets", "rx_bytes", "tx_dropped", "rx_dropped")
    return {name: read_counter(sysfs_root, interface, name) for name in names}


def delta(after: dict[str, int], before: dict[str, int], name: str) -> int:
    av, bv = after.get(name, 0), before.get(name, 0)
    return av - bv if av >= bv else 0


def on_signal(signo: int, _frame: Any) -> None:
    global STOP_REQUESTED, STOP_SIGNAL
    STOP_REQUESTED = True
    STOP_SIGNAL = signo


def stop_child(proc: subprocess.Popen[str], stop_signal: int, grace_s: float) -> tuple[int, bool]:
    forced = False
    if proc.poll() is not None:
        return int(proc.returncode or 0), forced
    try:
        os.killpg(proc.pid, stop_signal)
    except ProcessLookupError:
        return int(proc.poll() or 0), forced
    try:
        return int(proc.wait(timeout=grace_s)), forced
    except subprocess.TimeoutExpired:
        pass
    forced = True
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return int(proc.poll() or 0), forced
    try:
        return int(proc.wait(timeout=2.0)), forced
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return int(proc.wait(timeout=2.0)), True


def write_stats(
    path: Path, *, run_id: str, scenario: str, wall_ns: int, elapsed_s: float,
    iface_delta: dict[str, int], process_completed: bool, tool_exit_code: int,
) -> None:
    pps = iface_delta["tx_packets"] / elapsed_s if elapsed_s > 0 else 0.0
    mbps = iface_delta["tx_bytes"] * 8.0 / elapsed_s / 1_000_000.0 if elapsed_s > 0 else 0.0
    fields = [
        "run_id", "scenario", "workload", "mode", "backend", "wall_time_utc_ns", "elapsed_s", "phase",
        "offered_total", "attempted_total", "completed_total", "offered_rate", "attempted_rate", "completed_rate",
        "local_capacity_drop_total", "pending_release_current", "pending_release_max", "release_lag_max_us",
        "session_unavailable_total", "tcp_established_total", "full_handshake_ok_total", "resumed_handshake_ok_total",
        "handshake_fail_total", "profile_fail_total", "app_ok_total", "app_fail_total", "payload_fail_total",
        "timeout_fail_total", "reconnect_attempted_total", "reconnect_ok_total", "bytes_tx_total", "bytes_rx_total",
        "active_connections", "session_pool_size", "external_process_completed", "external_tool_exit_code",
        "external_interface_tx_packets_delta", "external_interface_tx_bytes_delta", "external_interface_rx_packets_delta",
        "external_interface_rx_bytes_delta", "external_interface_tx_dropped_delta", "external_interface_rx_dropped_delta",
        "external_observed_tx_pps", "external_observed_tx_mbps",
    ]
    row: dict[str, Any] = {name: 0 for name in fields}
    row.update({
        "run_id": run_id,
        "scenario": scenario,
        "workload": "tcp-syn",
        "mode": "flood",
        "backend": "posix",
        "wall_time_utc_ns": wall_ns,
        "elapsed_s": f"{elapsed_s:.9f}",
        "phase": "done" if process_completed else "failed",
        "bytes_tx_total": iface_delta["tx_bytes"],
        "bytes_rx_total": iface_delta["rx_bytes"],
        "external_process_completed": 1 if process_completed else 0,
        "external_tool_exit_code": tool_exit_code,
        "external_interface_tx_packets_delta": iface_delta["tx_packets"],
        "external_interface_tx_bytes_delta": iface_delta["tx_bytes"],
        "external_interface_rx_packets_delta": iface_delta["rx_packets"],
        "external_interface_rx_bytes_delta": iface_delta["rx_bytes"],
        "external_interface_tx_dropped_delta": iface_delta["tx_dropped"],
        "external_interface_rx_dropped_delta": iface_delta["rx_dropped"],
        "external_observed_tx_pps": f"{pps:.6f}",
        "external_observed_tx_mbps": f"{mbps:.6f}",
    })
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerow(row)
        fh.flush()
        os.fsync(fh.fileno())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--duration", required=True, type=int)
    ap.add_argument("--rate", required=True, type=float)
    ap.add_argument("--max-inflight", required=True, type=int)
    ap.add_argument("--record-connections", required=True, type=int)
    ap.add_argument("--generator-config", required=True, type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--sysfs-root", type=Path, default=Path("/sys/class/net"), help=argparse.SUPPRESS)
    args = ap.parse_args()
    validate_args(args)
    external = read_external_config(args.config)
    generator_cfg = load_flat_config(args.generator_config)

    executable = external["command"][0]
    if "/" in executable:
        exe_path = Path(executable)
        if not exe_path.is_file() or not os.access(exe_path, os.X_OK):
            print(f"ERROR: external tool is not executable: {executable}", file=sys.stderr)
            return 2
    else:
        from shutil import which
        resolved = which(executable)
        if resolved is None:
            print(f"ERROR: external tool is not in PATH: {executable}", file=sys.stderr)
            return 2

    iface_dir = args.sysfs_root / external["interface"]
    if not iface_dir.is_dir():
        print(f"ERROR: interface statistics are unavailable: {iface_dir}", file=sys.stderr)
        return 2

    repo_root = Path(__file__).resolve().parents[1]
    git_commit = repo_git_commit(repo_root)
    run_dir = args.output_dir / f"tls_loadgen_{args.scenario}_tcp-syn_flood_{args.run_id}"
    run_dir.mkdir(parents=True, exist_ok=False)
    metadata_path = run_dir / "generator.metadata.json"
    timeline_path = run_dir / "generator.timeline.json"
    stats_path = run_dir / "generator_stats.csv"
    stdout_path = run_dir / "external_tool.stdout.log"
    stderr_path = run_dir / "external_tool.stderr.log"
    command_path = run_dir / "external_tool.command.txt"
    exit_path = run_dir / "external_tool.exit_code"

    command_text = shlex.join(external["command"])
    command_path.write_text(command_text + "\n", encoding="utf-8")
    command_sha256 = hashlib.sha256(command_text.encode("utf-8")).hexdigest()
    before = interface_counters(args.sysfs_root, external["interface"])
    process_started_utc_ns = utc_ns()

    metadata = {
        "run_id": args.run_id,
        "scenario": args.scenario,
        "workload": "tcp-syn",
        "mode": "flood",
        "backend": "posix",
        "generator_version": TLSGEN_VERSION,
        "generator_git_commit": git_commit,
        "generator_kind": "external-tool",
        "external_runner_version": EXTERNAL_RUNNER_VERSION,
        "external_label": external["label"],
        "external_command_sha256": command_sha256,
        "timeline_schema_version": 1,
        "timeline_file": "generator.timeline.json",
        "stats_wall_time_utc_ns": True,
        "configured_rate_per_s": args.rate,
        "rate_semantics": "tool-controlled-observed-interface-rate",
        "configured_duration_s": args.duration,
        "configured_max_inflight": args.max_inflight,
        "payload_size": cfg_int(generator_cfg, "payload.size"),
        "record_connections": args.record_connections,
        "record_max_pending_releases": cfg_int(generator_cfg, "record.max_pending_releases"),
        "resumption_policy": generator_cfg.get("resumption.session_policy", ""),
        "resumption_pool_size": cfg_int(generator_cfg, "resumption.pool_size"),
        "expected_tls_version": "TLSv1.3",
        "expected_ciphersuite": generator_cfg.get("tls.ciphersuite", ""),
        "expected_group": generator_cfg.get("tls.group", ""),
        "expected_signature_algorithm": generator_cfg.get("tls.signature_algorithm", ""),
        "certificate_verification_enabled": cfg_bool(generator_cfg, "tls.verify_peer"),
        "tls_profile_applicable_to_external_workload": False,
        "network_details_omitted": True,
    }
    atomic_json(metadata_path, metadata)

    for signo in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signo, on_signal)

    phase_start_utc_ns = utc_ns()
    phase_start_mono_ns = time.monotonic_ns()
    deadline_mono_ns = phase_start_mono_ns + args.duration * 1_000_000_000
    deadline_utc_ns = phase_start_utc_ns + args.duration * 1_000_000_000
    normal_deadline = False
    forced = False
    rc = 127
    try:
        with stdout_path.open("w", encoding="utf-8") as out, stderr_path.open("w", encoding="utf-8") as err:
            proc = subprocess.Popen(
                external["command"],
                cwd=external["cwd"],
                stdout=out,
                stderr=err,
                text=True,
                start_new_session=True,
            )
            while not STOP_REQUESTED and time.monotonic_ns() < deadline_mono_ns:
                if proc.poll() is not None:
                    break
                remaining = max(0.0, (deadline_mono_ns - time.monotonic_ns()) / 1e9)
                time.sleep(min(0.1, remaining))
            normal_deadline = not STOP_REQUESTED and time.monotonic_ns() >= deadline_mono_ns and proc.poll() is None
            stop_sig = getattr(signal, external["stop_signal"])
            rc, forced = stop_child(proc, stop_sig, external["stop_grace_s"])
    except OSError as exc:
        print(f"ERROR: failed to execute external tool: {exc}", file=sys.stderr)
        return 3

    phase_end_observed_utc_ns = utc_ns()
    after = interface_counters(args.sysfs_root, external["interface"])
    iface_delta = {name: delta(after, before, name) for name in before}
    elapsed_s = max(1e-9, (phase_end_observed_utc_ns - phase_start_utc_ns) / 1e9)
    process_finished_utc_ns = utc_ns()
    reason = "duration-complete" if normal_deadline else (f"signal-{STOP_SIGNAL}" if STOP_REQUESTED else "tool-exited")

    timeline = {
        "schema_version": 1,
        "run_id": args.run_id,
        "scenario": args.scenario,
        "workload": "tcp-syn",
        "mode": "flood",
        "backend": "posix",
        "generator_version": TLSGEN_VERSION,
        "generator_git_commit": git_commit,
        "external_runner_version": EXTERNAL_RUNNER_VERSION,
        "clock_realtime": "CLOCK_REALTIME",
        "scheduling_clock": "CLOCK_MONOTONIC",
        "process_started_utc_ns": process_started_utc_ns,
        "phase_run_started_utc_ns": phase_start_utc_ns,
        "phase_run_end_deadline_utc_ns": deadline_utc_ns,
        "phase_run_end_observed_utc_ns": phase_end_observed_utc_ns,
        "drain_finished_utc_ns": phase_end_observed_utc_ns,
        "process_finished_utc_ns": process_finished_utc_ns,
        "configured_duration_s": args.duration,
        "run_end_reason": reason,
        "current_phase": "done" if normal_deadline else "failed",
        "terminal": True,
        "external_tool_exit_code": rc,
        "external_tool_stop_forced": forced,
    }
    atomic_json(timeline_path, timeline)
    write_stats(
        stats_path,
        run_id=args.run_id,
        scenario=args.scenario,
        wall_ns=process_finished_utc_ns,
        elapsed_s=elapsed_s,
        iface_delta=iface_delta,
        process_completed=normal_deadline,
        tool_exit_code=rc,
    )
    exit_path.write_text(f"{rc}\n", encoding="ascii")

    print(
        f"external_tool_end label={external['label']} interface_tx_packets={iface_delta['tx_packets']} "
        f"elapsed_s={elapsed_s:.6f} reason={reason} tool_exit={rc} forced={str(forced).lower()}"
    )
    if STOP_REQUESTED:
        return 128 + int(STOP_SIGNAL or signal.SIGTERM)
    if not normal_deadline:
        print("ERROR: external tool exited before the configured run duration", file=sys.stderr)
        return 4
    if external["require_tx_packets"] and iface_delta["tx_packets"] <= 0:
        print("ERROR: no transmitted packets were observed on the configured interface", file=sys.stderr)
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
