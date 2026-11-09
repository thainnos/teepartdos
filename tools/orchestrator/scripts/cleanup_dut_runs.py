#!/usr/bin/env python3
"""Safely delete DUT-side run directories only after verified local transfer.

Run this on the reference/orchestrator host from a TEE_TLS_DoS checkout.
It never deletes local results. Remote deletion is delegated to the restricted
DUT agent's ``delete-run`` command.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import orchestrate  # type: ignore  # repository-local module


class HousekeepingError(RuntimeError):
    pass


@dataclass
class Candidate:
    result_dir: Path
    run_id: str
    files: int
    payload_bytes: int
    transfer: dict[str, Any]


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HousekeepingError(f"cannot read valid JSON {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise HousekeepingError(f"JSON object expected: {path}")
    return data


def local_tree_stats(path: Path) -> tuple[int, int]:
    if not path.is_dir() or path.is_symlink():
        raise HousekeepingError(f"local DUT result directory missing or unsafe: {path}")
    files = 0
    total = 0
    for entry in path.rglob("*"):
        if entry.is_symlink():
            raise HousekeepingError(f"local DUT result contains symlink: {entry}")
        if entry.is_file():
            st = entry.stat()
            files += 1
            total += st.st_size
    return files, total


def verify_candidate(transfer_path: Path) -> Candidate:
    result_dir = transfer_path.parent
    transfer = load_json(transfer_path)
    run_id = str(transfer.get("run_id", ""))
    if not run_id or result_dir.name != run_id:
        raise HousekeepingError(
            f"run ID/path mismatch for {transfer_path}: metadata={run_id!r}, directory={result_dir.name!r}"
        )
    if transfer.get("host") != "dut":
        raise HousekeepingError(f"transfer metadata is not for DUT: {transfer_path}")
    if transfer.get("method") != "agent-tar-stream-over-ssh":
        raise HousekeepingError(
            f"unexpected DUT transfer method {transfer.get('method')!r}: {transfer_path}"
        )
    expected_files = transfer.get("files")
    expected_bytes = transfer.get("payload_bytes")
    if isinstance(expected_files, bool) or not isinstance(expected_files, int) or expected_files < 0:
        raise HousekeepingError(f"invalid files count in {transfer_path}")
    if isinstance(expected_bytes, bool) or not isinstance(expected_bytes, int) or expected_bytes < 0:
        raise HousekeepingError(f"invalid payload_bytes in {transfer_path}")

    # Where available, independently cross-check the authoritative run identity.
    for manifest_name in ("run_manifest.json", "iperf_manifest.json"):
        mp = result_dir / manifest_name
        if mp.is_file():
            manifest = load_json(mp)
            if str(manifest.get("run_id", "")) != run_id:
                raise HousekeepingError(
                    f"{manifest_name} run ID does not match transfer metadata for {result_dir}"
                )

    files, payload_bytes = local_tree_stats(result_dir / "dut")
    if files != expected_files:
        raise HousekeepingError(
            f"local DUT file count mismatch for {run_id}: local={files}, transfer={expected_files}"
        )
    if payload_bytes != expected_bytes:
        raise HousekeepingError(
            f"local DUT payload size mismatch for {run_id}: local={payload_bytes}, transfer={expected_bytes}"
        )
    return Candidate(result_dir, run_id, files, payload_bytes, transfer)


def parse_kv(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def atomic_json(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def discover(results_root: Path, selected_ids: set[str]) -> tuple[list[Candidate], list[str]]:
    candidates: list[Candidate] = []
    errors: list[str] = []
    for tp in sorted(results_root.rglob("dut_transfer.json")):
        try:
            cand = verify_candidate(tp)
            if selected_ids and cand.run_id not in selected_ids:
                continue
            cleanup_file = cand.result_dir / "dut_cleanup.json"
            if cleanup_file.is_file():
                cleanup = load_json(cleanup_file)
                if cleanup.get("state") in {"deleted", "already_missing"}:
                    continue
            candidates.append(cand)
        except HousekeepingError as exc:
            errors.append(str(exc))
    return candidates, errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", type=Path, required=True, help="central campaign TOML")
    ap.add_argument("--results-root", type=Path, default=None,
                    help="override repository.results_root from config")
    ap.add_argument("--run-id", action="append", default=[],
                    help="limit cleanup to one or more run IDs")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="verify and list only")
    mode.add_argument("--apply", action="store_true", help="delete verified remote DUT runs")
    args = ap.parse_args()

    cfg = orchestrate.load_config(args.config.expanduser().resolve())
    errors = orchestrate.validate_config(cfg)
    if errors:
        raise HousekeepingError("configuration invalid:\n- " + "\n- ".join(errors))
    results_root = (args.results_root.expanduser().resolve() if args.results_root
                    else cfg.local_path("repository.results_root"))
    if not results_root.is_dir():
        raise HousekeepingError(f"results root does not exist: {results_root}")

    candidates, discovery_errors = discover(results_root, set(args.run_id))
    for err in discovery_errors:
        print(f"SKIP-UNSAFE: {err}", file=sys.stderr)

    total = sum(c.payload_bytes for c in candidates)
    print(f"Verified cleanup candidates: {len(candidates)}")
    print(f"Verified local DUT payload: {total} bytes ({total / (1024**2):.1f} MiB)")
    for cand in candidates:
        print(f"  {cand.run_id}: {cand.files} files, {cand.payload_bytes / (1024**2):.1f} MiB")

    if args.dry_run:
        print("DRY RUN: no remote data deleted.")
        return 1 if discovery_errors else 0

    failures = 0
    for cand in candidates:
        try:
            cp = orchestrate.remote_agent(
                cfg, "dut", ["delete-run", cand.run_id], check=False, timeout=30
            )
            kv = parse_kv(cp.stdout)
            state = kv.get("STATE", "")
            if cp.returncode != 0 or state not in {"deleted", "missing"}:
                raise HousekeepingError(
                    f"DUT delete-run failed for {cand.run_id}: rc={cp.returncode} "
                    f"stdout={cp.stdout.strip()!r} stderr={cp.stderr.strip()!r}"
                )
            cleanup_state = "deleted" if state == "deleted" else "already_missing"
            atomic_json(
                cand.result_dir / "dut_cleanup.json",
                {
                    "state": cleanup_state,
                    "run_id": cand.run_id,
                    "verified_local_files": cand.files,
                    "verified_local_payload_bytes": cand.payload_bytes,
                    "transfer_archive_sha256": cand.transfer.get("archive_sha256"),
                    "deleted_utc": orchestrate.utc_iso_ns(),
                    "agent_stdout": cp.stdout,
                },
            )
            print(f"CLEANED: {cand.run_id} ({cleanup_state})")
        except Exception as exc:
            failures += 1
            print(f"CLEANUP-FAIL: {cand.run_id}: {exc}", file=sys.stderr)

    if discovery_errors:
        failures += len(discovery_errors)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HousekeepingError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
