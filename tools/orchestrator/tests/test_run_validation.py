#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("orchestrate_validation", root / "orchestrate.py")
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    (td / "reference").mkdir()
    (td / "generator" / "output" / "tls_loadgen_A_full-handshake_benign_run1").mkdir(parents=True)
    (td / "dut").mkdir()

    cfg = module.CampaignConfig(td / "campaign.toml", {
        "experiment": {
            "reference_probe_interval_ms": 1000,
            "payload_size": 1024,
            "tls_ciphersuite": "TLS_AES_128_GCM_SHA256",
            "tls_group": "P-256",
            "tls_signature_algorithm": "ecdsa_secp256r1_sha256",
        }
    })
    args = argparse.Namespace(
        scenario="A",
        profile="pilot-debug",
        reference_workload="full-handshake",
        reference_duration=10,
        generator_workload="full-handshake",
        generator_mode="benign",
        generator_backend="posix",
        generator_duration=3,
        generator_rate=1.0,
        generator_max_inflight=64,
        generator_connections=8,
        repetition=1,
    )
    rid = "run1"
    ref_meta = {
        "run_id": rid,
        "scenario": "A",
        "workload": "full-handshake",
        "repetition": 1,
        "configured_duration_s": 10,
        "configured_probe_interval_ms": 1000,
        "payload_size": 1024,
        "expected_tls_version": "TLSv1.3",
        "expected_ciphersuite": "TLS_AES_128_GCM_SHA256",
        "expected_group": "P-256",
        "expected_signature_algorithm": "ecdsa_secp256r1_sha256",
        "certificate_verification_enabled": True,
    }
    (td / "reference" / "run.metadata.json").write_text(
        json.dumps(ref_meta), encoding="utf-8"
    )
    fieldnames = [
        "run_id", "scenario", "workload", "repetition", "scheduled_elapsed_us",
        "result_code", "session_reused", "payload_match", "tls_version", "cipher", "group",
    ]
    with (td / "reference" / "run.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow({
            "run_id": rid,
            "scenario": "A",
            "workload": "full-handshake",
            "repetition": "1",
            "scheduled_elapsed_us": "9000000",
            "result_code": "0",
            "session_reused": "false",
            "payload_match": "true",
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_128_GCM_SHA256",
            "group": "secp256r1",
        })

    gen_dir = td / "generator" / "output" / "tls_loadgen_A_full-handshake_benign_run1"
    gen_meta = {
        "run_id": rid,
        "scenario": "A",
        "workload": "full-handshake",
        "mode": "benign",
        "backend": "posix",
        "generator_version": "0.1.5",
        "generator_git_commit": "0123456789ab",
        "timeline_schema_version": 1,
        "timeline_file": "generator.timeline.json",
        "stats_wall_time_utc_ns": True,
        "configured_rate_per_s": 1.0,
        "configured_duration_s": 3,
        "configured_max_inflight": 64,
        "payload_size": 1024,
        "record_connections": 8,
        "resumption_policy": "reuse_seed",
        "resumption_pool_size": 32,
        "expected_tls_version": "TLSv1.3",
        "expected_ciphersuite": "TLS_AES_128_GCM_SHA256",
        "expected_group": "P-256",
        "expected_signature_algorithm": "ecdsa_secp256r1_sha256",
        "certificate_verification_enabled": True,
    }
    (gen_dir / "generator.metadata.json").write_text(json.dumps(gen_meta), encoding="utf-8")
    with (gen_dir / "generator_stats.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "run_id", "scenario", "workload", "mode", "backend",
                "wall_time_utc_ns", "elapsed_s", "phase", "local_capacity_drop_total",
                "tcp_established_total", "full_handshake_ok_total",
                "resumed_handshake_ok_total", "app_ok_total",
            ],
        )
        writer.writeheader()
        writer.writerow({
            "run_id": rid,
            "scenario": "A",
            "workload": "full-handshake",
            "mode": "benign",
            "backend": "posix",
            "wall_time_utc_ns": "6000000000",
            "elapsed_s": "3.1",
            "phase": "done",
            "local_capacity_drop_total": "0",
            "tcp_established_total": "1",
            "full_handshake_ok_total": "1",
            "resumed_handshake_ok_total": "0",
            "app_ok_total": "0",
        })
    (gen_dir / "generator.timeline.json").write_text(json.dumps({
        "schema_version": 1,
        "run_id": rid,
        "scenario": "A",
        "workload": "full-handshake",
        "mode": "benign",
        "backend": "posix",
        "generator_version": "0.1.5",
        "generator_git_commit": "0123456789ab",
        "configured_duration_s": 3,
        "process_started_utc_ns": 2_900_000_000,
        "phase_run_started_utc_ns": 3_000_000_000,
        "phase_run_end_deadline_utc_ns": 6_000_000_000,
        "phase_run_end_observed_utc_ns": 6_001_000_000,
        "drain_finished_utc_ns": 6_050_000_000,
        "process_finished_utc_ns": 6_100_000_000,
        "run_end_reason": "duration-complete",
        "current_phase": "done",
        "terminal": True,
    }), encoding="utf-8")

    (td / "dut" / "server.log").write_text(
        "[2026-08-04T18:00:00.000000000Z] INFO  manifest scenario=A build=test placement=normal_world tls=TLS1.3\n"
        "[2026-08-04T18:00:00.000000001Z] INFO  manifest bind=172.10.10.150:4433 cert=/root/certs/server.crt key=/root/certs/server.key max_conn=256 max_payload=16384 backlog=128 log_mode=debug debug_level=2 session_cache=off session_tickets=on strict_cert_profile=on cache_timeout_sec=0 cache_max_entries=0 handshake_timeout_ms=30000 idle_timeout_ms=30000 summary_interval_ms=1000\n"
        "[2026-08-04T18:00:10.000000000Z] FINAL uptime_ms=10000 accepted=2 active=0 hs_ok=2 echo_responses=1\n",
        encoding="utf-8",
    )
    (td / "dut" / "server.exit_code").write_text("0\n", encoding="ascii")
    (td / "dut" / "wrapper.exit_code").write_text("0\n", encoding="ascii")

    ref_status = {
        "state": "finished",
        "exit_code": 0,
        "actual_start_utc_ns": 1_000_000_000,
        "actual_end_utc_ns": 11_000_000_000,
        "start_lag_ns": 1_000_000,
    }
    gen_status = {
        "state": "finished",
        "exit_code": 0,
        "actual_start_utc_ns": 3_000_000_000,
        "actual_end_utc_ns": 6_100_000_000,
        "start_lag_ns": 2_000_000,
    }
    result = module.validate_run(td, cfg, args, rid, ref_status, gen_status)
    assert result["status"] == "PASS", result
    assert not result["warnings"], result

    # The functional profile must reject client-side generator success that is
    # not reflected by server-side completed handshakes. This reproduces the
    # Scenario A peer-hangup defect caught during physical integration.
    server_log = td / "dut" / "server.log"
    valid_server_log = server_log.read_text(encoding="utf-8")
    server_log.write_text(
        valid_server_log.replace("accepted=2 active=0 hs_ok=2", "accepted=2 active=0 hs_ok=0"),
        encoding="utf-8",
    )
    result = module.validate_run(td, cfg, args, rid, ref_status, gen_status)
    assert result["status"] == "FAIL", result
    assert any("successful TLS handshakes" in error for error in result["errors"]), result
    server_log.write_text(valid_server_log, encoding="utf-8")

    # In measurement mode the same discrepancy is retained as a warning because
    # under overload it may be part of the observed DUT degradation rather than
    # an infrastructure failure.
    args.profile = "measurement"
    measurement_log = valid_server_log.replace("log_mode=debug debug_level=2", "log_mode=measurement debug_level=0")
    server_log.write_text(
        measurement_log.replace("accepted=2 active=0 hs_ok=2", "accepted=2 active=0 hs_ok=0"),
        encoding="utf-8",
    )
    result = module.validate_run(td, cfg, args, rid, ref_status, gen_status)
    assert result["status"] == "PASS", result
    assert any("successful TLS handshakes" in warning for warning in result["warnings"]), result
    args.profile = "pilot-debug"
    server_log.write_text(valid_server_log, encoding="utf-8")

    # Reproduce the previously observed false-success shape: only a few seconds
    # of rows for a nominally long reference run must be rejected.
    args.reference_duration = 300
    result = module.validate_run(td, cfg, args, rid, ref_status, gen_status)
    assert result["status"] == "FAIL"
    assert any("ended too early" in error for error in result["errors"])

print("run validation contract: PASS")
