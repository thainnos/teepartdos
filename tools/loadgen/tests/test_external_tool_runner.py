#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "external_tool_runner.py"


def write_counter(root: Path, iface: str, name: str, value: int) -> None:
    p = root / iface / "statistics" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"{value}\n", encoding="ascii")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="external-runner-test-") as td_s:
        td = Path(td_s)
        fake = td / "fake_tool.py"
        fake.write_text(textwrap.dedent("""\
            #!/usr/bin/env python3
            import signal, time
            stop=False
            def h(*_):
                global stop
                stop=True
            signal.signal(signal.SIGINT,h)
            signal.signal(signal.SIGTERM,h)
            while not stop:
                time.sleep(0.02)
        """), encoding="utf-8")
        fake.chmod(0o755)
        ext = td / "external.toml"
        ext.write_text(textwrap.dedent(f"""\
            [external]
            label = "tcp-syn"
            command = ["{fake}"]
            interface = "test0"
            stop_signal = "SIGINT"
            stop_grace_s = 1.0
            require_tx_packets = false
        """), encoding="utf-8")
        gen = td / "generator.conf"
        gen.write_text(textwrap.dedent("""\
            payload.size=1024
            record.max_pending_releases=4096
            resumption.session_policy=reuse_seed
            resumption.pool_size=32
            tls.ciphersuite=TLS_AES_128_GCM_SHA256
            tls.group=P-256
            tls.signature_algorithm=ecdsa_secp256r1_sha256
            tls.verify_peer=true
        """), encoding="utf-8")
        sysfs = td / "sysfs"
        for name in ("tx_packets","tx_bytes","rx_packets","rx_bytes","tx_dropped","rx_dropped"):
            write_counter(sysfs,"test0",name,100)
        out = td / "out"; out.mkdir()
        cp = subprocess.run([
            sys.executable, str(RUNNER), "--config", str(ext),
            "--run-id", "external-test", "--scenario", "A",
            "--duration", "1", "--rate", "0", "--max-inflight", "4096",
            "--record-connections", "32", "--generator-config", str(gen),
            "--output-dir", str(out), "--sysfs-root", str(sysfs),
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if cp.returncode != 0:
            raise SystemExit(f"runner failed rc={cp.returncode}\nstdout={cp.stdout}\nstderr={cp.stderr}")
        runs = list(out.glob("tls_loadgen_A_tcp-syn_flood_external-test"))
        assert len(runs) == 1
        run = runs[0]
        timeline = json.loads((run / "generator.timeline.json").read_text())
        meta = json.loads((run / "generator.metadata.json").read_text())
        rows = list(csv.DictReader((run / "generator_stats.csv").open()))
        assert timeline["current_phase"] == "done"
        assert timeline["phase_run_end_observed_utc_ns"] >= timeline["phase_run_started_utc_ns"]
        assert meta["external_runner_version"] == "0.1.0"
        assert meta["rate_semantics"] == "tool-controlled-observed-interface-rate"
        assert rows[-1]["external_process_completed"] == "1"
        assert rows[-1]["workload"] == "tcp-syn"
        assert (run / "external_tool.command.txt").exists()
    print("generic external tool runner test: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
