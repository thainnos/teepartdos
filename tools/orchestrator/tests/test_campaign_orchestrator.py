#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGNCTL = ROOT / "campaignctl.py"


def run(*args: str, cwd: Path, expected: int = 0) -> subprocess.CompletedProcess[str]:
    cp = subprocess.run(
        [sys.executable, str(CAMPAIGNCTL), *args],
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if cp.returncode != expected:
        raise AssertionError(
            f"returncode={cp.returncode}, expected={expected}\nstdout={cp.stdout}\nstderr={cp.stderr}"
        )
    return cp


with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    results = td / "results"
    config = td / "campaign.local.toml"
    config.write_text(
        f"""\
[repository]
results_root = {str(results)!r}
[experiment]
reference_duration_s = 20
generator_duration_s = 5
pre_generation_s = 2
start_delay_s = 1
[defaults.generator]
max_inflight = 64
record_connections = 8
""",
        encoding="utf-8",
    )

    mock = td / "orchestrate.py"
    mock.write_text(
        """\
#!/usr/bin/env python3
import argparse, json, pathlib, time
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
p=argparse.ArgumentParser(); sub=p.add_subparsers(dest='command',required=True)
r=sub.add_parser('tls-run')
r.add_argument('--config'); r.add_argument('--scenario'); r.add_argument('--profile')
r.add_argument('--reference-workload'); r.add_argument('--reference-duration')
r.add_argument('--generator-backend'); r.add_argument('--generator-workload')
r.add_argument('--generator-mode'); r.add_argument('--generator-rate')
r.add_argument('--generator-duration'); r.add_argument('--generator-max-inflight')
r.add_argument('--generator-connections'); r.add_argument('--repetition')
r.add_argument('--pre-generation'); r.add_argument('--start-delay'); r.add_argument('--confirm-flood',action='store_true')
a=p.parse_args()
with open(a.config,'rb') as fh: cfg=tomllib.load(fh)
root=pathlib.Path(cfg['repository']['results_root'])
rid=f\"{time.time_ns()}_{a.scenario}_{a.reference_workload}\"
rate=a.generator_rate.replace('.','p')
out=root/f\"scenario_{a.scenario}\"/a.reference_workload/a.generator_workload/a.generator_mode/a.generator_backend/f\"rate_{rate}\"/f\"repetition_{a.repetition}\"/rid
out.mkdir(parents=True)
manifest={'run_id':rid,'scenario':a.scenario,'profile':a.profile,'reference_workload':a.reference_workload,'generator_workload':a.generator_workload,'generator_mode':a.generator_mode,'generator_backend':a.generator_backend,'generator_rate':float(a.generator_rate),'repetition':int(a.repetition)}
(out/'run_manifest.json').write_text(json.dumps(manifest))
(out/'validation.json').write_text(json.dumps({'status':'PASS','errors':[],'warnings':[]}))
""",
        encoding="utf-8",
    )
    mock.chmod(0o755)

    matrix = td / "a.toml"
    matrix.write_text(
        """\
[campaign]
campaign_id='A-pilot-01'
overall_campaign_id='overall-pilot-01'
campaign_type='pilot'
description='test'
[[runs]]
scenario='A'
profile='measurement'
reference_workload='full-handshake'
generator_backend='fstack'
generator_workload='full-handshake'
generator_mode='benign'
rates=[10.0,20.0]
repetitions=1
""",
        encoding="utf-8",
    )

    run(
        "run",
        "--config",
        str(config),
        "--matrix",
        str(matrix),
        "--orchestrate",
        str(mock),
        cwd=td,
    )

    campaign_path = (
        results
        / "_campaigns"
        / "overall-pilot-01"
        / "campaigns"
        / "A-pilot-01"
        / "campaign_manifest.json"
    )
    campaign = json.loads(campaign_path.read_text())
    assert campaign["status"] == "complete", campaign
    assert campaign["summary"]["expected_points"] == 2, campaign
    assert campaign["summary"]["selected_points"] == 2, campaign
    assert all(item["selection"] == "selected" for item in campaign["runs"]), campaign
    for item in campaign["runs"]:
        raw = json.loads((results / item["result_path"] / "run_manifest.json").read_text())
        assert raw["campaign_id"] == "A-pilot-01", raw
        assert raw["overall_campaign_id"] == "overall-pilot-01", raw
        assert raw["campaign_type"] == "pilot", raw

    overall_path = results / "_campaigns" / "overall-pilot-01" / "overall_campaign_manifest.json"
    overall = json.loads(overall_path.read_text())
    assert overall["status"] == "incomplete", overall
    assert overall["complete_scenarios"] == ["A"], overall

    run(
        "verify",
        "--results-root",
        str(results),
        "--campaign-id",
        "A-pilot-01",
        cwd=td,
    )
    run("list", "--results-root", str(results), cwd=td)

    mixed = td / "mixed.toml"
    mixed.write_text(
        """\
[campaign]
campaign_id='A-mixed'
overall_campaign_id='overall-mixed'
campaign_type='pilot'
[[runs]]
scenario='A'
profile='measurement'
reference_workload='record'
generator_backend='fstack'
generator_workload='record'
generator_mode='benign'
rates=[100.0]
repetitions=1
[[runs]]
scenario='A'
profile='measurement'
reference_workload='record'
generator_backend='posix'
generator_workload='record'
generator_mode='benign'
rates=[200.0]
repetitions=1
""",
        encoding="utf-8",
    )
    cp = run(
        "run",
        "--config",
        str(config),
        "--matrix",
        str(mixed),
        "--orchestrate",
        str(mock),
        cwd=td,
        expected=2,
    )
    assert "backend mixing" in cp.stderr, cp.stderr

print("campaign orchestrator: PASS")
