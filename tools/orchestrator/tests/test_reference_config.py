#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import os
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("orchestrate", root / "orchestrate.py")
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory() as td_raw:
    td = Path(td_raw)
    ref = td / "reference_client"
    certs = td / "certificates"
    ref.mkdir(); certs.mkdir()
    ca = certs / "server.crt"; ca.write_text("test")
    conf = ref / "reference_client.conf"
    conf.write_text("""\
tls.ca_file=../certificates/server.crt
tls.server_name=tls-echo-server
tls.verify_peer=true
tls.verify_hostname=false
tls.strict_shutdown=false
tls.ciphersuite=TLS_AES_128_GCM_SHA256
tls.group=P-256
tls.signature_algorithm=ecdsa_secp256r1_sha256
run.probe_interval_ms=1000
timeouts.tcp_connect_ms=5000
timeouts.tls_handshake_ms=5000
timeouts.io_ms=5000
payload.size_bytes=1024
payload.mode=fixed_pattern
payload.pattern_hex=a5
payload.seed=12345
resumption.session_policy=reuse_seed
socket.tcp_nodelay=true # validated inline comment
record.reconnect_on_failure=true
record.reconnect_backoff_ms=1000
output.csv_prefix=tls_reference
output.stdout_progress=true
""")
    cfg_path = td / "campaign.toml"
    cfg_path.write_text("x=1\n")
    cfg = module.CampaignConfig(cfg_path, {
        "experiment": {"server_name":"tls-echo-server", "payload_size":1024, "reference_probe_interval_ms":1000},
        "reference": {"config":str(conf), "ca_file":str(ca)},
    })
    assert module.reference_workdir(cfg) == ref.resolve()
    assert module.validate_reference_configuration(cfg) == []

    chained = conf.read_text(encoding="utf-8").replace(
        "resumption.session_policy=reuse_seed",
        "resumption.session_policy=chain",
    )
    conf.write_text(chained, encoding="utf-8")
    cfg.data["reference"]["profile"] = {"resumption_policy": "chain"}
    assert module.validate_reference_configuration(cfg) == []

    cfg.data["reference"]["profile"] = {"resumption_policy": "reuse_seed"}
    mismatch = module.validate_reference_configuration(cfg)
    assert any("resumption.session_policy" in item for item in mismatch)

print("reference configuration/workdir validation: PASS")
