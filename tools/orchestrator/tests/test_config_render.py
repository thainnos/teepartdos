#!/usr/bin/env python3
from __future__ import annotations
import os
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
text = (root / "config/campaign.example.toml").read_text(encoding="utf-8")
text = text.replace("CHANGE_ME_DUT_SSH_PASSWORD", "dut-password")
text = text.replace("CHANGE_ME_LOADGEN_USER", "loadgenuser")
text = text.replace("CHANGE_ME_LOADGEN_SSH_PASSWORD", "loadgen-password")
text = text.replace("CHANGE_ME_LOADGEN_SUDO_PASSWORD", "loadgen-sudo-password")
for field, value in {
    "CHANGE_ME_DATA_INTERFACE": "eth0",
    "CHANGE_ME_REF_CONTROL_INTERFACE": "eth1",
    "CHANGE_ME_LOADGEN_CONTROL_INTERFACE": "eth1",
    "CHANGE_ME_PCI_ADDRESS": "0000:01:00.0",
    "CHANGE_ME_KERNEL_DRIVER": "e1000e",
}.items():
    text = text.replace(field, value)
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    cfg = td / "campaign.toml"
    out = td / "rendered"
    cfg.write_text(text, encoding="utf-8")
    os.chmod(cfg, 0o600)
    subprocess.run(["python3", str(root / "orchestrate.py"), "validate-config", "--config", str(cfg)], check=True)
    subprocess.run(["python3", str(root / "orchestrate.py"), "render-agent-configs", "--config", str(cfg), "--output", str(out)], check=True)
    assert (out / "dut-agent.conf").is_file()
    assert (out / "loadgen-agent.conf").is_file()
    rendered = (out / "dut-agent.conf").read_text() + (out / "loadgen-agent.conf").read_text()
    assert "dut-password" not in rendered
    assert "loadgen-password" not in rendered
    assert "loadgen-sudo-password" not in rendered
    assert "MTU=1500" in (out / "dut-agent.conf").read_text()
    load = (out / "loadgen-agent.conf").read_text()
    for assignment in (
        "RUN_GROUP=auto",
        "DUT_MAC=02:00:00:00:00:50",
        "SERVER_NAME=tls-echo-server",
        "PAYLOAD_SIZE=1024",
        "MTU=1500",
        "TLS_CIPHERSUITE=TLS_AES_128_GCM_SHA256",
        "TLS_GROUP=P-256",
        "TLS_SIGNATURE_ALGORITHM=ecdsa_secp256r1_sha256",
        "EXPECTED_NETWORK_NETMASK=255.255.255.0",
        "EXPECTED_TCP_NODELAY=true",
        "EXPECTED_MAX_RELEASE_BURST=4096",
        "EXPECTED_DRAIN_TIMEOUT_MS=10000",
        "EXPECTED_TCP_CONNECT_TIMEOUT_MS=5000",
        "EXPECTED_TLS_HANDSHAKE_TIMEOUT_MS=5000",
        "EXPECTED_IO_TIMEOUT_MS=5000",
        "EXPECTED_PAYLOAD_PATTERN_HEX=a5",
        "EXPECTED_FULL_ECHO_AFTER_HANDSHAKE=false",
        "EXPECTED_RESUMPTION_POLICY=reuse_seed",
        "EXPECTED_RESUMPTION_POOL_SIZE=32",
        "EXPECTED_WAIT_FOR_FRESH_TICKET=true",
        "EXPECTED_RECORD_MAX_PENDING_RELEASES=4096",
        "EXPECTED_RECORD_RECONNECT=true",
        "EXPECTED_RECORD_RECONNECT_BACKOFF_MS=1000",
        "EXPECTED_STDOUT_PROGRESS=true",
        "EXPECTED_FSTACK_PROC_ID=0",
    ):
        assert assignment in load, assignment

    alternate = text.replace('resumption_policy = "reuse_seed"', 'resumption_policy = "chain"', 1)
    alternate = alternate.replace('resumption_policy = "reuse_seed"', 'resumption_policy = "fresh_pool"', 1)
    alternate = alternate.replace('resumption_pool_size = 32', 'resumption_pool_size = 48', 1)
    alt_cfg = td / "campaign-alternate.toml"
    alt_out = td / "rendered-alternate"
    alt_cfg.write_text(alternate, encoding="utf-8")
    os.chmod(alt_cfg, 0o600)
    subprocess.run(["python3", str(root / "orchestrate.py"), "validate-config", "--config", str(alt_cfg)], check=True)
    subprocess.run(["python3", str(root / "orchestrate.py"), "render-agent-configs", "--config", str(alt_cfg), "--output", str(alt_out)], check=True)
    alt_load = (alt_out / "loadgen-agent.conf").read_text(encoding="utf-8")
    assert "EXPECTED_RESUMPTION_POLICY=fresh_pool" in alt_load
    assert "EXPECTED_RESUMPTION_POOL_SIZE=48" in alt_load
print("config render: PASS")
