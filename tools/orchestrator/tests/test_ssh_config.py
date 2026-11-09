#!/usr/bin/env python3
"""Regression checks for selectable key/password SSH transport."""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("orchestrate", root / "orchestrate.py")
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

text = (root / "config/campaign.example.toml").read_text(encoding="utf-8")
replacements = {
    "CHANGE_ME_DUT_SSH_PASSWORD": "dut-secret",
    "CHANGE_ME_LOADGEN_USER": "tester",
    "CHANGE_ME_LOADGEN_SSH_PASSWORD": "loadgen-secret",
    "CHANGE_ME_LOADGEN_SUDO_PASSWORD": "sudo-secret",
    "CHANGE_ME_DATA_INTERFACE": "eth0",
    "CHANGE_ME_REF_CONTROL_INTERFACE": "eth1",
    "CHANGE_ME_LOADGEN_CONTROL_INTERFACE": "eth1",
    "CHANGE_ME_PCI_ADDRESS": "0000:01:00.0",
    "CHANGE_ME_KERNEL_DRIVER": "e1000e",
}
for before, after in replacements.items():
    text = text.replace(before, after)

with tempfile.TemporaryDirectory() as td_raw:
    cfg_path = Path(td_raw) / "campaign.toml"
    cfg_path.write_text(text, encoding="utf-8")
    os.chmod(cfg_path, 0o600)
    cfg = module.load_config(cfg_path)
    assert not module.validate_config(cfg)
    assert module.ssh_auth_mode(cfg, "loadgen") == "password"
    args = module.ssh_base(cfg, "loadgen")
    assert "BatchMode=no" in args
    assert "PreferredAuthentications=keyboard-interactive,password" in args
    assert "PubkeyAuthentication=no" in args
    assert "loadgen-secret" not in repr(args)

    captured = {}
    original_run = module.subprocess.run
    original_find = module.find_executable
    def fake_password_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        captured["secret"] = os.read(int(argv[2]), 1024)
        return subprocess.CompletedProcess(argv, 0, "ok\n", "")
    module.subprocess.run = fake_password_run
    module.find_executable = lambda name, absolute_candidates=(): "/usr/bin/sshpass" if name == "sshpass" else original_find(name, absolute_candidates)
    try:
        cp = module.execute_with_password(cfg, "loadgen", ["ssh", "example", "/bin/true"])
        assert cp.returncode == 0
    finally:
        module.subprocess.run = original_run
        module.find_executable = original_find
    assert captured["secret"] == b"loadgen-secret\n"
    assert "loadgen-secret" not in repr(captured["argv"])
    assert "loadgen-secret" not in repr(captured["kwargs"])
    assert captured["kwargs"]["pass_fds"]

    # Public-key SSH remains available when explicitly selected.
    cfg_path.write_text(text.replace('auth = "password"', 'auth = "key"', 1), encoding="utf-8")
    cfg = module.load_config(cfg_path)
    assert not module.validate_config(cfg)
    assert module.ssh_auth_mode(cfg, "loadgen") == "key"
    key_argv = module.ssh_base(cfg, "loadgen")
    assert key_argv[0] == "ssh"
    assert "BatchMode=yes" in key_argv
    assert "PreferredAuthentications=publickey" in key_argv
    assert "PasswordAuthentication=no" in key_argv
    assert "loadgen-secret" not in repr(key_argv)

    calls = []
    def fake_key_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "ok\n", "")
    module.subprocess.run = fake_key_run
    try:
        cp = module.execute_with_password(cfg, "loadgen", ["ssh", "example", "/bin/true"])
        assert cp.returncode == 0
        assert calls and calls[0][0][0] == "ssh"
        assert "pass_fds" not in calls[0][1]
    finally:
        module.subprocess.run = original_run

print("ssh key and password transport: PASS")
