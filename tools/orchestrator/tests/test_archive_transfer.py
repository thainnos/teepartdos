#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import io
import os
import sys
import tarfile
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
    archive = td / "run.tar"
    source = td / "source"
    source.mkdir()
    (source / "server.log").write_text("manifest scenario=A ok\n", encoding="utf-8")
    (source / "state").mkdir()
    (source / "state" / "uname.txt").write_text("Linux test\n", encoding="utf-8")
    with tarfile.open(archive, "w") as tf:
        tf.add(source, arcname=".")
    destination = td / "destination"
    result = module._safe_extract_tar(archive, destination)
    assert result["files"] == 2, result
    assert (destination / "server.log").read_text() == "manifest scenario=A ok\n"
    assert (destination / "state" / "uname.txt").read_text() == "Linux test\n"

    malicious = td / "malicious.tar"
    with tarfile.open(malicious, "w") as tf:
        info = tarfile.TarInfo("../escape")
        payload = b"no\n"
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    try:
        module._safe_extract_tar(malicious, td / "bad")
    except module.OrchestratorError:
        pass
    else:
        raise AssertionError("path-traversal archive was accepted")
    assert not (td / "escape").exists()

    # Exercise the complete local stream/temporary-file/extraction path while
    # replacing only the SSH argv with a local cat of the known archive.
    cfg = module.CampaignConfig(td / "campaign.toml", {"dut": {"ssh_password": "secret"}})
    original = module._archive_stream_argv
    module._archive_stream_argv = lambda _cfg, _host, _rid, _fd: ["/bin/cat", str(archive)]
    try:
        streamed = module.fetch_run_archive(cfg, "dut", "run1", td / "streamed", timeout=5)
    finally:
        module._archive_stream_argv = original
    assert streamed["method"] == "agent-tar-stream-over-ssh"
    assert streamed["files"] == 2
    assert (td / "streamed" / "server.log").is_file()

    link_archive = td / "link.tar"
    with tarfile.open(link_archive, "w") as tf:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    try:
        module._safe_extract_tar(link_archive, td / "bad-link")
    except module.OrchestratorError:
        pass
    else:
        raise AssertionError("symlink archive member was accepted")

print("safe archive extraction: PASS")
