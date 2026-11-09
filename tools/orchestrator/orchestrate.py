#!/usr/bin/env python3
"""Three-host orchestrator for the TEE/TLS robustness measurement setup.

Runs on the reference-client device. It controls the DUT and load-generator
through pre-installed, fail-closed helper programs and keeps the authoritative
result copy locally.
"""
from __future__ import annotations

import argparse
import csv
import fcntl
import hashlib
import ipaddress
import json
import os
import random
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tarfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

try:
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit("Python 3.11 or newer is required (tomllib missing).") from exc

VERSION = "0.1.9"
SCENARIOS = set("ABCDE")
REFERENCE_WORKLOADS = {"full-handshake", "resumption", "record"}
GENERATOR_WORKLOADS = REFERENCE_WORKLOADS | {"tcp-syn"}
# Compatibility alias for existing TLS-only configuration checks.
WORKLOADS = REFERENCE_WORKLOADS
BACKENDS = {"posix", "fstack"}
MODES = {"benign", "flood"}
PROFILES = {"pilot-debug", "measurement"}
PLACEHOLDER = re.compile(r"CHANGE_ME")
ACTIVE_LOCAL: subprocess.Popen[Any] | None = None

REFERENCE_PROFILE_DEFAULTS: dict[str, Any] = {
    "strict_shutdown": False,
    "tcp_connect_timeout_ms": 5000,
    "tls_handshake_timeout_ms": 5000,
    "io_timeout_ms": 5000,
    "payload_mode": "fixed_pattern",
    "payload_pattern_hex": "a5",
    "payload_seed": 12345,
    "resumption_policy": "reuse_seed",
    "tcp_nodelay": True,
    "record_reconnect_on_failure": True,
    "record_reconnect_backoff_ms": 1000,
    "output_csv_prefix": "tls_reference",
    "stdout_progress": True,
}
LOADGEN_PROFILE_DEFAULTS: dict[str, Any] = {
    "network_netmask": "255.255.255.0",
    "tcp_nodelay": True,
    "max_release_burst": 4096,
    "drain_timeout_ms": 10000,
    "tcp_connect_timeout_ms": 5000,
    "tls_handshake_timeout_ms": 5000,
    "io_timeout_ms": 5000,
    "payload_pattern_hex": "a5",
    "full_echo_after_handshake": False,
    "resumption_policy": "reuse_seed",
    "resumption_pool_size": 32,
    "wait_for_fresh_ticket": True,
    "record_max_pending_releases": 4096,
    "record_reconnect": True,
    "record_reconnect_backoff_ms": 1000,
    "stdout_progress": True,
    "fstack_proc_id": 0,
}


class OrchestratorError(RuntimeError):
    pass


@dataclass
class CampaignConfig:
    path: Path
    data: dict[str, Any]

    def section(self, name: str) -> dict[str, Any]:
        value = self.data.get(name)
        if not isinstance(value, dict):
            raise OrchestratorError(f"missing TOML section [{name}]")
        return value

    def get(self, dotted: str, default: Any = None, required: bool = True) -> Any:
        cur: Any = self.data
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                if required:
                    raise OrchestratorError(f"missing configuration key: {dotted}")
                return default
            cur = cur[part]
        return cur

    def local_path(self, dotted: str) -> Path:
        return Path(os.path.expanduser(str(self.get(dotted)))).resolve()


def profile_value(
    cfg: CampaignConfig, section: str, key: str, defaults: dict[str, Any]
) -> Any:
    return cfg.get(f"{section}.profile.{key}", defaults[key], required=False)


def bool_text(value: Any) -> str:
    if not isinstance(value, bool):
        raise OrchestratorError(f"expected boolean profile value, got {value!r}")
    return "true" if value else "false"


def effective_profile(
    cfg: CampaignConfig, section: str, defaults: dict[str, Any]
) -> dict[str, Any]:
    """Return the complete non-secret frozen runtime profile for one tool."""
    return {
        key: profile_value(cfg, section, key, defaults)
        for key in sorted(defaults)
    }


def load_config(path: Path) -> CampaignConfig:
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    return CampaignConfig(path.resolve(), data)


def utc_iso_ns(epoch_ns: int | None = None) -> str:
    if epoch_ns is None:
        epoch_ns = time.time_ns()
    sec, ns = divmod(epoch_ns, 1_000_000_000)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sec)) + f".{ns:09d}Z"


def run_id(prefix: str) -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return f"{stamp}_{prefix}_{random.getrandbits(40):010x}"


def atomic_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


@contextmanager
def campaign_lock(cfg: CampaignConfig, operation: str) -> Iterable[None]:
    """Prevent overlapping deployment, initialization, iperf and TLS campaigns.

    The lock is local to the reference-client/orchestrator host.  It protects
    the single DUT TLS port, the single load-generator data port and the shared
    remote run roots from concurrent orchestrator instances.  The file remains
    after release as a small diagnostic record; the advisory lock itself is
    held only while this context is active.
    """
    state_root = cfg.local_path("repository.state_root")
    state_root.mkdir(parents=True, exist_ok=True)
    lock_path = state_root / "orchestrator.lock"
    handle = lock_path.open("a+", encoding="utf-8")
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.seek(0)
            detail = handle.read().strip()
            raise OrchestratorError(
                "another orchestrator operation already holds the campaign lock"
                + (f": {detail}" if detail else f": {lock_path}")
            ) from exc
        handle.seek(0)
        handle.truncate()
        json.dump(
            {
                "pid": os.getpid(),
                "operation": operation,
                "acquired_utc": utc_iso_ns(),
            },
            handle,
            sort_keys=True,
        )
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        yield
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def execute(argv: list[str], *, check: bool = True, capture: bool = True,
            timeout: float | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        timeout=timeout,
        cwd=str(cwd) if cwd else None,
    )


def find_executable(name: str, absolute_candidates: Iterable[str] = ()) -> str | None:
    """Resolve a command even when administrative directories are absent from PATH."""
    found = shutil.which(name)
    if found:
        return found
    for candidate in absolute_candidates:
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def completed_diagnostic(cp: subprocess.CompletedProcess[str]) -> str:
    parts = [f"exit_status={cp.returncode}"]
    if cp.stdout and cp.stdout.strip():
        parts.append(f"stdout={cp.stdout.strip()!r}")
    if cp.stderr and cp.stderr.strip():
        parts.append(f"stderr={cp.stderr.strip()!r}")
    return ", ".join(parts)


def _without_ssh_option(options: list[str], option_name: str) -> list[str]:
    """Remove all spellings of a named OpenSSH -o option from an argv list."""
    out: list[str] = []
    i = 0
    prefix = option_name.lower() + "="
    while i < len(options):
        item = options[i]
        if item == "-o" and i + 1 < len(options):
            value = options[i + 1]
            if value.lower().startswith(prefix):
                i += 2
                continue
        if item.startswith("-o") and item[2:].lower().startswith(prefix):
            i += 1
            continue
        out.append(item)
        i += 1
    return out


def ssh_target(cfg: CampaignConfig, host: str) -> str:
    if host not in {"dut", "loadgen"}:
        raise ValueError(host)
    return str(cfg.get(f"{host}.ssh_target"))


def ssh_auth_mode(cfg: CampaignConfig, host: str) -> str:
    mode = cfg.get(f"{host}.ssh_auth", cfg.get("ssh.auth", "password", required=False), required=False)
    if mode not in ("key", "password"):
        raise OrchestratorError(f"{host}.ssh_auth must be 'key' or 'password'")
    return mode


def ssh_password(cfg: CampaignConfig, host: str) -> str:
    if host not in {"dut", "loadgen"}:
        raise ValueError(host)
    value = cfg.get(f"{host}.ssh_password")
    if not isinstance(value, str) or not value:
        raise OrchestratorError(f"{host}.ssh_password must be a non-empty TOML string")
    if any(ch in value for ch in ("\n", "\r", "\x00")):
        raise OrchestratorError(f"{host}.ssh_password must not contain newline or NUL characters")
    return value


def loadgen_sudo_password(cfg: CampaignConfig) -> str:
    value = cfg.get("loadgen.sudo_password")
    if not isinstance(value, str) or not value:
        raise OrchestratorError("loadgen.sudo_password must be a non-empty TOML string")
    if any(ch in value for ch in ("\n", "\r", "\x00")):
        raise OrchestratorError("loadgen.sudo_password must not contain newline or NUL characters")
    return value


def ssh_options(cfg: CampaignConfig, host: str) -> list[str]:
    """Build authentication-specific SSH options for all remote operations."""
    options = [str(x) for x in cfg.get("ssh.options")]
    host_options = cfg.get(f"{host}.ssh_options", [], required=False)
    if not isinstance(host_options, list):
        raise OrchestratorError(f"{host}.ssh_options must be a TOML array")
    options.extend(str(x) for x in host_options)
    for name in (
        "BatchMode", "PasswordAuthentication", "KbdInteractiveAuthentication",
        "PreferredAuthentications", "PubkeyAuthentication", "NumberOfPasswordPrompts",
        "IdentitiesOnly", "IdentityFile",
    ):
        options = _without_ssh_option(options, name)
    if ssh_auth_mode(cfg, host) == "password":
        options.extend([
            "-o", "BatchMode=no",
            "-o", "PasswordAuthentication=yes",
            "-o", "KbdInteractiveAuthentication=yes",
            "-o", "PreferredAuthentications=keyboard-interactive,password",
            "-o", "PubkeyAuthentication=no",
            "-o", "NumberOfPasswordPrompts=1",
        ])
    else:
        options.extend([
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PubkeyAuthentication=yes",
            "-o", "IdentitiesOnly=yes",
        ])
        identity = cfg.get(f"{host}.ssh_identity_file", "", required=False)
        if identity:
            options.extend(["-o", "IdentityFile=" + os.path.expanduser(str(identity))])
    return options


def ssh_base(cfg: CampaignConfig, host: str) -> list[str]:
    return ["ssh", *ssh_options(cfg, host), ssh_target(cfg, host)]


def execute_with_password(
    cfg: CampaignConfig,
    host: str,
    argv: list[str],
    *,
    check: bool = True,
    capture: bool = True,
    timeout: float | None = None,
    cwd: Path | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run SSH/SCP with selected key or password authentication."""
    if ssh_auth_mode(cfg, host) == "key":
        return subprocess.run(
            argv, check=check, text=True, input=input_text,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            timeout=timeout, cwd=str(cwd) if cwd else None,
        )
    sshpass = find_executable("sshpass")
    if sshpass is None:
        raise OrchestratorError("sshpass is missing on the reference-client host")
    read_fd, write_fd = os.pipe()
    try:
        if ssh_auth_mode(cfg, host) == "password":
            os.write(write_fd, ssh_password(cfg, host).encode("utf-8") + b"\n")
    finally:
        os.close(write_fd)
    try:
        return subprocess.run(
            [sshpass, "-d", str(read_fd), *argv],
            check=check,
            text=True,
            input=input_text,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            pass_fds=(read_fd,),
        )
    finally:
        os.close(read_fd)


def ssh_run(
    cfg: CampaignConfig,
    host: str,
    command: list[str],
    *,
    sudo: bool = False,
    check: bool = True,
    timeout: float | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    remote = (["sudo", "-n"] if sudo else []) + command
    command_text = shlex.join(remote)
    return execute_with_password(
        cfg,
        host,
        [*ssh_base(cfg, host), command_text],
        check=check,
        timeout=timeout,
        input_text=input_text,
    )


def scp_to(cfg: CampaignConfig, host: str, sources: list[Path], remote_directory: str) -> None:
    argv = ["scp", *ssh_options(cfg, host), *[str(p) for p in sources],
            f"{ssh_target(cfg, host)}:{remote_directory.rstrip('/')}/"]
    execute_with_password(cfg, host, argv, capture=False)


def remote_temp_directory(cfg: CampaignConfig, host: str) -> str:
    cp = ssh_run(
        cfg,
        host,
        ["mktemp", "-d", "/tmp/tee-tls-orchestrator.XXXXXX"],
        check=False,
        timeout=15,
    )
    if cp.returncode != 0:
        raise OrchestratorError(f"cannot create {host} deployment directory: {completed_diagnostic(cp)}")
    value = cp.stdout.strip().splitlines()[-1] if cp.stdout.strip() else ""
    if not re.fullmatch(r"/tmp/tee-tls-orchestrator\.[A-Za-z0-9]+", value):
        raise OrchestratorError(f"unsafe {host} deployment directory returned: {value!r}")
    return value

def parse_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def remote_agent(cfg: CampaignConfig, host: str, args: list[str], *, check: bool = True,
                 timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    if host == "dut":
        agent = str(cfg.get("dut.agent"))
        return ssh_run(cfg, host, [agent, *args], check=check, timeout=timeout)
    if host == "loadgen":
        agent = str(cfg.get("loadgen.agent"))
        return ssh_run(cfg, host, [agent, *args], sudo=True, check=check, timeout=timeout)
    raise ValueError(host)


def _archive_stream_argv(cfg: CampaignConfig, host: str, run_id_value: str, password_fd: int) -> list[str]:
    if host == "dut":
        remote = [str(cfg.get("dut.agent")), "archive-run", run_id_value]
    elif host == "loadgen":
        remote = ["sudo", "-n", str(cfg.get("loadgen.agent")), "archive-run", run_id_value]
    else:
        raise ValueError(host)
    command = [*ssh_base(cfg, host), shlex.join(remote)]
    if ssh_auth_mode(cfg, host) == "key":
        return command
    sshpass = find_executable("sshpass")
    if sshpass is None:
        raise OrchestratorError("sshpass is missing on the reference-client host")
    return [sshpass, "-d", str(password_fd), *command]


def _safe_extract_tar(archive_path: Path, destination: Path) -> dict[str, Any]:
    """Extract an uncompressed remote run archive without trusting member paths.

    The remote agents emit only directories and regular files. Links, devices,
    FIFOs, absolute paths and parent traversal are rejected. Extraction occurs
    in a sibling temporary directory and replaces the destination atomically.
    """
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix=destination.name + ".extract-", dir=parent))
    files = 0
    total_bytes = 0
    try:
        with tarfile.open(archive_path, mode="r:") as tf:
            for member in tf:
                raw = member.name
                path = PurePosixPath(raw)
                parts = [part for part in path.parts if part not in ("", ".")]
                if path.is_absolute() or any(part == ".." for part in parts):
                    raise OrchestratorError(f"unsafe archive member path: {raw!r}")
                target = temp_dir.joinpath(*parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise OrchestratorError(
                        f"unsupported archive member type for {raw!r}; only directories and regular files are accepted"
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                source = tf.extractfile(member)
                if source is None:
                    raise OrchestratorError(f"cannot read archive member: {raw!r}")
                with source, target.open("wb") as out:
                    shutil.copyfileobj(source, out, length=1024 * 1024)
                os.chmod(target, member.mode & 0o777)
                files += 1
                total_bytes += member.size
        if destination.exists():
            shutil.rmtree(destination)
        os.replace(temp_dir, destination)
        return {"files": files, "payload_bytes": total_bytes}
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def fetch_run_archive(
    cfg: CampaignConfig,
    host: str,
    run_id_value: str,
    local_path: Path,
    *,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Fetch one run tree over an agent-generated uncompressed tar stream.

    No rsync implementation is required on either remote host. The remote
    dependency is limited to the tar invocation verified by agent preflight.
    Binary stdout is written to a local temporary file while SSH diagnostics
    remain on stderr.
    """
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", run_id_value):
        raise OrchestratorError(f"unsafe run ID for collection: {run_id_value!r}")

    read_fd, write_fd = os.pipe()
    try:
        if ssh_auth_mode(cfg, host) == "password":
            os.write(write_fd, ssh_password(cfg, host).encode("utf-8") + b"\n")
    finally:
        os.close(write_fd)

    archive_file = tempfile.NamedTemporaryFile(
        prefix=f"tee-tls-{host}-{run_id_value}-", suffix=".tar", delete=False
    )
    archive_path = Path(archive_file.name)
    proc: subprocess.Popen[bytes] | None = None
    try:
        try:
            proc = subprocess.Popen(
                _archive_stream_argv(cfg, host, run_id_value, read_fd),
                stdout=archive_file,
                stderr=subprocess.PIPE,
                pass_fds=(read_fd,),
            )
        finally:
            os.close(read_fd)
            archive_file.close()

        try:
            _, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            proc.terminate()
            try:
                _, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, stderr = proc.communicate(timeout=5)
            detail = stderr.decode("utf-8", errors="replace").strip() if stderr else ""
            raise OrchestratorError(
                f"{host} run archive transfer timed out after {timeout} seconds"
                + (f": {detail}" if detail else "")
            ) from exc

        if proc.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace").strip() if stderr else ""
            raise OrchestratorError(
                f"{host} run archive transfer failed with exit status {proc.returncode}"
                + (f": {detail}" if detail else "")
            )
        archive_size = archive_path.stat().st_size
        if archive_size == 0:
            raise OrchestratorError(f"{host} returned an empty run archive")
        digest = sha256_file(archive_path)
        extracted = _safe_extract_tar(archive_path, local_path)
        return {
            "host": host,
            "run_id": run_id_value,
            "archive_bytes": archive_size,
            "archive_sha256": digest,
            **extracted,
            "collected_utc": utc_iso_ns(),
            "method": "agent-tar-stream-over-ssh",
        }
    finally:
        if proc is None:
            try:
                os.close(read_fd)
            except OSError:
                pass
        archive_file.close()
        archive_path.unlink(missing_ok=True)

def read_kv_config(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    with path.open("r", encoding="utf-8") as fh:
        for number, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise OrchestratorError(f"invalid key=value line in {path}:{number}")
            key, value = line.split("=", 1)
            key = key.strip()
            if not key or key in values:
                raise OrchestratorError(f"invalid or duplicate key in {path}:{number}: {key!r}")
            # Both bundled C parsers treat an inline '#' as the beginning of a
            # comment after splitting key=value.
            values[key] = value.split("#", 1)[0].strip()
    return values


def expected_tls_profile(cfg: CampaignConfig) -> dict[str, str]:
    return {
        "tls.server_name": str(cfg.get("experiment.server_name")),
        "tls.verify_peer": "true",
        "tls.verify_hostname": "false",
        "tls.ciphersuite": str(cfg.get("experiment.tls_ciphersuite", "TLS_AES_128_GCM_SHA256", False)),
        "tls.group": str(cfg.get("experiment.tls_group", "P-256", False)),
        "tls.signature_algorithm": str(cfg.get("experiment.tls_signature_algorithm", "ecdsa_secp256r1_sha256", False)),
    }


def validate_reference_configuration(cfg: CampaignConfig) -> list[str]:
    errors: list[str] = []
    config_path = cfg.local_path("reference.config")
    try:
        values = read_kv_config(config_path)
    except (OSError, OrchestratorError) as exc:
        return [f"cannot read reference configuration: {exc}"]
    for key, expected in expected_tls_profile(cfg).items():
        actual = values.get(key)
        if actual != expected:
            errors.append(f"reference config {key}={actual!r}, expected {expected!r}")
    expected_payload = str(cfg.get("experiment.payload_size"))
    if values.get("payload.size_bytes") != expected_payload:
        errors.append(
            f"reference config payload.size_bytes={values.get('payload.size_bytes')!r}, expected {expected_payload!r}"
        )
    if values.get("run.probe_interval_ms") != str(cfg.get("experiment.reference_probe_interval_ms", 1000, False)):
        errors.append(
            "reference config run.probe_interval_ms does not match experiment.reference_probe_interval_ms"
        )
    fixed_reference = {
        "tls.strict_shutdown": bool_text(profile_value(cfg, "reference", "strict_shutdown", REFERENCE_PROFILE_DEFAULTS)),
        "timeouts.tcp_connect_ms": str(profile_value(cfg, "reference", "tcp_connect_timeout_ms", REFERENCE_PROFILE_DEFAULTS)),
        "timeouts.tls_handshake_ms": str(profile_value(cfg, "reference", "tls_handshake_timeout_ms", REFERENCE_PROFILE_DEFAULTS)),
        "timeouts.io_ms": str(profile_value(cfg, "reference", "io_timeout_ms", REFERENCE_PROFILE_DEFAULTS)),
        "payload.mode": str(profile_value(cfg, "reference", "payload_mode", REFERENCE_PROFILE_DEFAULTS)),
        "payload.pattern_hex": str(profile_value(cfg, "reference", "payload_pattern_hex", REFERENCE_PROFILE_DEFAULTS)),
        "payload.seed": str(profile_value(cfg, "reference", "payload_seed", REFERENCE_PROFILE_DEFAULTS)),
        "resumption.session_policy": str(profile_value(cfg, "reference", "resumption_policy", REFERENCE_PROFILE_DEFAULTS)),
        "socket.tcp_nodelay": bool_text(profile_value(cfg, "reference", "tcp_nodelay", REFERENCE_PROFILE_DEFAULTS)),
        "record.reconnect_on_failure": bool_text(profile_value(cfg, "reference", "record_reconnect_on_failure", REFERENCE_PROFILE_DEFAULTS)),
        "record.reconnect_backoff_ms": str(profile_value(cfg, "reference", "record_reconnect_backoff_ms", REFERENCE_PROFILE_DEFAULTS)),
        "output.csv_prefix": str(profile_value(cfg, "reference", "output_csv_prefix", REFERENCE_PROFILE_DEFAULTS)),
        "output.stdout_progress": bool_text(profile_value(cfg, "reference", "stdout_progress", REFERENCE_PROFILE_DEFAULTS)),
    }
    for key, expected in fixed_reference.items():
        actual = values.get(key)
        if actual != expected:
            errors.append(f"reference config {key}={actual!r}, expected {expected!r}")
    ca_value = values.get("tls.ca_file", "")
    if not ca_value:
        errors.append("reference config tls.ca_file is missing or empty")
    else:
        ca_path = Path(os.path.expanduser(ca_value))
        if not ca_path.is_absolute():
            ca_path = (config_path.parent / ca_path).resolve()
        else:
            ca_path = ca_path.resolve()
        if ca_path != cfg.local_path("reference.ca_file"):
            errors.append(
                f"reference config tls.ca_file resolves to {ca_path}, expected {cfg.local_path('reference.ca_file')}"
            )
    return errors

def validate_config(cfg: CampaignConfig) -> list[str]:
    errors: list[str] = []
    required = [
        "repository.root", "repository.results_root", "repository.state_root",
        "experiment.data_subnet", "experiment.control_subnet", "experiment.dut_address",
        "experiment.dut_mac", "experiment.tls_port", "experiment.server_name",
        "reference.data_interface", "reference.data_address", "reference.control_interface",
        "reference.control_address", "reference.binary", "reference.config", "reference.ca_file",
        "dut.ssh_target", "dut.agent", "dut.run_root",
        "dut.data_interface", "dut.data_address", "dut.control_interface",
        "dut.control_address", "dut.server_cpu",
        "loadgen.ssh_target", "loadgen.sudo_password",
        "loadgen.ssh_user", "loadgen.agent", "loadgen.project_root",
        "loadgen.run_root", "loadgen.data_interface", "loadgen.data_address",
        "loadgen.control_interface", "loadgen.control_address", "loadgen.pci_address",
        "loadgen.posix_binary", "loadgen.fstack_binary", "loadgen.generator_config",
        "loadgen.fstack_config", "loadgen.ca_file", "loadgen.kernel_driver",
        "loadgen.openssl_lib", "loadgen.openssl_modules", "loadgen.iperf3",
        "dut.agent_config", "dut.server_cert", "dut.server_key", "dut.iperf3",
        "dut.server", "dut.scenario_binaries", "iperf", "defaults.generator",
        "ssh.options",
    ]
    for key in required:
        try:
            value = cfg.get(key)
            if isinstance(value, str) and PLACEHOLDER.search(value):
                errors.append(f"placeholder remains: {key}")
        except OrchestratorError as exc:
            errors.append(str(exc))
    try:
        if cfg.path.stat().st_mode & 0o077:
            errors.append(f"private campaign configuration permissions are too broad; use chmod 0600: {cfg.path}")
    except OSError as exc:
        errors.append(f"cannot inspect campaign configuration permissions: {exc}")
    for host in ("dut", "loadgen"):
        host_options = cfg.get(f"{host}.ssh_options", [], required=False)
        if not isinstance(host_options, list):
            errors.append(f"{host}.ssh_options must be a TOML array")
        try:
            if ssh_auth_mode(cfg, host) == "password":
                ssh_password(cfg, host)
        except OrchestratorError as exc:
            errors.append(str(exc))
    try:
        loadgen_sudo_password(cfg)
    except OrchestratorError as exc:
        errors.append(str(exc))
    ssh_global_options = cfg.get("ssh.options", [], required=False)
    if not isinstance(ssh_global_options, list):
        errors.append("ssh.options must be a TOML array")
    try:
        data_net = ipaddress.ip_network(str(cfg.get("experiment.data_subnet")))
        control_net = ipaddress.ip_network(str(cfg.get("experiment.control_subnet")))
        if data_net.version != 4 or control_net.version != 4:
            errors.append("experiment data/control subnets must be IPv4 networks")
        if data_net.overlaps(control_net):
            errors.append("experiment data and control subnets must not overlap")
        for key in ("experiment.dut_address", "reference.data_address", "loadgen.data_address", "dut.data_address"):
            if ipaddress.ip_address(str(cfg.get(key))) not in data_net:
                errors.append(f"{key} is outside experiment.data_subnet")
        for key in ("reference.control_address", "loadgen.control_address", "dut.control_address"):
            if ipaddress.ip_address(str(cfg.get(key))) not in control_net:
                errors.append(f"{key} is outside experiment.control_subnet")
    except (ValueError, OrchestratorError) as exc:
        errors.append(f"network configuration: {exc}")
    try:
        data_addresses = {
            str(cfg.get("reference.data_address")),
            str(cfg.get("loadgen.data_address")),
            str(cfg.get("dut.data_address")),
        }
        if len(data_addresses) != 3:
            errors.append("reference, load-generator and DUT data addresses must be distinct")
        control_addresses = {
            str(cfg.get("reference.control_address")),
            str(cfg.get("loadgen.control_address")),
            str(cfg.get("dut.control_address")),
        }
        if len(control_addresses) != 3:
            errors.append("reference, load-generator and DUT control addresses must be distinct")
    except OrchestratorError:
        pass
    try:
        mac = str(cfg.get("experiment.dut_mac"))
        if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac) is None:
            errors.append("experiment.dut_mac must use six colon-separated hexadecimal octets")
    except OrchestratorError:
        pass
    if int(cfg.get("dut.server_cpu", -1, False)) != 1:
        errors.append("dut.server_cpu must remain 1 for the frozen experiment allocation")
    binaries = cfg.get("dut.scenario_binaries")
    if not isinstance(binaries, dict) or set(binaries) != SCENARIOS:
        errors.append("[dut.scenario_binaries] must contain exactly A, B, C, D and E")
    for key in ("experiment.payload_size", "experiment.tls_port", "experiment.mtu",
                "experiment.clock_samples", "experiment.process_grace_s"):
        try:
            if int(cfg.get(key)) <= 0:
                errors.append(f"{key} must be positive")
        except (TypeError, ValueError, OrchestratorError):
            errors.append(f"{key} must be an integer")
    try:
        if int(cfg.get("experiment.mtu")) != 1500:
            errors.append("experiment.mtu must remain 1500 for the frozen campaign profile")
    except (TypeError, ValueError, OrchestratorError):
        pass
    try:
        if float(cfg.get("experiment.transfer_timeout_s", 300, False)) <= 0:
            errors.append("experiment.transfer_timeout_s must be positive")
    except (TypeError, ValueError):
        errors.append("experiment.transfer_timeout_s must be numeric")

    for key in (
        "experiment.pilot_max_offset_ms", "experiment.measurement_max_offset_ms",
        "experiment.max_clock_uncertainty_ms", "experiment.server_ready_timeout_s",
    ):
        try:
            if float(cfg.get(key)) <= 0:
                errors.append(f"{key} must be positive")
        except (TypeError, ValueError, OrchestratorError):
            errors.append(f"{key} must be numeric")

    try:
        tls_port = int(cfg.get("experiment.tls_port"))
        if not 1 <= tls_port <= 65535:
            errors.append("experiment.tls_port must be between 1 and 65535")
    except (TypeError, ValueError, OrchestratorError):
        pass

    try:
        if str(cfg.get("experiment.dut_address")) != str(cfg.get("dut.data_address")):
            errors.append("experiment.dut_address must equal dut.data_address")
    except OrchestratorError:
        pass

    try:
        server = cfg.get("dut.server")
        required_server = {
            "max_payload", "listen_backlog", "max_connections",
            "handshake_timeout_ms", "idle_timeout_ms", "summary_interval_ms",
        }
        if not isinstance(server, dict):
            errors.append("[dut.server] must be a TOML table")
        else:
            missing_server = sorted(required_server - set(server))
            if missing_server:
                errors.append("[dut.server] missing keys: " + ", ".join(missing_server))
            for key in sorted(required_server & set(server)):
                try:
                    if int(server[key]) <= 0:
                        errors.append(f"dut.server.{key} must be positive")
                except (TypeError, ValueError):
                    errors.append(f"dut.server.{key} must be an integer")
            if "max_payload" in server and int(cfg.get("experiment.payload_size")) > int(server["max_payload"]):
                errors.append("experiment.payload_size exceeds dut.server.max_payload")
    except (OrchestratorError, TypeError, ValueError):
        pass

    try:
        iperf = cfg.get("iperf")
        required_iperf = {"port", "duration_s", "parallel_streams", "udp_enabled", "udp_rate", "server_ready_wait_s"}
        if not isinstance(iperf, dict):
            errors.append("[iperf] must be a TOML table")
        else:
            missing_iperf = sorted(required_iperf - set(iperf))
            if missing_iperf:
                errors.append("[iperf] missing keys: " + ", ".join(missing_iperf))
            if "port" in iperf and not 1 <= int(iperf["port"]) <= 65535:
                errors.append("iperf.port must be between 1 and 65535")
            for key in ("duration_s", "parallel_streams"):
                if key in iperf and int(iperf[key]) <= 0:
                    errors.append(f"iperf.{key} must be positive")
            if "server_ready_wait_s" in iperf and float(iperf["server_ready_wait_s"]) < 0:
                errors.append("iperf.server_ready_wait_s must be non-negative")
            if "udp_enabled" in iperf and not isinstance(iperf["udp_enabled"], bool):
                errors.append("iperf.udp_enabled must be true or false")
            if "udp_rate" in iperf and not re.fullmatch(r"[0-9]+(?:[.][0-9]+)?[KMG]?", str(iperf["udp_rate"])):
                errors.append("iperf.udp_rate must be an iperf rate such as 950M")
    except (OrchestratorError, TypeError, ValueError):
        errors.append("invalid numeric value in [iperf]")

    try:
        defaults = cfg.get("defaults.generator")
        if not isinstance(defaults, dict):
            errors.append("[defaults.generator] must be a TOML table")
        else:
            for key, allowed in (("backend", BACKENDS), ("workload", WORKLOADS), ("mode", MODES)):
                if defaults.get(key) not in allowed:
                    errors.append(f"defaults.generator.{key} is invalid")
            for key in ("rate", "max_inflight", "record_connections"):
                try:
                    if float(defaults.get(key, 0)) <= 0:
                        errors.append(f"defaults.generator.{key} must be positive")
                except (TypeError, ValueError):
                    errors.append(f"defaults.generator.{key} must be numeric")
    except OrchestratorError:
        pass

    for section, defaults in (
        ("reference", REFERENCE_PROFILE_DEFAULTS),
        ("loadgen", LOADGEN_PROFILE_DEFAULTS),
    ):
        table = cfg.get(f"{section}.profile", {}, required=False)
        if not isinstance(table, dict):
            errors.append(f"[{section}.profile] must be a TOML table")
            continue
        unknown = sorted(set(table) - set(defaults))
        if unknown:
            errors.append(f"[{section}.profile] unknown keys: {', '.join(unknown)}")
        for key, default in defaults.items():
            value = table.get(key, default)
            if isinstance(default, bool):
                if not isinstance(value, bool):
                    errors.append(f"{section}.profile.{key} must be true or false")
            elif isinstance(default, int):
                minimum = 0 if key == "fstack_proc_id" else 1
                if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                    qualifier = "a non-negative integer" if minimum == 0 else "a positive integer"
                    errors.append(f"{section}.profile.{key} must be {qualifier}")
            elif not isinstance(value, str) or not value:
                errors.append(f"{section}.profile.{key} must be a non-empty string")

    try:
        ref_policy = str(profile_value(cfg, "reference", "resumption_policy", REFERENCE_PROFILE_DEFAULTS))
        if ref_policy not in {"reuse_seed", "chain"}:
            errors.append("reference.profile.resumption_policy must be reuse_seed or chain")
        generator_policy = str(profile_value(cfg, "loadgen", "resumption_policy", LOADGEN_PROFILE_DEFAULTS))
        if generator_policy not in {"reuse_seed", "fresh_pool"}:
            errors.append("loadgen.profile.resumption_policy must be reuse_seed or fresh_pool")
        if str(profile_value(cfg, "loadgen", "network_netmask", LOADGEN_PROFILE_DEFAULTS)) != "255.255.255.0":
            errors.append("loadgen.profile.network_netmask must remain 255.255.255.0 for the /24 data network")
        pending_releases = profile_value(cfg, "loadgen", "record_max_pending_releases", LOADGEN_PROFILE_DEFAULTS)
        if isinstance(pending_releases, bool) or not isinstance(pending_releases, int) or pending_releases <= 0:
            errors.append("loadgen.profile.record_max_pending_releases must be a positive integer")
        for section, key, defaults in (
            ("reference", "payload_pattern_hex", REFERENCE_PROFILE_DEFAULTS),
            ("loadgen", "payload_pattern_hex", LOADGEN_PROFILE_DEFAULTS),
        ):
            pattern = str(profile_value(cfg, section, key, defaults))
            if re.fullmatch(r"[0-9A-Fa-f]{2}", pattern) is None:
                errors.append(f"{section}.profile.{key} must be exactly one hexadecimal byte")
        csv_prefix = str(profile_value(cfg, "reference", "output_csv_prefix", REFERENCE_PROFILE_DEFAULTS))
        if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", csv_prefix) is None:
            errors.append("reference.profile.output_csv_prefix must contain only A-Z, a-z, 0-9, dot, underscore or hyphen")
    except OrchestratorError:
        pass

    for key in (
        "dut.agent", "dut.agent_config", "dut.run_root", "dut.server_cert", "dut.server_key",
        "dut.iperf3", "loadgen.agent", "loadgen.agent_config", "loadgen.project_root",
        "loadgen.run_root", "loadgen.posix_binary", "loadgen.fstack_binary",
        "loadgen.generator_config", "loadgen.fstack_config", "loadgen.ca_file",
        "loadgen.openssl_lib", "loadgen.openssl_modules", "loadgen.iperf3",
    ):
        try:
            if not str(cfg.get(key)).startswith("/"):
                errors.append(f"{key} must be an absolute remote path")
        except OrchestratorError:
            pass

    try:
        target = str(cfg.get("loadgen.ssh_target"))
        configured_user = str(cfg.get("loadgen.ssh_user"))
        if "@" in target and target.split("@", 1)[0] != configured_user:
            errors.append("loadgen.ssh_user must match the user in loadgen.ssh_target")
    except OrchestratorError:
        pass

    return errors

def shell_assignment(name: str, value: Any) -> str:
    return f"{name}={shlex.quote(str(value))}\n"


def render_agent_configs(cfg: CampaignConfig, output: Path) -> tuple[Path, Path]:
    errors = validate_config(cfg)
    if errors:
        raise OrchestratorError("configuration invalid:\n- " + "\n- ".join(errors))
    output.mkdir(parents=True, exist_ok=True)
    server = cfg.get("dut.server")
    bins = cfg.get("dut.scenario_binaries")
    dut_values = {
        "RUN_ROOT": cfg.get("dut.run_root"), "DATA_INTERFACE": cfg.get("dut.data_interface"),
        "DATA_ADDRESS": cfg.get("dut.data_address"), "CONTROL_INTERFACE": cfg.get("dut.control_interface"),
        "CONTROL_ADDRESS": cfg.get("dut.control_address"), "TLS_PORT": cfg.get("experiment.tls_port"),
        "MTU": cfg.get("experiment.mtu"),
        "SERVER_CPU": cfg.get("dut.server_cpu"), "SERVER_CERT": cfg.get("dut.server_cert"),
        "SERVER_KEY": cfg.get("dut.server_key"), "IPERF3": cfg.get("dut.iperf3"),
        "MAX_PAYLOAD": server["max_payload"], "LISTEN_BACKLOG": server["listen_backlog"],
        "MAX_CONNECTIONS": server["max_connections"], "HANDSHAKE_TIMEOUT_MS": server["handshake_timeout_ms"],
        "IDLE_TIMEOUT_MS": server["idle_timeout_ms"], "SUMMARY_INTERVAL_MS": server["summary_interval_ms"],
        **{f"SCENARIO_{s}_BINARY": bins[s] for s in sorted(SCENARIOS)},
    }
    dut_path = output / "dut-agent.conf"
    dut_path.write_text("# Generated; install root-owned mode 0600.\n" + "".join(shell_assignment(k, v) for k, v in dut_values.items()), encoding="utf-8")

    user = str(cfg.get("loadgen.ssh_user"))
    load_values = {
        "RUN_OWNER": user, "RUN_GROUP": "auto", "PROJECT_ROOT": cfg.get("loadgen.project_root"),
        "RUN_ROOT": cfg.get("loadgen.run_root"), "DATA_INTERFACE": cfg.get("loadgen.data_interface"),
        "DATA_ADDRESS": cfg.get("loadgen.data_address"), "CONTROL_INTERFACE": cfg.get("loadgen.control_interface"),
        "CONTROL_ADDRESS": cfg.get("loadgen.control_address"), "PCI_ADDRESS": cfg.get("loadgen.pci_address"),
        "KERNEL_DRIVER": cfg.get("loadgen.kernel_driver"), "DUT_ADDRESS": cfg.get("experiment.dut_address"),
        "TLS_PORT": cfg.get("experiment.tls_port"), "IPERF_PORT": cfg.get("iperf.port"),
        "POSIX_BINARY": cfg.get("loadgen.posix_binary"), "FSTACK_BINARY": cfg.get("loadgen.fstack_binary"),
        "GENERATOR_CONFIG": cfg.get("loadgen.generator_config"), "FSTACK_CONFIG": cfg.get("loadgen.fstack_config"),
        "CA_FILE": cfg.get("loadgen.ca_file"), "OPENSSL_LIB": cfg.get("loadgen.openssl_lib"),
        "OPENSSL_MODULES": cfg.get("loadgen.openssl_modules"),
        "SCHEDULED_EXEC": "/usr/local/libexec/tee-tls-orchestrator/scheduled_exec.py",
        "IPERF3": cfg.get("loadgen.iperf3"),
        "DUT_MAC": cfg.get("experiment.dut_mac"),
        "SERVER_NAME": cfg.get("experiment.server_name"),
        "PAYLOAD_SIZE": cfg.get("experiment.payload_size"),
        "MTU": cfg.get("experiment.mtu"),
        "TLS_CIPHERSUITE": cfg.get("experiment.tls_ciphersuite", "TLS_AES_128_GCM_SHA256", False),
        "TLS_GROUP": cfg.get("experiment.tls_group", "P-256", False),
        "TLS_SIGNATURE_ALGORITHM": cfg.get("experiment.tls_signature_algorithm", "ecdsa_secp256r1_sha256", False),
        "EXPECTED_GENERATOR_VERSION": "0.1.5",
        "EXPECTED_NETWORK_NETMASK": profile_value(cfg, "loadgen", "network_netmask", LOADGEN_PROFILE_DEFAULTS),
        "EXPECTED_TCP_NODELAY": bool_text(profile_value(cfg, "loadgen", "tcp_nodelay", LOADGEN_PROFILE_DEFAULTS)),
        "EXPECTED_MAX_RELEASE_BURST": profile_value(cfg, "loadgen", "max_release_burst", LOADGEN_PROFILE_DEFAULTS),
        "EXPECTED_DRAIN_TIMEOUT_MS": profile_value(cfg, "loadgen", "drain_timeout_ms", LOADGEN_PROFILE_DEFAULTS),
        "EXPECTED_TCP_CONNECT_TIMEOUT_MS": profile_value(cfg, "loadgen", "tcp_connect_timeout_ms", LOADGEN_PROFILE_DEFAULTS),
        "EXPECTED_TLS_HANDSHAKE_TIMEOUT_MS": profile_value(cfg, "loadgen", "tls_handshake_timeout_ms", LOADGEN_PROFILE_DEFAULTS),
        "EXPECTED_IO_TIMEOUT_MS": profile_value(cfg, "loadgen", "io_timeout_ms", LOADGEN_PROFILE_DEFAULTS),
        "EXPECTED_PAYLOAD_PATTERN_HEX": profile_value(cfg, "loadgen", "payload_pattern_hex", LOADGEN_PROFILE_DEFAULTS),
        "EXPECTED_FULL_ECHO_AFTER_HANDSHAKE": bool_text(profile_value(cfg, "loadgen", "full_echo_after_handshake", LOADGEN_PROFILE_DEFAULTS)),
        "EXPECTED_RESUMPTION_POLICY": profile_value(cfg, "loadgen", "resumption_policy", LOADGEN_PROFILE_DEFAULTS),
        "EXPECTED_RESUMPTION_POOL_SIZE": profile_value(cfg, "loadgen", "resumption_pool_size", LOADGEN_PROFILE_DEFAULTS),
        "EXPECTED_WAIT_FOR_FRESH_TICKET": bool_text(profile_value(cfg, "loadgen", "wait_for_fresh_ticket", LOADGEN_PROFILE_DEFAULTS)),
        "EXPECTED_RECORD_MAX_PENDING_RELEASES": profile_value(cfg, "loadgen", "record_max_pending_releases", LOADGEN_PROFILE_DEFAULTS),
        "EXPECTED_RECORD_RECONNECT": bool_text(profile_value(cfg, "loadgen", "record_reconnect", LOADGEN_PROFILE_DEFAULTS)),
        "EXPECTED_RECORD_RECONNECT_BACKOFF_MS": profile_value(cfg, "loadgen", "record_reconnect_backoff_ms", LOADGEN_PROFILE_DEFAULTS),
        "EXPECTED_STDOUT_PROGRESS": bool_text(profile_value(cfg, "loadgen", "stdout_progress", LOADGEN_PROFILE_DEFAULTS)),
        "EXPECTED_FSTACK_PROC_ID": profile_value(cfg, "loadgen", "fstack_proc_id", LOADGEN_PROFILE_DEFAULTS),
    }
    load_path = output / "loadgen-agent.conf"
    load_path.write_text("# Generated; install root-owned mode 0600.\n" + "".join(shell_assignment(k, v) for k, v in load_values.items()), encoding="utf-8")
    return dut_path, load_path


def local_network_check(cfg: CampaignConfig) -> list[str]:
    errors: list[str] = []
    iface = str(cfg.get("reference.data_interface")); addr = str(cfg.get("reference.data_address")); dut = str(cfg.get("experiment.dut_address"))
    cp = execute(["ip", "-o", "-4", "addr", "show", "dev", iface], check=False)
    if cp.returncode != 0 or f" {addr}/" not in cp.stdout:
        errors.append(f"reference data address {addr} not present on {iface}")
    cp = execute(["ip", "link", "show", "dev", iface], check=False)
    expected_mtu = int(cfg.get("experiment.mtu"))
    if cp.returncode != 0 or f"mtu {expected_mtu}" not in cp.stdout:
        errors.append(f"reference data interface {iface} does not report MTU {expected_mtu}")
    cp = execute(["ip", "route", "get", dut], check=False)
    if cp.returncode != 0 or f"dev {iface}" not in cp.stdout or f"src {addr}" not in cp.stdout:
        errors.append(f"route to DUT does not use {iface} source {addr}: {cp.stdout.strip()}")
    cif = str(cfg.get("reference.control_interface")); caddr = str(cfg.get("reference.control_address"))
    cp = execute(["ip", "-o", "-4", "addr", "show", "dev", cif], check=False)
    if cp.returncode != 0 or f" {caddr}/" not in cp.stdout:
        errors.append(f"reference control address {caddr} not present on {cif}")
    for host_key in ("dut.control_address", "loadgen.control_address"):
        target = str(cfg.get(host_key))
        cp = execute(["ip", "route", "get", target], check=False)
        if cp.returncode != 0 or f"dev {cif}" not in cp.stdout or f"src {caddr}" not in cp.stdout:
            errors.append(
                f"route to {target} does not use control interface {cif} source {caddr}: {cp.stdout.strip()}"
            )
    return errors


def _clock_probe_argv(cfg: CampaignConfig, host: str, password_fd: int) -> list[str]:
    if host == "dut":
        remote = [str(cfg.get("dut.agent")), "clock-probe"]
    elif host == "loadgen":
        remote = ["sudo", "-n", str(cfg.get("loadgen.agent")), "clock-probe"]
    else:
        raise ValueError(host)
    command = [*ssh_base(cfg, host), shlex.join(remote)]
    if ssh_auth_mode(cfg, host) == "key":
        return command
    sshpass = find_executable("sshpass")
    if sshpass is None:
        raise OrchestratorError("sshpass is missing on the reference-client host")
    return [sshpass, "-d", str(password_fd), *command]


def _read_clock_probe_line(
    proc: subprocess.Popen[str], host: str, timeout_s: float
) -> str:
    if proc.stdout is None:
        raise OrchestratorError(f"{host} clock probe has no stdout pipe")
    ready, _, _ = select.select([proc.stdout], [], [], timeout_s)
    if not ready:
        raise OrchestratorError(
            f"{host} clock probe timed out after {timeout_s:.1f} s"
        )
    line = proc.stdout.readline()
    if line == "":
        stderr = proc.stderr.read().strip() if proc.stderr is not None else ""
        raise OrchestratorError(
            f"{host} clock probe closed unexpectedly"
            + (f": stderr={stderr!r}" if stderr else "")
        )
    return line.rstrip("\r\n")


def measure_clock(cfg: CampaignConfig, host: str) -> dict[str, Any]:
    """Measure relative clock offset over one already-authenticated SSH channel.

    Authentication and remote-shell startup are completed before timing begins.
    Each sample is then a request/reply exchange on the established channel, so
    half of that exchange's RTT is a meaningful uncertainty bound. The previous
    implementation included password authentication in every sample and could
    therefore report hundreds of milliseconds of artificial uncertainty.
    """
    sample_count = int(cfg.get("experiment.clock_samples"))
    read_fd, write_fd = os.pipe()
    try:
        if ssh_auth_mode(cfg, host) == "password":
            os.write(write_fd, ssh_password(cfg, host).encode("utf-8") + b"\n")
    finally:
        os.close(write_fd)

    proc: subprocess.Popen[str] | None = None
    samples: list[tuple[float, float]] = []
    try:
        proc = subprocess.Popen(
            _clock_probe_argv(cfg, host, read_fd),
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            pass_fds=(read_fd,),
        )
    finally:
        os.close(read_fd)

    try:
        if _read_clock_probe_line(proc, host, 15.0) != "READY":
            raise OrchestratorError(f"{host} clock probe did not report READY")
        if proc.stdin is None:
            raise OrchestratorError(f"{host} clock probe has no stdin pipe")

        for probe_id in range(sample_count):
            t0 = time.time_ns()
            proc.stdin.write(f"{probe_id}\n")
            proc.stdin.flush()
            line = _read_clock_probe_line(proc, host, 3.0)
            t1 = time.time_ns()
            match = re.fullmatch(r"([0-9]+) ([0-9]{16,20})", line)
            if match is None or int(match.group(1)) != probe_id:
                raise OrchestratorError(
                    f"cannot parse {host} clock probe response: {line!r}"
                )
            remote_ns = int(match.group(2))
            midpoint = (t0 + t1) / 2
            samples.append(
                ((remote_ns - midpoint) / 1_000_000, (t1 - t0) / 2_000_000)
            )

        proc.stdin.close()
        rc = proc.wait(timeout=5)
        stderr = proc.stderr.read().strip() if proc.stderr is not None else ""
        if rc != 0:
            raise OrchestratorError(
                f"{host} clock probe exited with status {rc}"
                + (f": stderr={stderr!r}" if stderr else "")
            )
    except Exception:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        raise

    best = min(samples, key=lambda x: x[1])
    return {
        "host": host,
        "offset_ms": best[0],
        "uncertainty_ms": best[1],
        "round_trip_ms": best[1] * 2,
        "samples": [
            {
                "offset_ms": offset,
                "uncertainty_ms": uncertainty,
                "round_trip_ms": uncertainty * 2,
            }
            for offset, uncertainty in samples
        ],
        "measured_utc": utc_iso_ns(),
        "method": "established-ssh-request-reply",
    }


def clock_preflight(cfg: CampaignConfig, profile: str) -> dict[str, Any]:
    threshold = float(cfg.get("experiment.pilot_max_offset_ms" if profile == "pilot-debug" else "experiment.measurement_max_offset_ms"))
    max_unc = float(cfg.get("experiment.max_clock_uncertainty_ms"))
    results = {host: measure_clock(cfg, host) for host in ("dut", "loadgen")}
    errors: list[str] = []
    for host, result in results.items():
        if abs(result["offset_ms"]) > threshold:
            errors.append(f"{host} absolute clock offset {result['offset_ms']:.3f} ms exceeds {threshold:.3f} ms")
        if result["uncertainty_ms"] > max_unc:
            errors.append(f"{host} clock-measurement uncertainty {result['uncertainty_ms']:.3f} ms exceeds {max_unc:.3f} ms")
    return {"profile": profile, "threshold_ms": threshold, "max_uncertainty_ms": max_unc, "hosts": results, "errors": errors}


def ssh_authentication_check(cfg: CampaignConfig, host: str) -> subprocess.CompletedProcess[str]:
    return ssh_run(cfg, host, ["/bin/true"], check=False, timeout=12)


def ssh_authentication_error(cfg: CampaignConfig, host: str,
                             cp: subprocess.CompletedProcess[str]) -> str:
    if cp.returncode == 5 and ssh_auth_mode(cfg, host) == "password":
        reason = "the configured SSH password was rejected"
    elif cp.returncode == 6:
        reason = "the remote host key is unknown and was not accepted"
    elif cp.returncode == 7:
        reason = "the remote host key changed"
    else:
        reason = "SSH authentication or transport failed"
    return (
        f"{host} SSH connection failed for {ssh_target(cfg, host)!r}: {reason}; "
        f"{completed_diagnostic(cp)}. The orchestrator runs locally on the Armbian "
        "reference-client host and opens only outbound SSH "
        "connections to the DUT and Ubuntu load generator."
    )


def command_ssh_check(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    errors = validate_config(cfg)
    if errors:
        raise OrchestratorError("configuration invalid:\n- " + "\n- ".join(errors))
    if any(ssh_auth_mode(cfg, h) == "password" for h in ("dut", "loadgen")):
        if find_executable("sshpass") is None:
            raise OrchestratorError("sshpass required for password authentication")
    failures = 0
    hosts = (args.host,) if args.host else ("dut", "loadgen")
    for host in hosts:
        cp = ssh_authentication_check(cfg, host)
        if cp.returncode == 0:
            print(f"{host}: PASS target={ssh_target(cfg, host)} authentication={ssh_auth_mode(cfg, host)}")
        else:
            failures += 1
            print(f"{host}: FAIL", file=sys.stderr)
            print(ssh_authentication_error(cfg, host, cp), file=sys.stderr)
    return 1 if failures else 0


def _write_install_script(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o700)


def command_deploy(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    errors = validate_config(cfg)
    if errors:
        raise OrchestratorError("configuration invalid:\n- " + "\n- ".join(errors))
    needed = ["ssh", "scp"]
    if any(ssh_auth_mode(cfg, h) == "password" for h in ("dut", "loadgen")):
        needed.append("sshpass")
    missing = [name for name in needed if find_executable(name) is None]
    if missing:
        raise OrchestratorError("required local programs missing: " + ", ".join(missing))
    for host in ("dut", "loadgen"):
        cp = ssh_authentication_check(cfg, host)
        if cp.returncode != 0:
            raise OrchestratorError(ssh_authentication_error(cfg, host, cp))

    state = cfg.local_path("repository.state_root") / "rendered-agent-configs"
    dut_conf, load_conf = render_agent_configs(cfg, state)
    root = Path(__file__).resolve().parent

    print(f"Deploying DUT helper to {ssh_target(cfg, 'dut')} ...")
    dut_tmp = remote_temp_directory(cfg, "dut")
    with tempfile.TemporaryDirectory(prefix="tee-tls-dut-deploy-") as local_tmp_raw:
        local_tmp = Path(local_tmp_raw)
        install_script = local_tmp / "install-dut.sh"
        agent = str(cfg.get("dut.agent"))
        agent_conf = str(cfg.get("dut.agent_config"))
        _write_install_script(install_script, f"""#!/bin/sh
set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LANG=C
LC_ALL=C
export PATH LANG LC_ALL
install -d -m 0755 {shlex.quote(str(Path(agent).parent))} {shlex.quote(str(Path(agent_conf).parent))}
install -o root -g root -m 0755 {shlex.quote(dut_tmp + '/tee-tls-dut-agent')} {shlex.quote(agent)}
install -o root -g root -m 0600 {shlex.quote(dut_tmp + '/dut-agent.conf')} {shlex.quote(agent_conf)}
test -x {shlex.quote(agent)}
test -r {shlex.quote(agent_conf)}
rm -rf {shlex.quote(dut_tmp)}
{shlex.quote(agent)} clock-ns >/dev/null
""")
        scp_to(cfg, "dut", [root / "remote/tee-tls-dut-agent", dut_conf, install_script], dut_tmp)
        cp = ssh_run(cfg, "dut", ["/bin/sh", f"{dut_tmp}/install-dut.sh"], check=False, timeout=45)
        if cp.returncode != 0:
            raise OrchestratorError(f"DUT helper deployment failed: {completed_diagnostic(cp)}")

    print(f"Deploying load-generator helper to {ssh_target(cfg, 'loadgen')} ...")
    load_tmp = remote_temp_directory(cfg, "loadgen")
    with tempfile.TemporaryDirectory(prefix="tee-tls-loadgen-deploy-") as local_tmp_raw:
        local_tmp = Path(local_tmp_raw)
        install_script = local_tmp / "install-loadgen.sh"
        agent = str(cfg.get("loadgen.agent"))
        agent_conf = str(cfg.get("loadgen.agent_config"))
        run_user = str(cfg.get("loadgen.ssh_user"))
        _write_install_script(install_script, f"""#!/bin/bash
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LANG=C
export LC_ALL=C
install -d -m 0755 {shlex.quote(str(Path(agent).parent))} {shlex.quote(str(Path(agent_conf).parent))} /usr/local/libexec/tee-tls-orchestrator
install -o root -g root -m 0755 {shlex.quote(load_tmp + '/tee-tls-loadgen-agent')} {shlex.quote(agent)}
install -o root -g root -m 0755 {shlex.quote(load_tmp + '/scheduled_exec.py')} /usr/local/libexec/tee-tls-orchestrator/scheduled_exec.py
install -o root -g root -m 0600 {shlex.quote(load_tmp + '/loadgen-agent.conf')} {shlex.quote(agent_conf)}
printf '%s ALL=(root) NOPASSWD: %s\\n' {shlex.quote(run_user)} {shlex.quote(agent)} > /etc/sudoers.d/tee-tls-loadgen-agent
chmod 0440 /etc/sudoers.d/tee-tls-loadgen-agent
visudo -cf /etc/sudoers.d/tee-tls-loadgen-agent
rm -rf {shlex.quote(load_tmp)}
""")
        scp_to(
            cfg,
            "loadgen",
            [root / "remote/tee-tls-loadgen-agent", root / "orchestration/scheduled_exec.py", load_conf, install_script],
            load_tmp,
        )
        cp = ssh_run(
            cfg,
            "loadgen",
            ["/usr/bin/sudo", "-S", "-p", "", "/bin/bash", f"{load_tmp}/install-loadgen.sh"],
            check=False,
            timeout=60,
            input_text=loadgen_sudo_password(cfg) + "\n",
        )
        if cp.returncode != 0:
            raise OrchestratorError(f"load-generator helper deployment failed: {completed_diagnostic(cp)}")

    print("Verifying DUT helper ...")
    cp = remote_agent(cfg, "dut", ["clock-ns"], check=False, timeout=15)
    if cp.returncode != 0:
        raise OrchestratorError(f"DUT helper verification failed: {completed_diagnostic(cp)}")
    print("Verifying noninteractive restricted sudo on load generator ...")
    cp = remote_agent(cfg, "loadgen", ["clock-ns"], check=False, timeout=15)
    if cp.returncode != 0:
        raise OrchestratorError(f"load-generator helper verification failed: {completed_diagnostic(cp)}")
    print("Remote helper deployment: PASS")
    return 0

def command_init(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    errors = validate_config(cfg)
    errors.extend(local_network_check(cfg))
    for path_key in ("reference.binary", "reference.config", "reference.ca_file"):
        path = cfg.local_path(path_key)
        if not path.exists(): errors.append(f"local file missing: {path_key} -> {path}")
    if all(cfg.local_path(key).exists() for key in ("reference.binary", "reference.config", "reference.ca_file")):
        errors.extend(validate_reference_configuration(cfg))
        ref_help = execute([str(cfg.local_path("reference.binary")), "--help"], check=False)
        if ref_help.returncode != 0:
            errors.append(f"reference binary --help failed: {completed_diagnostic(ref_help)}")
        else:
            for option in ("--config", "--scenario", "--workload", "--repetition", "--server", "--port", "--source-address", "--interface", "--output-dir", "--run-id", "--duration-s", "--probe-interval-ms", "--payload-size"):
                if option not in ref_help.stdout:
                    errors.append(f"reference binary does not advertise required option {option}")
    ref_binary = cfg.local_path("reference.binary")
    if ref_binary.exists() and os.geteuid() != 0:
        getcap = find_executable("getcap", ("/usr/sbin/getcap", "/sbin/getcap"))
        if getcap is None:
            errors.append(
                "getcap is unavailable; install libcap2-bin "
                "(the expected Debian-family path is /usr/sbin/getcap)"
            )
        else:
            cp = execute([getcap, str(ref_binary)], check=False)
            if cp.returncode != 0:
                errors.append(
                    f"getcap failed for reference binary {ref_binary}: "
                    f"{completed_diagnostic(cp)}"
                )
            elif "cap_net_raw" not in cp.stdout:
                errors.append(f"reference binary lacks cap_net_raw required by --interface: {ref_binary}")
    needed = ["ssh", "ip"]
    if any(ssh_auth_mode(cfg, h) == "password" for h in ("dut", "loadgen")):
        needed.append("sshpass")
    for program in needed:
        if find_executable(program) is None:
            errors.append(f"required local program missing: {program}")
    auth_ok: dict[str, bool] = {}
    for host in ("dut", "loadgen"):
        try:
            cp = ssh_authentication_check(cfg, host)
            auth_ok[host] = cp.returncode == 0
            if not auth_ok[host]:
                errors.append(ssh_authentication_error(cfg, host, cp))
        except Exception as exc:
            auth_ok[host] = False
            errors.append(f"{host} SSH authentication check failed: {type(exc).__name__}: {exc}")
    for host in ("dut", "loadgen"):
        if not auth_ok.get(host):
            continue
        try:
            cp = remote_agent(
                cfg, host,
                ["preflight", args.backend] if host == "loadgen" else ["preflight"],
                check=False, timeout=20,
            )
            if cp.returncode != 0:
                errors.append(f"{host} preflight failed: {completed_diagnostic(cp)}")
        except Exception as exc:
            errors.append(f"{host} preflight invocation failed: {type(exc).__name__}: {exc}")
    clock = None
    if all(auth_ok.get(host, False) for host in ("dut", "loadgen")):
        try:
            clock = clock_preflight(cfg, args.profile)
            errors.extend(clock["errors"])
        except Exception as exc:
            errors.append(f"clock preflight failed: {exc}")
    else:
        clock = {"skipped": True, "reason": "remote SSH authentication failed"}
    state_root = cfg.local_path("repository.state_root")
    state_root.mkdir(parents=True, exist_ok=True)
    report = {"version": VERSION, "checked_utc": utc_iso_ns(), "backend": args.backend, "profile": args.profile, "clock": clock, "errors": errors}
    atomic_json(state_root / "campaign-init-latest.json", report)
    if errors:
        print("Campaign initialization: FAIL", file=sys.stderr)
        for error in errors: print(f"- {error}", file=sys.stderr)
        return 1
    print("Campaign initialization: PASS")
    if args.functional_check:
        print("Running short Scenario A functional check...")
        ns = argparse.Namespace(**vars(args))
        ns.scenario = "A"; ns.reference_workload = "full-handshake"; ns.reference_duration = 10
        ns.generator_backend = args.backend; ns.generator_workload = "full-handshake"; ns.generator_mode = "benign"; ns.generator_rate = 1.0
        ns.generator_duration = 3; ns.generator_max_inflight = 64; ns.generator_connections = 8
        ns.repetition = 1; ns.pre_generation = 2; ns.start_delay = 10; ns.confirm_flood = False
        return command_tls_run(ns)
    return 0


def poll_dut_server(cfg: CampaignConfig, rid: str, timeout_s: float, require_manifest: bool = False) -> dict[str, str]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, str] = {}
    while time.monotonic() < deadline:
        cp = remote_agent(cfg, "dut", ["server-status", rid], check=False, timeout=10)
        if cp.returncode != 0:
            raise OrchestratorError(
                "DUT server-status failed: " + completed_diagnostic(cp)
            )
        last = parse_kv(cp.stdout)
        if require_manifest and last.get("STATE") == "running" and last.get("MANIFEST_READY") == "1":
            return last
        if require_manifest and last.get("STATE") == "exited":
            raise OrchestratorError(f"DUT server exited before readiness; last={last}")
        if not require_manifest and last.get("STATE") == "exited":
            return last
        time.sleep(0.5)
    raise OrchestratorError(f"DUT server did not reach expected state; last={last}")


def poll_loadgen(cfg: CampaignConfig, rid: str, timeout_s: float) -> dict[str, Any]:
    """Poll only after the reference interval has ended.

    An SSH connection is deliberately not opened every
    half second during the measured interval.  Repeated SSH authentication on
    the load-generator CPU would itself become campaign load.  The caller waits
    for the local reference client first, then uses this bounded post-run poll.
    """
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        cp = remote_agent(cfg, "loadgen", ["run-status", rid], check=False, timeout=10)
        if cp.returncode != 0:
            raise OrchestratorError(
                "load-generator run-status failed: " + completed_diagnostic(cp)
            )
        try: last = json.loads(cp.stdout)
        except json.JSONDecodeError: last = {"state": "unparseable", "stdout": cp.stdout, "stderr": cp.stderr}
        if last.get("state") in {"finished", "failed_before_start", "cancelled_before_start"}: return last
        time.sleep(1.0)
    raise OrchestratorError(f"load generator did not finish; last={last}")


def wait_local_status(status_path: Path, timeout_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        if status_path.exists():
            try: last = json.loads(status_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError): pass
            if last.get("state") in {"finished", "failed_before_start", "cancelled_before_start"}: return last
        time.sleep(0.25)
    raise OrchestratorError(f"local reference client did not finish; last={last}")


def stop_local_wrapper(proc: subprocess.Popen[Any], grace_s: float = 5.0) -> dict[str, Any]:
    """Terminate the scheduled local wrapper and its child process group."""
    if proc.poll() is not None:
        return {"state": "already_exited", "returncode": proc.returncode, "forced": False}
    forced = False
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return {"state": "not_found", "returncode": proc.poll(), "forced": False}
    try:
        proc.wait(timeout=grace_s)
    except subprocess.TimeoutExpired:
        forced = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=grace_s)
    return {"state": "stopped", "returncode": proc.returncode, "forced": forced}


def resolve_tls_defaults(cfg: CampaignConfig, args: argparse.Namespace) -> None:
    """Resolve optional run controls from the private central TOML once."""
    defaults: dict[str, tuple[str, type]] = {
        "reference_duration": ("experiment.reference_duration_s", int),
        "generator_duration": ("experiment.generator_duration_s", int),
        "generator_max_inflight": ("defaults.generator.max_inflight", int),
        "generator_connections": ("defaults.generator.record_connections", int),
        "pre_generation": ("experiment.pre_generation_s", int),
        "start_delay": ("experiment.start_delay_s", int),
    }
    for attr, (key, converter) in defaults.items():
        if getattr(args, attr, None) is None:
            setattr(args, attr, converter(cfg.get(key)))


def make_result_dir(cfg: CampaignConfig, args: argparse.Namespace, rid: str) -> Path:
    rate = str(args.generator_rate).replace(".", "p")
    base = cfg.local_path("repository.results_root")
    path = base / f"scenario_{args.scenario}" / args.reference_workload / args.generator_workload / args.generator_mode / args.generator_backend / f"rate_{rate}" / f"repetition_{args.repetition}" / rid
    path.mkdir(parents=True, exist_ok=False)
    return path


def reference_workdir(cfg: CampaignConfig) -> Path:
    # Relative paths inside reference_client.conf are resolved by the client against cwd.
    return cfg.local_path("reference.config").parent


def reference_command(cfg: CampaignConfig, args: argparse.Namespace, rid: str, output_dir: Path) -> list[str]:
    return [
        str(cfg.local_path("reference.binary")), "--config", str(cfg.local_path("reference.config")),
        "--scenario", args.scenario, "--workload", args.reference_workload,
        "--repetition", str(args.repetition), "--server", str(cfg.get("experiment.dut_address")),
        "--port", str(cfg.get("experiment.tls_port")), "--source-address", str(cfg.get("reference.data_address")),
        "--interface", str(cfg.get("reference.data_interface")), "--output-dir", str(output_dir),
        "--run-id", rid, "--duration-s", str(args.reference_duration),
        "--probe-interval-ms", str(cfg.get("experiment.reference_probe_interval_ms", 1000, False)),
        "--payload-size", str(cfg.get("experiment.payload_size")),
    ]


def validate_run(
    result_dir: Path,
    cfg: CampaignConfig,
    args: argparse.Namespace,
    rid: str,
    ref_status: dict[str, Any],
    gen_status: dict[str, Any],
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    if ref_status.get("state") != "finished":
        errors.append(f"reference process state {ref_status.get('state')!r}, expected 'finished'")
    if int(ref_status.get("exit_code", 1)) != 0:
        errors.append(f"reference exit code {ref_status.get('exit_code')}")
    if gen_status.get("state") != "finished":
        errors.append(f"generator process state {gen_status.get('state')!r}, expected 'finished'")
    if int(gen_status.get("exit_code", 1)) != 0:
        errors.append(f"generator exit code {gen_status.get('exit_code')}")

    expected_interval_ms = int(cfg.get("experiment.reference_probe_interval_ms", 1000, False))
    expected_payload = int(cfg.get("experiment.payload_size"))
    expected_suite = str(cfg.get("experiment.tls_ciphersuite", "TLS_AES_128_GCM_SHA256", False))
    expected_group = str(cfg.get("experiment.tls_group", "P-256", False))
    expected_signature = str(
        cfg.get("experiment.tls_signature_algorithm", "ecdsa_secp256r1_sha256", False)
    )

    ref_meta_files = list((result_dir / "reference").glob("*.metadata.json"))
    ref_csv_files = list((result_dir / "reference").glob("*.csv"))
    if len(ref_meta_files) != 1:
        errors.append(f"expected one reference metadata file, found {len(ref_meta_files)}")
    if len(ref_csv_files) != 1:
        errors.append(f"expected one reference CSV, found {len(ref_csv_files)}")

    if len(ref_meta_files) == 1:
        try:
            meta = json.loads(ref_meta_files[0].read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"cannot parse reference metadata: {exc}")
        else:
            for key, expected in (
                ("run_id", rid),
                ("scenario", args.scenario),
                ("workload", args.reference_workload),
                ("repetition", args.repetition),
                ("configured_duration_s", args.reference_duration),
                ("configured_probe_interval_ms", expected_interval_ms),
                ("payload_size", expected_payload),
                ("expected_tls_version", "TLSv1.3"),
                ("expected_ciphersuite", expected_suite),
                ("expected_group", expected_group),
                ("expected_signature_algorithm", expected_signature),
                ("certificate_verification_enabled", True),
            ):
                if str(meta.get(key)) != str(expected):
                    errors.append(
                        f"reference metadata {key}={meta.get(key)!r}, expected {expected!r}"
                    )

    if len(ref_csv_files) == 1:
        try:
            with ref_csv_files[0].open(newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
        except OSError as exc:
            errors.append(f"cannot read reference CSV: {exc}")
            rows = []
        if not rows:
            errors.append("reference CSV has no rows")
        else:
            for key, expected in (
                ("run_id", rid),
                ("scenario", args.scenario),
                ("workload", args.reference_workload),
                ("repetition", str(args.repetition)),
            ):
                mismatches = sum(str(row.get(key, "")) != str(expected) for row in rows)
                if mismatches:
                    errors.append(f"{mismatches} reference CSV rows have an unexpected {key}")

            scheduled_values: list[int] = []
            for row in rows:
                try:
                    scheduled_values.append(int(row.get("scheduled_elapsed_us", "")))
                except (TypeError, ValueError):
                    errors.append("reference CSV contains a non-numeric scheduled_elapsed_us")
                    break
            if scheduled_values:
                # A busy client may skip release slots, so row count is not a safe
                # duration check.  The final scheduled slot must nevertheless be
                # close to the configured end of the run.
                expected_last_us = max(
                    0,
                    args.reference_duration * 1_000_000
                    - 2 * expected_interval_ms * 1_000,
                )
                if max(scheduled_values) < expected_last_us:
                    errors.append(
                        "reference CSV ended too early: maximum scheduled_elapsed_us "
                        f"{max(scheduled_values)} is below {expected_last_us}"
                    )

            successful = [row for row in rows if row.get("result_code") == "0"]
            if args.reference_workload == "resumption":
                bad = [
                    row for row in successful
                    if row.get("session_reused", "").lower() not in {"true", "1"}
                ]
                if bad:
                    errors.append(
                        f"{len(bad)} successful resumption rows were not marked reused"
                    )
            if args.reference_workload == "full-handshake":
                bad = [
                    row for row in successful
                    if row.get("session_reused", "").lower() in {"true", "1"}
                ]
                if bad:
                    errors.append(
                        f"{len(bad)} successful full-handshake rows were marked reused"
                    )
            bad_payload = [
                row for row in successful
                if row.get("payload_match", "").lower() not in {"true", "1"}
            ]
            if bad_payload:
                errors.append(
                    f"{len(bad_payload)} successful reference rows failed payload comparison"
                )
            accepted_values = {
                "tls_version": {"TLSv1.3"},
                "cipher": {expected_suite},
                # OpenSSL's negotiated-group reporting uses the IANA/OBJ short
                # name on the tested build even though configuration uses P-256.
                "group": (
                    {"P-256", "prime256v1", "secp256r1"}
                    if expected_group == "P-256"
                    else {expected_group}
                ),
            }
            for field, accepted in accepted_values.items():
                bad = [row for row in successful if row.get(field) not in accepted]
                if bad:
                    errors.append(
                        f"{len(bad)} successful reference rows have unexpected {field}"
                    )

    gen_meta_files = list((result_dir / "generator").glob("output/**/generator.metadata.json"))
    gen_stats_files = list((result_dir / "generator").glob("output/**/generator_stats.csv"))
    gen_timeline_files = list((result_dir / "generator").glob("output/**/generator.timeline.json"))
    generator_timeline: dict[str, Any] | None = None
    generator_git_commit: str | None = None
    generator_final_stats: dict[str, str] | None = None
    generator_stats_wall_times: list[int] = []
    if len(gen_meta_files) != 1:
        errors.append(f"expected one generator metadata file, found {len(gen_meta_files)}")
    if len(gen_stats_files) != 1:
        errors.append(f"expected one generator stats file, found {len(gen_stats_files)}")
    if len(gen_timeline_files) != 1:
        errors.append(f"expected one generator timeline file, found {len(gen_timeline_files)}")

    if len(gen_meta_files) == 1:
        try:
            meta = json.loads(gen_meta_files[0].read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"cannot parse generator metadata: {exc}")
        else:
            for key, expected in (
                ("run_id", rid),
                ("scenario", args.scenario),
                ("workload", args.generator_workload),
                ("mode", args.generator_mode),
                ("backend", args.generator_backend),
                ("generator_version", "0.1.5"),
                ("timeline_schema_version", 1),
                ("timeline_file", "generator.timeline.json"),
                ("stats_wall_time_utc_ns", True),
                ("configured_duration_s", args.generator_duration),
                ("configured_max_inflight", args.generator_max_inflight),
                ("payload_size", expected_payload),
                ("record_connections", args.generator_connections),
                ("resumption_policy", str(profile_value(cfg, "loadgen", "resumption_policy", LOADGEN_PROFILE_DEFAULTS))),
                ("resumption_pool_size", int(profile_value(cfg, "loadgen", "resumption_pool_size", LOADGEN_PROFILE_DEFAULTS))),
                ("expected_tls_version", "TLSv1.3"),
                ("expected_ciphersuite", expected_suite),
                ("expected_group", expected_group),
                ("expected_signature_algorithm", expected_signature),
                ("certificate_verification_enabled", True),
            ):
                if str(meta.get(key)) != str(expected):
                    errors.append(
                        f"generator metadata {key}={meta.get(key)!r}, expected {expected!r}"
                    )
            generator_git_commit = str(meta.get("generator_git_commit", ""))
            if re.fullmatch(r"[0-9a-f]{12}", generator_git_commit) is None:
                errors.append(
                    "generator metadata generator_git_commit is missing, dirty, or not a 12-hex commit"
                )
            try:
                configured_rate = float(meta.get("configured_rate_per_s"))
                if abs(configured_rate - float(args.generator_rate)) > max(
                    1e-9, abs(float(args.generator_rate)) * 1e-9
                ):
                    errors.append(
                        "generator metadata configured_rate_per_s="
                        f"{configured_rate!r}, expected {args.generator_rate!r}"
                    )
            except (TypeError, ValueError):
                errors.append("generator metadata configured_rate_per_s is not numeric")

    if len(gen_stats_files) == 1:
        try:
            with gen_stats_files[0].open(newline="", encoding="utf-8") as fh:
                stats = list(csv.DictReader(fh))
        except OSError as exc:
            errors.append(f"cannot read generator stats CSV: {exc}")
            stats = []
        if not stats:
            errors.append("generator stats CSV has no rows")
        else:
            required_stats_fields = {
                "run_id", "scenario", "workload", "mode", "backend",
                "wall_time_utc_ns", "elapsed_s", "phase",
                "local_capacity_drop_total", "tcp_established_total",
                "full_handshake_ok_total", "resumed_handshake_ok_total",
                "app_ok_total",
            }
            missing_stats_fields = sorted(required_stats_fields - set(stats[0]))
            if missing_stats_fields:
                errors.append(
                    "generator stats CSV is missing fields: " + ", ".join(missing_stats_fields)
                )
            for row in stats:
                for key, expected in (
                    ("run_id", rid),
                    ("scenario", args.scenario),
                    ("workload", args.generator_workload),
                    ("mode", args.generator_mode),
                    ("backend", args.generator_backend),
                ):
                    if row.get(key) != str(expected):
                        errors.append(
                            f"generator stats {key}={row.get(key)!r}, expected {expected!r}"
                        )
                        break
                try:
                    wall_time = int(row.get("wall_time_utc_ns", "0"))
                    if wall_time <= 0:
                        raise ValueError
                    generator_stats_wall_times.append(wall_time)
                except (TypeError, ValueError):
                    errors.append("generator stats contain an invalid wall_time_utc_ns")
                    generator_stats_wall_times.clear()
                    break
            if generator_stats_wall_times and generator_stats_wall_times != sorted(generator_stats_wall_times):
                errors.append("generator stats wall_time_utc_ns values are not monotonic")
            last = stats[-1]
            generator_final_stats = last
            if last.get("phase") != "done":
                errors.append(f"generator final phase {last.get('phase')!r}, expected 'done'")
            try:
                if float(last.get("elapsed_s", "0")) < float(args.generator_duration):
                    errors.append("generator stats ended before the configured run duration")
            except ValueError:
                errors.append("generator final elapsed_s is not numeric")
            try:
                if int(last.get("local_capacity_drop_total", "0") or 0) > 0:
                    errors.append("generator local capacity guard dropped offered work")
            except ValueError:
                errors.append("generator local_capacity_drop_total is not numeric")

    if len(gen_timeline_files) == 1:
        try:
            generator_timeline = json.loads(gen_timeline_files[0].read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"cannot parse generator timeline: {exc}")
        else:
            for key, expected in (
                ("schema_version", 1),
                ("run_id", rid),
                ("scenario", args.scenario),
                ("workload", args.generator_workload),
                ("mode", args.generator_mode),
                ("backend", args.generator_backend),
                ("generator_version", "0.1.5"),
                ("configured_duration_s", args.generator_duration),
                ("current_phase", "done"),
                ("terminal", True),
                ("run_end_reason", "duration-complete"),
            ):
                if str(generator_timeline.get(key)) != str(expected):
                    errors.append(
                        f"generator timeline {key}={generator_timeline.get(key)!r}, expected {expected!r}"
                    )
            timeline_git_commit = str(generator_timeline.get("generator_git_commit", ""))
            if re.fullmatch(r"[0-9a-f]{12}", timeline_git_commit) is None:
                errors.append(
                    "generator timeline generator_git_commit is missing, dirty, or not a 12-hex commit"
                )
            if generator_git_commit is not None and timeline_git_commit != generator_git_commit:
                errors.append("generator metadata/timeline Git commits disagree")
            try:
                process_started = int(generator_timeline["process_started_utc_ns"])
                phase_start = int(generator_timeline["phase_run_started_utc_ns"])
                phase_deadline = int(generator_timeline["phase_run_end_deadline_utc_ns"])
                phase_observed_end = int(generator_timeline["phase_run_end_observed_utc_ns"])
                drain_finished = int(generator_timeline["drain_finished_utc_ns"])
                process_finished = int(generator_timeline["process_finished_utc_ns"])
            except (KeyError, TypeError, ValueError):
                errors.append("generator timeline contains missing or non-numeric phase timestamps")
            else:
                expected_duration_ns = int(args.generator_duration) * 1_000_000_000
                if process_started <= 0:
                    errors.append("generator process-start timestamp is not positive")
                if phase_start <= 0:
                    errors.append("generator PHASE_RUN start timestamp is not positive")
                if phase_deadline - phase_start != expected_duration_ns:
                    errors.append("generator PHASE_RUN UTC deadline does not match configured duration")
                if not (
                    process_started <= phase_start <= phase_deadline
                    <= phase_observed_end <= drain_finished <= process_finished
                ):
                    errors.append("generator timeline timestamps are not in lifecycle order")
                if generator_stats_wall_times:
                    if generator_stats_wall_times[0] < process_started:
                        errors.append("generator stats begin before generator process start")
                    if generator_stats_wall_times[-1] > process_finished:
                        errors.append("generator stats extend beyond generator process finalization")
                end_lag_ns = phase_observed_end - phase_deadline
                if end_lag_ns > 100_000_000:
                    warnings.append(
                        f"generator PHASE_RUN end observation lag was {end_lag_ns / 1_000_000:.3f} ms"
                    )
                ref_start = ref_status.get("actual_start_utc_ns")
                ref_end = ref_status.get("actual_end_utc_ns")
                if isinstance(ref_start, int) and phase_start < ref_start:
                    errors.append("generator PHASE_RUN started before reference client")
                if isinstance(ref_end, int) and phase_observed_end > ref_end:
                    errors.append("generator PHASE_RUN ended after reference client")

    server_log = result_dir / "dut" / "server.log"
    if not server_log.exists():
        errors.append("DUT server log missing")
    else:
        text = server_log.read_text(encoding="utf-8", errors="replace")
        if f"manifest scenario={args.scenario} " not in text:
            errors.append("DUT server manifest scenario mismatch or missing")
        expected_log_mode = "debug" if args.profile == "pilot-debug" else "measurement"
        expected_debug_level = "2" if args.profile == "pilot-debug" else "0"
        if not re.search(
            rf"manifest bind=.*log_mode={re.escape(expected_log_mode)} "
            rf"debug_level={expected_debug_level} .*session_cache=off session_tickets=on "
            rf"strict_cert_profile=on",
            text,
        ):
            errors.append("DUT server operational-profile manifest is missing or inconsistent")
        final_matches = re.findall(r"^\[[^\n]+\] FINAL\s+(.*)$", text, re.MULTILINE)
        if not final_matches:
            errors.append("DUT server final summary is missing")
        else:
            final_counters = {
                key: value
                for key, value in re.findall(r"(?:^|\s)([A-Za-z0-9_]+)=([^\s]+)", final_matches[-1])
            }
            required_server_counters = ("accepted", "hs_ok", "echo_responses")
            missing_counters = [key for key in required_server_counters if key not in final_counters]
            if missing_counters:
                errors.append(
                    "DUT server final summary is missing counters: "
                    + ", ".join(missing_counters)
                )
            if generator_final_stats is not None and not missing_counters:
                try:
                    generator_tcp = int(generator_final_stats.get("tcp_established_total", "0") or 0)
                    generator_tls = (
                        int(generator_final_stats.get("full_handshake_ok_total", "0") or 0)
                        + int(generator_final_stats.get("resumed_handshake_ok_total", "0") or 0)
                    )
                    generator_app = int(generator_final_stats.get("app_ok_total", "0") or 0)
                    dut_accepted = int(final_counters["accepted"])
                    dut_handshakes = int(final_counters["hs_ok"])
                    dut_echoes = int(final_counters["echo_responses"])
                except ValueError:
                    errors.append("generator/DUT consistency counters are non-numeric")
                else:
                    consistency_messages: list[str] = []
                    if dut_accepted < generator_tcp:
                        consistency_messages.append(
                            f"DUT accepted={dut_accepted} is below generator tcp_established_total={generator_tcp}"
                        )
                    if dut_handshakes < generator_tls:
                        consistency_messages.append(
                            f"DUT hs_ok={dut_handshakes} is below generator successful TLS handshakes={generator_tls}"
                        )
                    if dut_echoes < generator_app:
                        consistency_messages.append(
                            f"DUT echo_responses={dut_echoes} is below generator app_ok_total={generator_app}"
                        )
                    if consistency_messages:
                        # The low-rate pilot-debug path is a semantic integration
                        # check, so cross-side disagreement invalidates it. Under
                        # measurement load the same disagreement may itself be a
                        # DUT degradation result and is retained as a warning.
                        target = errors if args.profile == "pilot-debug" else warnings
                        target.extend(consistency_messages)

    for filename, label in (
        ("server.exit_code", "DUT server"),
        ("wrapper.exit_code", "DUT server wrapper"),
    ):
        path = result_dir / "dut" / filename
        if not path.exists():
            errors.append(f"{label} exit-code file missing")
        else:
            try:
                code = int(path.read_text(encoding="ascii").strip())
            except (OSError, ValueError):
                errors.append(f"{label} exit-code file is invalid")
            else:
                if code != 0:
                    errors.append(f"{label} exit code {code}")
    if (result_dir / "dut" / "startup.error").exists():
        errors.append("DUT server startup.error is present")

    if ref_status.get("actual_start_utc_ns") and gen_status.get("actual_start_utc_ns"):
        if gen_status["actual_start_utc_ns"] < ref_status["actual_start_utc_ns"]:
            errors.append("generator process started before reference client")
        if gen_status.get("actual_end_utc_ns", 0) > ref_status.get("actual_end_utc_ns", 0):
            errors.append("generator process ended after reference client")
        for label, status in (("reference", ref_status), ("generator", gen_status)):
            lag_ns = status.get("start_lag_ns")
            if isinstance(lag_ns, int) and abs(lag_ns) > 100_000_000:
                warnings.append(
                    f"{label} scheduled-start lag was {lag_ns / 1_000_000:.3f} ms"
                )

    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "warnings": warnings,
        "validated_utc": utc_iso_ns(),
    }



def validate_tls_arguments(args: argparse.Namespace) -> list[str]:
    errors: list[str] = []
    categories = (
        ("scenario", SCENARIOS),
        ("profile", PROFILES),
        ("reference_workload", REFERENCE_WORKLOADS),
        ("generator_backend", BACKENDS),
        ("generator_workload", GENERATOR_WORKLOADS),
        ("generator_mode", MODES),
    )
    for name, allowed in categories:
        if getattr(args, name, None) not in allowed:
            errors.append(
                f"--{name.replace('_', '-')} must be one of: {', '.join(sorted(allowed))}"
            )
    integer_positive = (
        "reference_duration", "generator_duration", "generator_max_inflight",
        "generator_connections", "repetition", "start_delay",
    )
    for name in integer_positive:
        value = getattr(args, name)
        if not isinstance(value, int) or value <= 0:
            errors.append(f"--{name.replace('_', '-')} must be a positive integer")
    if not isinstance(args.pre_generation, int) or args.pre_generation < 0:
        errors.append("--pre-generation must be a non-negative integer")
    if not isinstance(args.generator_rate, (int, float)):
        errors.append("--generator-rate must be numeric")
    elif args.generator_workload == "tcp-syn":
        if float(args.generator_rate) != 0.0:
            errors.append("--generator-rate must be exactly 0 for tcp-syn (external tool-controlled-rate sentinel)")
    elif args.generator_rate <= 0:
        errors.append("--generator-rate must be positive")
    if args.generator_workload == "tcp-syn":
        if args.generator_backend != "posix":
            errors.append("tcp-syn requires --generator-backend posix")
        if args.generator_mode != "flood":
            errors.append("tcp-syn requires --generator-mode flood")
        if args.reference_workload != "full-handshake":
            errors.append("tcp-syn requires --reference-workload full-handshake")
    if (
        isinstance(args.reference_duration, int)
        and isinstance(args.generator_duration, int)
        and isinstance(args.pre_generation, int)
        and args.pre_generation + args.generator_duration > args.reference_duration
    ):
        errors.append(
            "generator interval exceeds reference interval: "
            "pre-generation + generator-duration must be <= reference-duration"
        )
    return errors

def command_tls_run(args: argparse.Namespace) -> int:
    global ACTIVE_LOCAL
    cfg = load_config(args.config)
    resolve_tls_defaults(cfg, args)
    errors = validate_config(cfg)
    errors.extend(validate_tls_arguments(args))
    if args.generator_workload == "resumption":
        pool_size = int(profile_value(cfg, "loadgen", "resumption_pool_size", LOADGEN_PROFILE_DEFAULTS))
        if args.generator_max_inflight < pool_size:
            errors.append(
                "--generator-max-inflight must be at least "
                f"loadgen.profile.resumption_pool_size ({pool_size}) for resumption runs"
            )
    if errors: raise OrchestratorError("configuration or run arguments invalid:\n- " + "\n- ".join(errors))
    if args.generator_mode == "flood" and not args.confirm_flood:
        raise OrchestratorError("flood mode requires --confirm-flood")
    rid = run_id(f"{args.scenario}_{args.reference_workload}_{args.generator_mode}")
    result_dir = make_result_dir(cfg, args, rid)
    (result_dir / "reference").mkdir(); (result_dir / "dut").mkdir(); (result_dir / "generator").mkdir()
    manifest = {
        "orchestrator_version": VERSION, "run_id": rid, "created_utc": utc_iso_ns(),
        "scenario": args.scenario, "profile": args.profile, "reference_workload": args.reference_workload,
        "reference_duration_s": args.reference_duration, "generator_backend": args.generator_backend,
        "generator_workload": args.generator_workload, "generator_mode": args.generator_mode,
        "generator_rate": args.generator_rate, "generator_duration_s": args.generator_duration,
        "generator_max_inflight": args.generator_max_inflight, "generator_connections": args.generator_connections,
        "pre_generation_s": args.pre_generation, "start_delay_s": args.start_delay,
        "reference_probe_interval_ms": int(cfg.get("experiment.reference_probe_interval_ms", 1000, False)),
        "reference_profile": effective_profile(cfg, "reference", REFERENCE_PROFILE_DEFAULTS),
        "loadgen_profile": effective_profile(cfg, "loadgen", LOADGEN_PROFILE_DEFAULTS),
        "repetition": args.repetition,
        "state": "initializing",
        "control_plane_policy": "no remote status polling during the reference interval",
    }
    atomic_json(result_dir / "run_manifest.json", manifest)
    clock = clock_preflight(cfg, args.profile)
    atomic_json(result_dir / "clock_preflight.json", clock)
    if clock["errors"]: raise OrchestratorError("clock preflight failed: " + "; ".join(clock["errors"]))

    server_started = False
    dut_run_created = False
    loadgen_run_created = False
    loadgen_needs_stop = False
    dut_transfer_done = False
    loadgen_transfer_done = False
    try:
        # Mark cleanup as required before submission. A timeout can occur after
        # the remote agent has already created the run and started the server.
        server_started = True
        dut_run_created = True
        submission = remote_agent(
            cfg, "dut", ["server-start", rid, args.scenario, args.profile],
            check=False, timeout=15,
        )
        atomic_json(result_dir / "dut_server_submission.json", {
            "returncode": submission.returncode,
            "stdout": submission.stdout,
            "stderr": submission.stderr,
        })
        if submission.returncode != 0:
            raise OrchestratorError(
                "DUT server-start failed: " + completed_diagnostic(submission)
            )
        status = poll_dut_server(cfg, rid, float(cfg.get("experiment.server_ready_timeout_s")), require_manifest=True)
        if status.get("AFFINITY") != str(cfg.get("dut.server_cpu")):
            raise OrchestratorError(f"DUT server affinity mismatch: {status.get('AFFINITY')}")

        t0_ns = time.time_ns() + int(args.start_delay * 1_000_000_000)
        gen_start_ns = t0_ns + int(args.pre_generation * 1_000_000_000)
        ref_status_path = result_dir / "reference" / "process_status.json"
        ref_cmd = reference_command(cfg, args, rid, result_dir / "reference")
        scheduled = Path(__file__).resolve().parent / "orchestration" / "scheduled_exec.py"
        wrapper_cmd = [sys.executable, str(scheduled), "--scheduled-start-ns", str(t0_ns),
                       "--status", str(ref_status_path), "--stdout", str(result_dir / "reference" / "client.stdout.log"),
                       "--stderr", str(result_dir / "reference" / "client.stderr.log"),
                       "--pid-file", str(result_dir / "reference" / "client.pid"),
                       "--workdir", str(reference_workdir(cfg)), "--", *ref_cmd]
        (result_dir / "reference" / "client.command.txt").write_text(shlex.join(ref_cmd) + "\n", encoding="utf-8")
        ACTIVE_LOCAL = subprocess.Popen(wrapper_cmd, start_new_session=True)

        loadgen_run_created = True
        loadgen_needs_stop = True
        cp = remote_agent(cfg, "loadgen", ["run-start", rid, args.scenario, args.generator_workload,
             args.generator_mode, args.generator_backend, str(args.generator_rate), str(args.generator_duration),
             str(args.generator_max_inflight), str(args.generator_connections), str(gen_start_ns)], timeout=20)
        atomic_json(result_dir / "generator_submission.json", json.loads(cp.stdout))

        ref_timeout = args.start_delay + args.reference_duration + 60
        ref_status = wait_local_status(ref_status_path, ref_timeout)
        ACTIVE_LOCAL.wait(timeout=10)
        ACTIVE_LOCAL = None

        # Do not repeatedly authenticate to the load-generator host while the
        # reference interval is active.  A failed reference run is already
        # invalid, so cancel the generator before collecting its status.
        if int(ref_status.get("exit_code", 1)) != 0:
            remote_agent(
                cfg, "loadgen",
                ["run-stop", rid, str(cfg.get("experiment.process_grace_s"))],
                check=False, timeout=30,
            )
        gen_status = poll_loadgen(
            cfg,
            rid,
            max(30.0, float(cfg.get("experiment.process_grace_s")) + 15.0),
        )
        loadgen_needs_stop = False

        remote_agent(cfg, "loadgen", ["collect-state", rid], check=False, timeout=20)
        remote_agent(cfg, "dut", ["collect-state", rid], check=False, timeout=20)
        stop_result = remote_agent(
            cfg, "dut",
            ["server-stop", rid, str(cfg.get("experiment.process_grace_s"))],
            check=False, timeout=30,
        )
        atomic_json(result_dir / "dut_server_stop.json", {
            "returncode": stop_result.returncode,
            "stdout": stop_result.stdout,
            "stderr": stop_result.stderr,
        })
        if stop_result.returncode != 0:
            raise OrchestratorError(
                "DUT server-stop failed: " + completed_diagnostic(stop_result)
            )
        server_started = False
        final_server_status = poll_dut_server(cfg, rid, 15, require_manifest=False)
        atomic_json(result_dir / "dut_server_final_status.json", final_server_status)

        transfer_timeout = float(cfg.get("experiment.transfer_timeout_s", 300, False))
        dut_transfer = fetch_run_archive(cfg, "dut", rid, result_dir / "dut", timeout=transfer_timeout)
        gen_transfer = fetch_run_archive(cfg, "loadgen", rid, result_dir / "generator", timeout=transfer_timeout)
        atomic_json(result_dir / "dut_transfer.json", dut_transfer)
        dut_transfer_done = True
        atomic_json(result_dir / "generator_transfer.json", gen_transfer)
        loadgen_transfer_done = True

        server_start_ns = None; server_end_ns = None
        p = result_dir / "dut" / "wrapper_start_utc_ns"
        if p.exists(): server_start_ns = int(p.read_text().strip())
        p = result_dir / "dut" / "server_end_utc_ns"
        if p.exists(): server_end_ns = int(p.read_text().strip())
        generator_timeline_files = list(
            (result_dir / "generator").glob("output/**/generator.timeline.json")
        )
        generator_phase = None
        if len(generator_timeline_files) == 1:
            try:
                candidate_phase = json.loads(
                    generator_timeline_files[0].read_text(encoding="utf-8")
                )
                for required_key in (
                    "phase_run_started_utc_ns",
                    "phase_run_end_deadline_utc_ns",
                    "phase_run_end_observed_utc_ns",
                ):
                    int(candidate_phase[required_key])
                generator_phase = candidate_phase
            except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
                generator_phase = None
        timeline = {
            "run_id": rid,
            "server_start_utc_ns": server_start_ns,
            "reference_scheduled_start_utc_ns": t0_ns,
            "reference_actual_start_utc_ns": ref_status.get("actual_start_utc_ns"),
            "generator_scheduled_process_start_utc_ns": gen_start_ns,
            "generator_process_actual_start_utc_ns": gen_status.get("actual_start_utc_ns"),
            "generator_process_actual_end_utc_ns": gen_status.get("actual_end_utc_ns"),
            "reference_actual_end_utc_ns": ref_status.get("actual_end_utc_ns"),
            "server_end_utc_ns": server_end_ns,
            "offered_load_phase_timestamps_available": generator_phase is not None,
        }
        if generator_phase is not None:
            timeline.update({
                "generator_phase_run_start_utc_ns": generator_phase.get("phase_run_started_utc_ns"),
                "generator_phase_run_end_deadline_utc_ns": generator_phase.get("phase_run_end_deadline_utc_ns"),
                "generator_phase_run_end_observed_utc_ns": generator_phase.get("phase_run_end_observed_utc_ns"),
                "generator_phase_run_end_reason": generator_phase.get("run_end_reason"),
            })
        else:
            timeline["offered_load_phase_note"] = (
                "generator.timeline.json is missing or invalid; validation will fail"
            )
        if ref_status.get("actual_start_utc_ns") and gen_status.get("actual_start_utc_ns"):
            timeline["generator_process_start_elapsed_from_reference_s"] = (gen_status["actual_start_utc_ns"] - ref_status["actual_start_utc_ns"]) / 1e9
            timeline["generator_process_end_elapsed_from_reference_s"] = (gen_status["actual_end_utc_ns"] - ref_status["actual_start_utc_ns"]) / 1e9
        if generator_phase is not None and ref_status.get("actual_start_utc_ns"):
            reference_start_ns = int(ref_status["actual_start_utc_ns"])
            timeline["generator_phase_run_start_elapsed_from_reference_s"] = (
                int(generator_phase["phase_run_started_utc_ns"]) - reference_start_ns
            ) / 1e9
            timeline["generator_phase_run_end_elapsed_from_reference_s"] = (
                int(generator_phase["phase_run_end_deadline_utc_ns"]) - reference_start_ns
            ) / 1e9
        atomic_json(result_dir / "timeline.json", timeline)
        validation = validate_run(result_dir, cfg, args, rid, ref_status, gen_status)
        atomic_json(result_dir / "validation.json", validation)
        manifest.update({
            "state": "finished",
            "finished_utc": utc_iso_ns(),
            "validation_status": validation["status"],
        })
        atomic_json(result_dir / "run_manifest.json", manifest)
        print(f"Run ID: {rid}")
        print(f"Results: {result_dir}")
        print(f"Validation: {validation['status']}")
        for error in validation["errors"]: print(f"- {error}", file=sys.stderr)
        return 0 if validation["status"] == "PASS" else 1
    except Exception as exc:
        manifest.update({
            "state": "failed",
            "finished_utc": utc_iso_ns(),
            "error_type": type(exc).__name__,
            "error": str(exc),
        })
        atomic_json(result_dir / "run_manifest.json", manifest)
        (result_dir / "orchestration_error.txt").write_text(
            f"{type(exc).__name__}: {exc}\n", encoding="utf-8"
        )
        raise
    finally:
        if ACTIVE_LOCAL is not None:
            try:
                cleanup = stop_local_wrapper(
                    ACTIVE_LOCAL,
                    float(cfg.get("experiment.process_grace_s")),
                )
                atomic_json(result_dir / "reference_cleanup.json", cleanup)
            except Exception as exc:
                (result_dir / "reference_cleanup_error.txt").write_text(
                    f"{type(exc).__name__}: {exc}\n", encoding="utf-8"
                )
            ACTIVE_LOCAL = None
        if server_started:
            try:
                remote_agent(cfg, "dut", ["server-stop", rid, str(cfg.get("experiment.process_grace_s"))], check=False, timeout=30)
            except Exception as exc:
                (result_dir / "dut_stop_error.txt").write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
        if loadgen_needs_stop:
            try:
                remote_agent(cfg, "loadgen", ["run-stop", rid, str(cfg.get("experiment.process_grace_s"))], check=False, timeout=30)
            except Exception as exc:
                (result_dir / "generator_stop_error.txt").write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
        # Preserve remote diagnostics even when the run fails before normal collection.
        transfer_timeout = float(cfg.get("experiment.transfer_timeout_s", 300, False))
        if dut_run_created and not dut_transfer_done:
            try:
                remote_agent(cfg, "dut", ["collect-state", rid], check=False, timeout=20)
                atomic_json(result_dir / "dut_transfer.json", fetch_run_archive(cfg, "dut", rid, result_dir / "dut", timeout=transfer_timeout))
            except Exception as exc:
                (result_dir / "dut_transfer_error.txt").write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
        if loadgen_run_created and not loadgen_transfer_done:
            try:
                remote_agent(cfg, "loadgen", ["collect-state", rid], check=False, timeout=20)
                atomic_json(result_dir / "generator_transfer.json", fetch_run_archive(cfg, "loadgen", rid, result_dir / "generator", timeout=transfer_timeout))
            except Exception as exc:
                (result_dir / "generator_transfer_error.txt").write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")


def command_iperf(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    duration = int(args.duration if args.duration is not None else cfg.get("iperf.duration_s"))
    parallel = int(args.parallel if args.parallel is not None else cfg.get("iperf.parallel_streams"))
    port = int(args.port if args.port is not None else cfg.get("iperf.port"))
    udp = bool(args.udp if args.udp is not None else cfg.get("iperf.udp_enabled"))
    udp_rate = str(args.udp_rate if args.udp_rate is not None else cfg.get("iperf.udp_rate"))
    server_ready_wait = float(
        args.server_ready_wait
        if args.server_ready_wait is not None
        else cfg.get("iperf.server_ready_wait_s")
    )
    errors = validate_config(cfg)
    if duration <= 0:
        errors.append("--duration must be positive")
    if parallel <= 0:
        errors.append("--parallel must be positive")
    if not 1 <= port <= 65535:
        errors.append("--port must be between 1 and 65535")
    if server_ready_wait < 0:
        errors.append("--server-ready-wait must be non-negative")
    if udp and re.fullmatch(r"[0-9]+(?:[.][0-9]+)?[KMG]?", udp_rate) is None:
        errors.append("--udp-rate must be an iperf rate such as 950M")
    if errors:
        raise OrchestratorError("configuration or iperf arguments invalid:\n- " + "\n- ".join(errors))

    remote_agent(cfg, "dut", ["iperf-preflight"], timeout=20)
    remote_agent(cfg, "loadgen", ["iperf-preflight"], timeout=20)
    rid = run_id("iperf")
    result_dir = cfg.local_path("repository.results_root") / "network-characterization" / rid
    result_dir.mkdir(parents=True)
    tests: list[tuple[str, str, str | None]] = [
        ("tcp-forward", "forward", None),
        ("tcp-reverse", "reverse", None),
    ]
    if udp:
        tests.append(("udp", "udp", udp_rate))
    results: list[dict[str, Any]] = []
    transfer_timeout = float(cfg.get("experiment.transfer_timeout_s", 300, False))
    dut_run_created = False
    loadgen_run_created = False
    dut_transfer_done = False
    loadgen_transfer_done = False
    active_test: str | None = None
    iperf_created_utc = utc_iso_ns()
    atomic_json(result_dir / "iperf_manifest.json", {
        "run_id": rid,
        "created_utc": iperf_created_utc,
        "duration_s": duration,
        "parallel": parallel,
        "port": port,
        "udp_enabled": udp,
        "udp_rate": udp_rate if udp else None,
        "tests": [],
        "state": "running",
    })
    try:
        for name, direction, test_udp_rate in tests:
            active_test = name
            dut_run_created = True
            remote_agent(cfg, "dut", ["iperf-start", rid, name, str(port)], timeout=10)
            deadline = time.monotonic() + 10
            status: dict[str, str] = {}
            while time.monotonic() < deadline:
                status_cp = remote_agent(
                    cfg, "dut", ["iperf-status", rid, name],
                    check=False, timeout=10,
                )
                if status_cp.returncode != 0:
                    raise OrchestratorError(
                        "DUT iperf-status failed: " + completed_diagnostic(status_cp)
                    )
                status = parse_kv(status_cp.stdout)
                if status.get("STATE") == "running":
                    break
                if status.get("STATE") == "exited":
                    raise OrchestratorError(
                        f"DUT iperf server exited before client start: {status}"
                    )
                time.sleep(0.1)
            else:
                raise OrchestratorError(f"DUT iperf server did not become ready: {status}")

            time.sleep(server_ready_wait)
            cmd = ["iperf-run", rid, name, str(duration), str(parallel), direction, str(port)]
            if test_udp_rate:
                cmd.append(test_udp_rate)
            loadgen_run_created = True
            cp = remote_agent(cfg, "loadgen", cmd, check=False, timeout=duration + 30)
            try:
                result = json.loads(cp.stdout) if cp.stdout.strip().startswith("{") else {
                    "exit_code": cp.returncode,
                    "stdout": cp.stdout,
                    "stderr": cp.stderr,
                }
            except json.JSONDecodeError:
                result = {
                    "exit_code": cp.returncode,
                    "stdout": cp.stdout,
                    "stderr": cp.stderr,
                    "parse_error": "load-generator agent did not return valid JSON",
                }
            results.append({"name": name, "direction": direction, "result": result})
            atomic_json(result_dir / "iperf_manifest.json", {
                "run_id": rid,
                "created_utc": iperf_created_utc,
                "duration_s": duration,
                "parallel": parallel,
                "port": port,
                "udp_enabled": udp,
                "udp_rate": udp_rate if udp else None,
                "tests": results,
                "state": "running",
            })

            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                status_cp = remote_agent(
                    cfg, "dut", ["iperf-status", rid, name],
                    check=False, timeout=10,
                )
                if status_cp.returncode != 0:
                    raise OrchestratorError(
                        "DUT iperf-status failed: " + completed_diagnostic(status_cp)
                    )
                status = parse_kv(status_cp.stdout)
                if status.get("STATE") == "exited":
                    break
                time.sleep(0.25)
            remote_agent(
                cfg, "dut",
                ["iperf-stop", rid, name, str(cfg.get("experiment.process_grace_s"))],
                check=False, timeout=20,
            )
            active_test = None

        remote_agent(cfg, "dut", ["collect-state", rid], check=False, timeout=20)
        remote_agent(cfg, "loadgen", ["collect-state", rid], check=False, timeout=20)
        atomic_json(
            result_dir / "dut_transfer.json",
            fetch_run_archive(cfg, "dut", rid, result_dir / "dut", timeout=transfer_timeout),
        )
        dut_transfer_done = True
        atomic_json(
            result_dir / "loadgen_transfer.json",
            fetch_run_archive(cfg, "loadgen", rid, result_dir / "loadgen", timeout=transfer_timeout),
        )
        loadgen_transfer_done = True
        report = {
            "run_id": rid,
            "created_utc": iperf_created_utc,
            "finished_utc": utc_iso_ns(),
            "duration_s": duration,
            "parallel": parallel,
            "port": port,
            "udp_enabled": udp,
            "udp_rate": udp_rate if udp else None,
            "tests": results,
            "state": "finished",
        }
        atomic_json(result_dir / "iperf_manifest.json", report)
        failed = [r for r in results if int(r["result"].get("exit_code", 1)) != 0]
        print(f"iperf results: {result_dir}")
        return 1 if failed else 0
    except Exception as exc:
        (result_dir / "orchestration_error.txt").write_text(
            f"{type(exc).__name__}: {exc}\n", encoding="utf-8"
        )
        raise
    finally:
        if active_test is not None:
            try:
                remote_agent(
                    cfg, "dut",
                    ["iperf-stop", rid, active_test, str(cfg.get("experiment.process_grace_s"))],
                    check=False, timeout=20,
                )
            except Exception as exc:
                (result_dir / "dut_iperf_stop_error.txt").write_text(
                    f"{type(exc).__name__}: {exc}\n", encoding="utf-8"
                )
        if dut_run_created and not dut_transfer_done:
            try:
                remote_agent(cfg, "dut", ["collect-state", rid], check=False, timeout=20)
                atomic_json(
                    result_dir / "dut_transfer.json",
                    fetch_run_archive(cfg, "dut", rid, result_dir / "dut", timeout=transfer_timeout),
                )
            except Exception as exc:
                (result_dir / "dut_transfer_error.txt").write_text(
                    f"{type(exc).__name__}: {exc}\n", encoding="utf-8"
                )
        if loadgen_run_created and not loadgen_transfer_done:
            try:
                remote_agent(cfg, "loadgen", ["collect-state", rid], check=False, timeout=20)
                atomic_json(
                    result_dir / "loadgen_transfer.json",
                    fetch_run_archive(cfg, "loadgen", rid, result_dir / "loadgen", timeout=transfer_timeout),
                )
            except Exception as exc:
                (result_dir / "loadgen_transfer_error.txt").write_text(
                    f"{type(exc).__name__}: {exc}\n", encoding="utf-8"
                )

def command_sweep(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    with args.matrix.open("rb") as fh:
        matrix = tomllib.load(fh)
    runs = matrix.get("runs")
    if not isinstance(runs, list) or not runs:
        raise OrchestratorError("matrix must contain at least one [[runs]] entry")

    required = {
        "scenario", "reference_workload", "generator_backend",
        "generator_workload", "rates",
    }
    matrix_errors: list[str] = []
    normalized: list[tuple[dict[str, Any], list[float], int]] = []
    for index, spec in enumerate(runs, start=1):
        prefix = f"matrix runs[{index}]"
        if not isinstance(spec, dict):
            matrix_errors.append(f"{prefix} must be a TOML table")
            continue
        missing = sorted(required - set(spec))
        if missing:
            matrix_errors.append(f"{prefix} missing keys: {', '.join(missing)}")
            continue
        for key, allowed in (
            ("scenario", SCENARIOS),
            ("profile", PROFILES),
            ("reference_workload", REFERENCE_WORKLOADS),
            ("generator_backend", BACKENDS),
            ("generator_workload", GENERATOR_WORKLOADS),
            ("generator_mode", MODES),
        ):
            value = spec.get(key, "measurement" if key == "profile" else "benign" if key == "generator_mode" else None)
            if value not in allowed:
                matrix_errors.append(
                    f"{prefix}.{key} must be one of: {', '.join(sorted(allowed))}"
                )
        rates_raw = spec.get("rates")
        rates: list[float] = []
        if not isinstance(rates_raw, list) or not rates_raw:
            matrix_errors.append(f"{prefix}.rates must be a non-empty array")
        else:
            for rate_index, rate in enumerate(rates_raw, start=1):
                try:
                    numeric = float(rate)
                except (TypeError, ValueError):
                    matrix_errors.append(f"{prefix}.rates[{rate_index}] must be numeric")
                    continue
                if spec.get("generator_workload") == "tcp-syn":
                    if numeric != 0.0:
                        matrix_errors.append(f"{prefix}.rates[{rate_index}] must be exactly 0 for tcp-syn external-tool sentinel")
                    else:
                        rates.append(numeric)
                elif numeric <= 0:
                    matrix_errors.append(f"{prefix}.rates[{rate_index}] must be positive")
                else:
                    rates.append(numeric)
        try:
            repetitions = int(spec.get("repetitions", 1))
            if repetitions <= 0:
                raise ValueError
        except (TypeError, ValueError):
            matrix_errors.append(f"{prefix}.repetitions must be a positive integer")
            repetitions = 0
        normalized.append((spec, rates, repetitions))

    if matrix_errors:
        raise OrchestratorError("invalid sweep matrix:\n- " + "\n- ".join(matrix_errors))

    failures = 0
    for spec, rates, repetitions in normalized:
        for rate in rates:
            for rep in range(1, repetitions + 1):
                ns = argparse.Namespace(
                    config=args.config,
                    scenario=spec["scenario"],
                    profile=spec.get("profile", "measurement"),
                    reference_workload=spec["reference_workload"],
                    reference_duration=int(spec.get("reference_duration_s", cfg.get("experiment.reference_duration_s"))),
                    generator_backend=spec["generator_backend"],
                    generator_workload=spec["generator_workload"],
                    generator_mode=spec.get("generator_mode", "benign"),
                    generator_rate=rate,
                    generator_duration=int(spec.get("generator_duration_s", cfg.get("experiment.generator_duration_s"))),
                    generator_max_inflight=int(spec.get("max_inflight", cfg.get("defaults.generator.max_inflight"))),
                    generator_connections=int(spec.get("record_connections", cfg.get("defaults.generator.record_connections"))),
                    repetition=rep,
                    pre_generation=int(spec.get("pre_generation_s", cfg.get("experiment.pre_generation_s"))),
                    start_delay=int(spec.get("start_delay_s", cfg.get("experiment.start_delay_s"))),
                    confirm_flood=args.confirm_flood,
                )
                run_errors = validate_tls_arguments(ns)
                if run_errors:
                    raise OrchestratorError(
                        "invalid expanded sweep run:\n- " + "\n- ".join(run_errors)
                    )
                rc = command_tls_run(ns)
                if rc != 0:
                    failures += 1
                    if not args.continue_on_failure:
                        return rc
    return 1 if failures else 0


def add_common_tls_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--scenario", choices=sorted(SCENARIOS), required=True)
    p.add_argument("--profile", choices=sorted(PROFILES), default="measurement")
    p.add_argument("--reference-workload", choices=sorted(REFERENCE_WORKLOADS), required=True)
    p.add_argument("--reference-duration", type=int)
    p.add_argument("--generator-backend", choices=sorted(BACKENDS), required=True)
    p.add_argument("--generator-workload", choices=sorted(GENERATOR_WORKLOADS), required=True)
    p.add_argument("--generator-mode", choices=sorted(MODES), required=True)
    p.add_argument("--generator-rate", type=float, required=True)
    p.add_argument("--generator-duration", type=int)
    p.add_argument("--generator-max-inflight", type=int)
    p.add_argument("--generator-connections", type=int)
    p.add_argument("--repetition", type=int, required=True)
    p.add_argument("--pre-generation", type=int)
    p.add_argument("--start-delay", type=int)
    p.add_argument("--confirm-flood", action="store_true")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="command", required=True)
    v = sub.add_parser("validate-config"); v.add_argument("--config", type=Path, required=True)
    sc = sub.add_parser("ssh-check"); sc.add_argument("--config", type=Path, required=True); sc.add_argument("--host", choices=("dut", "loadgen"))
    d = sub.add_parser("deploy"); d.add_argument("--config", type=Path, required=True)
    r = sub.add_parser("render-agent-configs"); r.add_argument("--config", type=Path, required=True); r.add_argument("--output", type=Path, required=True)
    i = sub.add_parser("init"); i.add_argument("--config", type=Path, required=True); i.add_argument("--backend", choices=sorted(BACKENDS), required=True); i.add_argument("--profile", choices=sorted(PROFILES), default="measurement"); i.add_argument("--functional-check", action="store_true")
    t = sub.add_parser("tls-run"); t.add_argument("--config", type=Path, required=True); add_common_tls_args(t)
    ip = sub.add_parser("iperf"); ip.add_argument("--config", type=Path, required=True); ip.add_argument("--duration", type=int); ip.add_argument("--parallel", type=int); ip.add_argument("--port", type=int); ip.add_argument("--udp", action=argparse.BooleanOptionalAction, default=None); ip.add_argument("--udp-rate"); ip.add_argument("--server-ready-wait", type=float)
    s = sub.add_parser("sweep"); s.add_argument("--config", type=Path, required=True); s.add_argument("--matrix", type=Path, required=True); s.add_argument("--continue-on-failure", action="store_true"); s.add_argument("--confirm-flood", action="store_true")
    return p


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "validate-config":
            cfg = load_config(args.config); errors = validate_config(cfg)
            if errors:
                for error in errors: print(error, file=sys.stderr)
                return 1
            print("Configuration: PASS"); return 0
        if args.command == "ssh-check": return command_ssh_check(args)
        if args.command == "deploy":
            cfg = load_config(args.config)
            with campaign_lock(cfg, args.command):
                return command_deploy(args)
        if args.command == "render-agent-configs":
            cfg = load_config(args.config); paths = render_agent_configs(cfg, args.output)
            print("\n".join(str(p) for p in paths)); return 0
        if args.command in {"init", "tls-run", "iperf", "sweep"}:
            cfg = load_config(args.config)
            with campaign_lock(cfg, args.command):
                if args.command == "init": return command_init(args)
                if args.command == "tls-run": return command_tls_run(args)
                if args.command == "iperf": return command_iperf(args)
                return command_sweep(args)
        raise AssertionError(args.command)
    except KeyboardInterrupt:
        print("ERROR: interrupted", file=sys.stderr)
        return 130
    except (OrchestratorError, subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError):
            if exc.stdout: print(exc.stdout, file=sys.stderr)
            if exc.stderr: print(exc.stderr, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
