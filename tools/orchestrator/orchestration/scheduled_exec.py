#!/usr/bin/env python3
"""Run one command at an absolute UTC epoch using a monotonic deadline.

The wrapper records scheduled and actual timing, exit status, and PIDs in JSON.
It forwards SIGTERM/SIGINT to the child's process group.
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
import grp
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

CHILD: subprocess.Popen[bytes] | None = None
CANCEL_SIGNAL: int | None = None


def atomic_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def utc_iso_ns(epoch_ns: int) -> str:
    sec, ns = divmod(epoch_ns, 1_000_000_000)
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sec))
    return f"{base}.{ns:09d}Z"


def chown_tree(path: Path, user_group: str) -> None:
    if not user_group:
        return
    if ":" not in user_group:
        raise ValueError("--chown must be USER:GROUP")
    user, group = user_group.split(":", 1)
    uid = pwd.getpwnam(user).pw_uid if user else -1
    gid = grp.getgrnam(group).gr_gid if group else -1
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            try:
                os.chown(os.path.join(root, name), uid, gid)
            except FileNotFoundError:
                pass
    os.chown(path, uid, gid)


def forward(signum: int, _frame: object) -> None:
    global CHILD, CANCEL_SIGNAL
    CANCEL_SIGNAL = signum
    if CHILD is not None and CHILD.poll() is None:
        try:
            os.killpg(CHILD.pid, signum)
        except ProcessLookupError:
            pass


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--scheduled-start-ns", type=int, required=True)
    p.add_argument("--status", type=Path, required=True)
    p.add_argument("--stdout", type=Path, required=True)
    p.add_argument("--stderr", type=Path, required=True)
    p.add_argument("--pid-file", type=Path, required=True)
    p.add_argument("--workdir", type=Path, default=None)
    p.add_argument("--chown", default="")
    p.add_argument("--chown-tree", type=Path, default=None)
    p.add_argument("--max-past-ms", type=int, default=1000)
    p.add_argument("command", nargs=argparse.REMAINDER)
    args = p.parse_args()
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        p.error("command after -- is required")
    return args


def main() -> int:
    global CHILD, CANCEL_SIGNAL
    args = parse_args()
    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)

    ready_utc_ns = time.time_ns()
    delay_ns = args.scheduled_start_ns - ready_utc_ns
    if delay_ns < -args.max_past_ms * 1_000_000:
        atomic_json(args.status, {
            "state": "failed_before_start",
            "scheduled_start_utc_ns": args.scheduled_start_ns,
            "scheduled_start_utc": utc_iso_ns(args.scheduled_start_ns),
            "wrapper_ready_utc_ns": ready_utc_ns,
            "wrapper_ready_utc": utc_iso_ns(ready_utc_ns),
            "error": "scheduled start is too far in the past",
            "exit_code": 125,
        })
        return 125

    deadline_ns = time.monotonic_ns() + max(0, delay_ns)
    atomic_json(args.status, {
        "state": "waiting",
        "scheduled_start_utc_ns": args.scheduled_start_ns,
        "scheduled_start_utc": utc_iso_ns(args.scheduled_start_ns),
        "wrapper_ready_utc_ns": ready_utc_ns,
        "wrapper_ready_utc": utc_iso_ns(ready_utc_ns),
        "command": args.command,
    })

    while True:
        if CANCEL_SIGNAL is not None:
            cancelled_ns = time.time_ns()
            atomic_json(args.status, {
                "state": "cancelled_before_start",
                "scheduled_start_utc_ns": args.scheduled_start_ns,
                "scheduled_start_utc": utc_iso_ns(args.scheduled_start_ns),
                "wrapper_ready_utc_ns": ready_utc_ns,
                "wrapper_ready_utc": utc_iso_ns(ready_utc_ns),
                "actual_end_utc_ns": cancelled_ns,
                "actual_end_utc": utc_iso_ns(cancelled_ns),
                "signal": CANCEL_SIGNAL,
                "exit_code": 128 + CANCEL_SIGNAL,
                "command": args.command,
            })
            return 128 + CANCEL_SIGNAL
        remaining = deadline_ns - time.monotonic_ns()
        if remaining <= 0:
            break
        time.sleep(min(remaining / 1_000_000_000, 0.1))

    if CANCEL_SIGNAL is not None:
        cancelled_ns = time.time_ns()
        atomic_json(args.status, {
            "state": "cancelled_before_start",
            "scheduled_start_utc_ns": args.scheduled_start_ns,
            "scheduled_start_utc": utc_iso_ns(args.scheduled_start_ns),
            "wrapper_ready_utc_ns": ready_utc_ns,
            "wrapper_ready_utc": utc_iso_ns(ready_utc_ns),
            "actual_end_utc_ns": cancelled_ns,
            "actual_end_utc": utc_iso_ns(cancelled_ns),
            "signal": CANCEL_SIGNAL,
            "exit_code": 128 + CANCEL_SIGNAL,
            "command": args.command,
        })
        return 128 + CANCEL_SIGNAL

    args.stdout.parent.mkdir(parents=True, exist_ok=True)
    args.stderr.parent.mkdir(parents=True, exist_ok=True)
    actual_start_ns = time.time_ns()
    with args.stdout.open("wb") as out, args.stderr.open("wb") as err:
        try:
            CHILD = subprocess.Popen(
                args.command,
                cwd=str(args.workdir) if args.workdir else None,
                stdout=out,
                stderr=err,
                start_new_session=True,
                env=os.environ.copy(),
            )
        except OSError as exc:
            # Preserve a terminal status even when exec/cwd setup fails before
            # a child PID exists.  127 denotes a missing executable; other
            # local spawn failures use 126.
            code = 127 if isinstance(exc, FileNotFoundError) else 126
            failed_ns = time.time_ns()
            atomic_json(args.status, {
                "state": "failed_before_start",
                "scheduled_start_utc_ns": args.scheduled_start_ns,
                "scheduled_start_utc": utc_iso_ns(args.scheduled_start_ns),
                "wrapper_ready_utc_ns": ready_utc_ns,
                "wrapper_ready_utc": utc_iso_ns(ready_utc_ns),
                "actual_start_utc_ns": actual_start_ns,
                "actual_start_utc": utc_iso_ns(actual_start_ns),
                "actual_end_utc_ns": failed_ns,
                "actual_end_utc": utc_iso_ns(failed_ns),
                "start_lag_ns": actual_start_ns - args.scheduled_start_ns,
                "exit_code": code,
                "error": f"{type(exc).__name__}: {exc}",
                "command": args.command,
            })
            return code
        args.pid_file.write_text(f"{CHILD.pid}\n", encoding="ascii")
        atomic_json(args.status, {
            "state": "running",
            "scheduled_start_utc_ns": args.scheduled_start_ns,
            "scheduled_start_utc": utc_iso_ns(args.scheduled_start_ns),
            "wrapper_ready_utc_ns": ready_utc_ns,
            "wrapper_ready_utc": utc_iso_ns(ready_utc_ns),
            "actual_start_utc_ns": actual_start_ns,
            "actual_start_utc": utc_iso_ns(actual_start_ns),
            "start_lag_ns": actual_start_ns - args.scheduled_start_ns,
            "pid": CHILD.pid,
            "command": args.command,
        })
        rc = CHILD.wait()

    end_ns = time.time_ns()
    final = {
        "state": "finished",
        "scheduled_start_utc_ns": args.scheduled_start_ns,
        "scheduled_start_utc": utc_iso_ns(args.scheduled_start_ns),
        "wrapper_ready_utc_ns": ready_utc_ns,
        "wrapper_ready_utc": utc_iso_ns(ready_utc_ns),
        "actual_start_utc_ns": actual_start_ns,
        "actual_start_utc": utc_iso_ns(actual_start_ns),
        "actual_end_utc_ns": end_ns,
        "actual_end_utc": utc_iso_ns(end_ns),
        "start_lag_ns": actual_start_ns - args.scheduled_start_ns,
        "duration_ns": end_ns - actual_start_ns,
        "pid": CHILD.pid,
        "exit_code": rc,
        "command": args.command,
    }
    atomic_json(args.status, final)

    if args.chown_tree is not None and args.chown:
        chown_tree(args.chown_tree, args.chown)
    elif args.chown:
        for p in (args.status, args.stdout, args.stderr, args.pid_file):
            if p.exists():
                user, group = args.chown.split(":", 1)
                os.chown(p, pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
