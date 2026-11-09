from __future__ import annotations
import csv, json, re
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

KV_RE = re.compile(r"([A-Za-z0-9_]+)=([^\s]+)")
LOG_RE = re.compile(r"^\[([^\]]+)\]\s+(SUMRY|FINAL)\s+(.*)$")


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def first_matching(root: Path, pattern: str) -> Path | None:
    items = sorted(root.glob(pattern))
    return items[0] if items else None


def numeric(value: Any) -> float | None:
    if value is None or value == "": return None
    try: return float(value)
    except (TypeError, ValueError): return None


def integer(value: Any) -> int | None:
    if value is None or value == "": return None
    try: return int(value)
    except (TypeError, ValueError): return None


def parse_kv_line(text: str) -> dict[str, int | float | str]:
    out: dict[str, int | float | str] = {}
    for k, v in KV_RE.findall(text):
        try: out[k] = int(v, 10)
        except ValueError:
            try: out[k] = float(v)
            except ValueError: out[k] = v
    return out


def parse_server_log(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    summaries: list[dict[str, Any]] = []
    final = None
    if not path.exists(): return summaries, final
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = LOG_RE.match(line)
        if not m: continue
        ts, kind, body = m.groups()
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            ns = int(dt.timestamp() * 1_000_000_000)
        except ValueError:
            ns = None
        row = parse_kv_line(body)
        row["_kind"] = kind
        row["_timestamp"] = ts
        row["_utc_ns"] = ns
        summaries.append(row)
        if kind == "FINAL": final = row
    return summaries, final
