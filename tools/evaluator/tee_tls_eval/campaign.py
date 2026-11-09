from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from .parsing import read_json

@dataclass
class Selection:
    results_root: Path
    selection_type: str
    selection_id: str
    campaign_type: str
    backend: str
    mode: str
    campaigns: list[dict[str, Any]]
    runs: list[dict[str, Any]]
    warnings: list[str]


def _index(root: Path) -> dict[str, Any]:
    p = root / "_campaigns" / "index.json"
    if not p.exists(): raise RuntimeError(f"campaign index missing: {p}")
    return read_json(p)


def select(root: Path, campaign_id: str | None, overall_id: str | None) -> Selection:
    if bool(campaign_id) == bool(overall_id):
        raise RuntimeError("specify exactly one of campaign_id or overall_campaign_id")
    idx = _index(root)
    warnings: list[str] = []
    campaign_entries: list[dict[str, Any]] = []
    if campaign_id:
        matches = [x for x in idx.get("campaigns", []) if x.get("campaign_id") == campaign_id]
        if len(matches) != 1: raise RuntimeError(f"campaign ID {campaign_id!r} found {len(matches)} times")
        campaign_entries = matches
        sel_type, sel_id = "campaign", campaign_id
    else:
        matches = [x for x in idx.get("overall_campaigns", []) if x.get("overall_campaign_id") == overall_id]
        if len(matches) != 1: raise RuntimeError(f"overall campaign ID {overall_id!r} found {len(matches)} times")
        om = read_json(root / matches[0]["manifest_path"])
        for scenario, c in sorted(om.get("campaigns", {}).items()):
            campaign_entries.append({
                "campaign_id": c["campaign_id"], "manifest_path": c["manifest_path"],
                "campaign_type": om["campaign_type"], "generator_backend": om["generator_backend"],
                "generator_mode": om["generator_mode"], "scenario": scenario, "status": c["status"],
                "overall_campaign_id": overall_id,
            })
        sel_type, sel_id = "overall_campaign", overall_id
    campaigns, runs = [], []
    types, backends, modes = set(), set(), set()
    for e in campaign_entries:
        cm = read_json(root / e["manifest_path"])
        campaigns.append(cm)
        types.add(cm.get("campaign_type")); backends.add(cm.get("generator_backend")); modes.add(cm.get("generator_mode"))
        selected_by_point: dict[str, list[dict[str, Any]]] = {}
        for rr in cm.get("runs", []):
            if rr.get("selection") == "selected": selected_by_point.setdefault(rr.get("point_id", ""), []).append(rr)
        expected = {p["point_id"]: p for p in cm.get("expected_points", [])}
        for pid, entries in selected_by_point.items():
            if len(entries) != 1: raise RuntimeError(f"{cm['campaign_id']}: point {pid} has {len(entries)} selected runs")
            rr = entries[0]
            if rr.get("validation_status") != "PASS":
                warnings.append(f"selected run {rr.get('run_id')} has validation {rr.get('validation_status')}")
            point = expected.get(pid)
            if point is None: raise RuntimeError(f"selected point {pid} absent from expected_points")
            runs.append({"campaign": cm, "point": point, "record": rr})
        missing = set(expected) - set(selected_by_point)
        if missing: warnings.append(f"{cm['campaign_id']} has {len(missing)} expected points without a selected run")
    if len(types) != 1 or len(backends) != 1 or len(modes) != 1:
        raise RuntimeError("selected campaigns mix campaign type, backend, or generator mode")
    return Selection(root, sel_type, sel_id, str(next(iter(types))), str(next(iter(backends))), str(next(iter(modes))), campaigns, runs, warnings)
