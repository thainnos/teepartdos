from __future__ import annotations
import math, statistics
from collections import Counter
from pathlib import Path
from typing import Any, Iterable
from .config import EvalConfig
from .parsing import read_json, read_csv, first_matching, numeric, integer, parse_server_log

METRICS = ["tcp_connect_us", "tls_handshake_us", "connection_establishment_us", "app_rtt_us", "probe_total_us"]


def percentile(vals: list[float], p: float) -> float | None:
    if not vals: return None
    s = sorted(vals)
    if len(s) == 1: return s[0]
    x = (len(s)-1)*p
    lo, hi = math.floor(x), math.ceil(x)
    if lo == hi: return s[lo]
    return s[lo]*(hi-x)+s[hi]*(x-lo)


def stats(vals: list[float]) -> dict[str, Any]:
    if not vals: return {"n": 0, "median_ms": None, "q1_ms": None, "q3_ms": None, "iqr_ms": None, "p95_ms": None, "p99_ms": None, "max_ms": None}
    ms = [v/1000.0 for v in vals]
    q1, q3 = percentile(ms,.25), percentile(ms,.75)
    return {"n": len(ms), "median_ms": statistics.median(ms), "q1_ms": q1, "q3_ms": q3, "iqr_ms": (q3-q1) if q1 is not None and q3 is not None else None, "p95_ms": percentile(ms,.95), "p99_ms": percentile(ms,.99), "max_ms": max(ms)}


def _scheduled_us(row: dict[str,Any]) -> float | None:
    value=numeric(row.get("scheduled_elapsed_us"))
    if value is None:
        value=numeric(row.get("elapsed_run_us"))
    return value


def infer_reference_period_us(rows: list[dict[str,Any]], configured_probe_interval_ms: float | None = None) -> float:
    """Return the reference schedule period used to reconstruct missed slots.

    Prefer the client metadata because it is the authoritative configured
    cadence.  Older result sets can still be evaluated by inferring the period
    from adjacent scheduled slots.  A row with m missed slots spans m+1 schedule
    periods from the previous emitted row.
    """
    if configured_probe_interval_ms is not None and configured_probe_interval_ms > 0:
        return configured_probe_interval_ms * 1000.0
    periods=[]
    previous=None
    for row in rows:
        current=_scheduled_us(row)
        if current is None:
            continue
        if previous is not None and current > previous:
            missed=max(0,integer(row.get("missed_slots_before")) or 0)
            periods.append((current-previous)/(missed+1))
        previous=current
    if periods:
        return statistics.median(periods)
    return 1_000_000.0


def reconstruct_reference_opportunities(rows: list[dict[str,Any]], configured_probe_interval_ms: float | None = None) -> tuple[list[dict[str,Any]],float]:
    """Expand emitted rows plus missed slots into scheduled probe opportunities.

    `missed_slots_before` belongs to the schedule interval immediately before
    the emitted row that reports it.  Assigning those misses to the emitted
    row's phase is wrong when a long probe crosses a baseline/load/recovery
    boundary.  Each missing slot therefore receives its own reconstructed
    scheduled timestamp before phase classification.
    """
    period_us=infer_reference_period_us(rows,configured_probe_interval_ms)
    opportunities=[]
    for row in rows:
        scheduled_us=_scheduled_us(row)
        if scheduled_us is None:
            continue
        missed=max(0,integer(row.get("missed_slots_before")) or 0)
        for offset in range(missed,0,-1):
            miss_us=scheduled_us-offset*period_us
            opportunities.append({
                "_opportunity_kind":"missed",
                "_scheduled_elapsed_us":miss_us,
                "_scheduled_elapsed_s":miss_us/1e6,
                "result_code":None,
                "failure_stage":"missed_slot",
            })
        emitted=dict(row)
        emitted["_opportunity_kind"]="emitted"
        emitted["_scheduled_elapsed_us"]=scheduled_us
        emitted["_scheduled_elapsed_s"]=scheduled_us/1e6
        opportunities.append(emitted)
    opportunities.sort(key=lambda x:x["_scheduled_elapsed_us"])
    return opportunities,period_us


def phase_rows(rows: list[dict[str,Any]], start_s: float, end_s: float) -> list[dict[str,Any]]:
    """Return emitted reference rows by scheduled (not completion) time."""
    out=[]
    for row in rows:
        scheduled_us=_scheduled_us(row)
        if scheduled_us is not None and start_s <= scheduled_us/1e6 < end_s:
            out.append(row)
    return out


def phase_opportunities(opportunities: list[dict[str,Any]], start_s: float, end_s: float) -> list[dict[str,Any]]:
    return [o for o in opportunities if start_s <= float(o["_scheduled_elapsed_s"]) < end_s]


def phase_summary(opportunities: list[dict[str,Any]]) -> dict[str,Any]:
    emitted=[o for o in opportunities if o.get("_opportunity_kind")!="missed"]
    ok=[o for o in emitted if integer(o.get("result_code")) == 0]
    failures=Counter()
    missed=0
    for opportunity in opportunities:
        if opportunity.get("_opportunity_kind")=="missed":
            missed += 1
            failures["missed_slot"] += 1
        elif integer(opportunity.get("result_code")) != 0:
            failures[opportunity.get("failure_stage") or "unknown"] += 1
    m={}
    for key in METRICS:
        vals=[numeric(r.get(key)) for r in ok]
        m[key]=stats([v for v in vals if v is not None])
    n=len(emitted); total=len(opportunities)
    return {"probes":n,"scheduled_opportunities":total,"successes":len(ok),"failures":total-len(ok),"success_rate":len(ok)/total if total else None,"failure_stages":dict(failures),"missed_slots":missed,"metrics":m}


def _metric_guard(base: dict[str,Any], key: str, cfg: EvalConfig) -> float:
    absolute=cfg.latency_abs_app_ms if key=="app_rtt_us" else cfg.latency_abs_default_ms
    iqr=base.get("iqr_ms") or 0.0
    return max(absolute,cfg.latency_iqr_fraction*iqr)


def latency_triggers(base: dict[str,Any], load: dict[str,Any], cfg: EvalConfig, workload: str) -> list[dict[str,Any]]:
    keys=["app_rtt_us","probe_total_us"] if workload=="record" else METRICS
    triggers=[]
    for key in keys:
        b=base["metrics"].get(key,{}); l=load["metrics"].get(key,{})
        if not b.get("n") or not l.get("n"): continue
        guard=_metric_guard(b,key,cfg)
        for stat_key in ("median_ms","p95_ms"):
            bv=b.get(stat_key); lv=l.get(stat_key)
            if bv is None or lv is None: continue
            delta=lv-bv; ratio=(lv/bv) if bv>0 else None
            if ratio is not None and ratio >= 1+cfg.latency_relative and delta >= guard:
                triggers.append({"metric":key,"stat":stat_key,"baseline_ms":bv,"load_ms":lv,"delta_ms":delta,"ratio":ratio,"guard_ms":guard})
    return triggers


def baseline_stability(rows: list[dict[str,str]], start_s: float, end_s: float, workload: str, cfg: EvalConfig) -> dict[str,Any]:
    primary="app_rtt_us" if workload=="record" else "probe_total_us"
    width=(end_s-start_s)/cfg.baseline_windows
    meds=[]
    for i in range(cfg.baseline_windows):
        pr=phase_rows(rows,start_s+i*width,start_s+(i+1)*width)
        vals=[numeric(r.get(primary)) for r in pr if integer(r.get("result_code"))==0]
        vals=[x for x in vals if x is not None]
        meds.append(statistics.median(vals)/1000.0 if vals else None)
    valid=[x for x in meds if x is not None]
    overall=statistics.median(valid) if valid else None
    spread=((max(valid)-min(valid))/overall) if len(valid)==cfg.baseline_windows and overall and overall>0 else None
    return {"primary_metric":primary,"window_medians_ms":meds,"spread_fraction":spread,"status":"stable" if spread is not None and spread<cfg.baseline_spread else "insufficient" if spread is None else "unstable"}


def recovery_assessment(base: dict[str,Any], rec: dict[str,Any], workload: str, cfg: EvalConfig) -> dict[str,Any]:
    if not rec.get("probes"): return {"status":"N/A","checks":[]}
    checks=[]
    bsr=base.get("success_rate"); rsr=rec.get("success_rate")
    success_ok=bsr is not None and rsr is not None and rsr >= bsr - cfg.recovery_success_pp/100.0
    checks.append({"name":"success_rate","ok":success_ok,"baseline":bsr,"recovery":rsr})
    keys=["app_rtt_us","probe_total_us"] if workload=="record" else ["connection_establishment_us","app_rtt_us","probe_total_us"]
    for key in keys:
        b=base["metrics"].get(key,{}); r=rec["metrics"].get(key,{})
        if not b.get("n") or not r.get("n"): continue
        guard=_metric_guard(b,key,cfg)
        for sk in ("median_ms","p95_ms"):
            bv=b.get(sk); rv=r.get(sk)
            if bv is None or rv is None: continue
            tol=max(cfg.recovery_relative*bv,guard)
            checks.append({"name":f"{key}.{sk}","ok":rv<=bv+tol,"baseline_ms":bv,"recovery_ms":rv,"tolerance_ms":tol})
    oks=[c["ok"] for c in checks]
    failure_fraction = 1.0 - rsr if rsr is not None else 1.0
    if oks and all(oks):
        status="recovered"
    elif failure_fraction >= cfg.ref_saturated_fraction:
        # Continued availability loss at the saturation threshold means the
        # service has not recovered, irrespective of individual latency checks.
        status="not recovered"
    else:
        status="partially recovered"
    return {"status":status,"checks":checks,"failure_fraction":failure_fraction}


def counter_snapshot(summaries: list[dict[str,Any]], ref_start_ns: int, target_elapsed_s: float) -> dict[str,Any] | None:
    target=ref_start_ns+int(target_elapsed_s*1e9)
    eligible=[s for s in summaries if isinstance(s.get("_utc_ns"),int) and s["_utc_ns"]<=target]
    return eligible[-1] if eligible else None


def counter_delta(a: dict[str,Any] | None,b: dict[str,Any] | None) -> dict[str,int]:
    if a is None or b is None: return {}
    out={}
    for k,v in b.items():
        if k.startswith("_") or not isinstance(v,int): continue
        av=a.get(k)
        if isinstance(av,int) and v>=av: out[k]=v-av
    return out


def analyze_run(results_root: Path, item: dict[str,Any], cfg: EvalConfig) -> dict[str,Any]:
    rr=item["record"]; point=item["point"]; run_dir=results_root/rr["result_path"]
    manifest=read_json(run_dir/"run_manifest.json")
    validation=read_json(run_dir/"validation.json") if (run_dir/"validation.json").exists() else {"status":"MISSING","errors":["validation.json missing"],"warnings":[]}
    timeline=read_json(run_dir/"timeline.json")
    refp=first_matching(run_dir/"reference","*.csv")
    if refp is None: raise RuntimeError(f"reference CSV missing for {rr['run_id']}")
    rows=read_csv(refp)
    refmetap=first_matching(run_dir/"reference","*.metadata.json")
    ref_meta=read_json(refmetap) if refmetap else {}
    configured_probe_interval_ms=numeric(ref_meta.get("configured_probe_interval_ms"))
    opportunities,period_us=reconstruct_reference_opportunities(rows,configured_probe_interval_ms)
    load_start=float(timeline["generator_phase_run_start_elapsed_from_reference_s"])
    load_end=float(timeline["generator_phase_run_end_elapsed_from_reference_s"])
    ref_duration=float(manifest.get("reference_duration_s",point.get("reference_duration_s",300)))
    baseline=phase_summary(phase_opportunities(opportunities,0.0,load_start))
    load=phase_summary(phase_opportunities(opportunities,load_start,load_end))
    recovery=phase_summary(phase_opportunities(opportunities,load_end,ref_duration+1e-6))
    rec_len=max(0.0,ref_duration-load_end)
    final_len=max(cfg.recovery_min_target_s, rec_len*cfg.recovery_final_fraction) if rec_len else 0
    final_len=min(final_len,rec_len)
    rec_final=phase_summary(phase_opportunities(opportunities,ref_duration-final_len,ref_duration+1e-6)) if rec_len else phase_summary([])
    stability=baseline_stability(rows,0.0,load_start,manifest["reference_workload"],cfg)
    triggers=latency_triggers(baseline,load,cfg,manifest["reference_workload"])
    genp=first_matching(run_dir/"generator","output/**/generator_stats.csv")
    metap=first_matching(run_dir/"generator","output/**/generator.metadata.json")
    gen_rows=read_csv(genp) if genp else []
    gen_meta=read_json(metap) if metap else {}
    gen_final=gen_rows[-1] if gen_rows else {}
    workload=str(manifest["generator_workload"])
    offered=integer(gen_final.get("offered_total")) or 0; attempted=integer(gen_final.get("attempted_total")) or 0; completed=integer(gen_final.get("completed_total")) or 0
    gen_completion=completed/offered if offered else None
    gen={"offered":offered,"attempted":attempted,"completed":completed,"completion_ratio":gen_completion,
         "local_capacity_drop_total":integer(gen_final.get("local_capacity_drop_total")) or 0,
         "pending_release_max":integer(gen_final.get("pending_release_max")),"release_lag_max_us":integer(gen_final.get("release_lag_max_us")),
         "tcp_established_total":integer(gen_final.get("tcp_established_total")),"full_handshake_ok_total":integer(gen_final.get("full_handshake_ok_total")),
         "resumed_handshake_ok_total":integer(gen_final.get("resumed_handshake_ok_total")),"handshake_fail_total":integer(gen_final.get("handshake_fail_total")),
         "app_ok_total":integer(gen_final.get("app_ok_total")),"app_fail_total":integer(gen_final.get("app_fail_total")),"timeout_fail_total":integer(gen_final.get("timeout_fail_total")),
         "rate_semantics":gen_meta.get("rate_semantics","configured_offered_rate"),
         "external_runner_version":gen_meta.get("external_runner_version"),
         "external_label":gen_meta.get("external_label"),
         "external_process_completed":integer(gen_final.get("external_process_completed")),
         "external_tool_exit_code":integer(gen_final.get("external_tool_exit_code")),
         "external_interface_tx_packets_delta":integer(gen_final.get("external_interface_tx_packets_delta")),
         "external_interface_tx_bytes_delta":integer(gen_final.get("external_interface_tx_bytes_delta")),
         "external_interface_tx_dropped_delta":integer(gen_final.get("external_interface_tx_dropped_delta")),
         "external_observed_tx_pps":numeric(gen_final.get("external_observed_tx_pps")),
         "external_observed_tx_mbps":numeric(gen_final.get("external_observed_tx_mbps"))}
    summaries, final=parse_server_log(run_dir/"dut"/"server.log")
    dut={k:v for k,v in (final or {}).items() if not k.startswith("_")}
    ref_start=int(timeline["reference_actual_start_utc_ns"])
    snap0=counter_snapshot(summaries,ref_start,0.0) or (summaries[0] if summaries else None)
    snap_ls=counter_snapshot(summaries,ref_start,load_start)
    snap_le=counter_snapshot(summaries,ref_start,load_end)
    snap_end=final or (summaries[-1] if summaries else None)
    phase_counter_deltas={"baseline":counter_delta(snap0,snap_ls),"load":counter_delta(snap_ls,snap_le),"recovery":counter_delta(snap_le,snap_end)}
    warnings=list(validation.get("warnings",[]))
    period_s=period_us/1e6 if period_us>0 else None
    expected_opportunities=int(math.ceil((ref_duration-1e-9)/period_s)) if period_s else None
    counted_opportunities=len(phase_opportunities(opportunities,0.0,ref_duration+1e-6))
    if expected_opportunities is not None and counted_opportunities != expected_opportunities:
        warnings.append(f"reference schedule reconstructed {counted_opportunities} opportunities, expected {expected_opportunities} from duration/cadence")
    if stability["status"]=="unstable": warnings.append("baseline primary metric failed stability threshold")
    invalid=validation.get("status")!="PASS" or (workload != "tcp-syn" and gen["local_capacity_drop_total"]>0)
    if workload == "tcp-syn":
        if gen.get("external_process_completed") != 1:
            warnings.append("external tool did not complete the configured measurement duration")
            invalid=True
        if not (gen.get("external_interface_tx_packets_delta") or 0) > 0:
            warnings.append("external tool run reports no transmitted packets on the configured interface")
            invalid=True
    failfrac=1-(load.get("success_rate") or 0.0) if load.get("success_rate") is not None else 1.0
    saturated_reasons=[]; degraded_reasons=[]
    if failfrac>=cfg.ref_saturated_fraction: saturated_reasons.append(f"reference failure fraction {failfrac:.3f} >= {cfg.ref_saturated_fraction:.3f}")
    elif failfrac>=cfg.ref_degraded_fraction and failfrac>0: degraded_reasons.append(f"reference failure fraction {failfrac:.3f} > 0")
    if gen_completion is not None:
        if gen_completion<cfg.gen_saturated_completion: saturated_reasons.append(f"generator completion {gen_completion:.3f} < {cfg.gen_saturated_completion:.3f}")
        elif gen_completion<cfg.gen_healthy_completion: degraded_reasons.append(f"generator completion {gen_completion:.3f} < {cfg.gen_healthy_completion:.3f}")
    if int(dut.get("dropped_no_slot",0) or 0)>0: saturated_reasons.append(f"DUT dropped_no_slot={dut.get('dropped_no_slot')}")
    if triggers: degraded_reasons.append(f"{len(triggers)} latency threshold trigger(s)")
    if invalid: verdict="INVALID"
    elif stability["status"]=="unstable": verdict="INCONCLUSIVE"
    elif saturated_reasons: verdict="SATURATED"
    elif degraded_reasons: verdict="VALID / DEGRADED"
    else: verdict="VALID / NO DEGRADATION"
    recovery_eval=recovery_assessment(baseline,rec_final,manifest["reference_workload"],cfg)
    tee={}
    if manifest["scenario"]!="A":
        prefixes=("tee_","backend_","km_","sign_","record_","finished_","async_")
        tee={k:v for k,v in dut.items() if k.startswith(prefixes)}
    clock=read_json(run_dir/"clock_preflight.json") if (run_dir/"clock_preflight.json").exists() else {}
    return {"run_id":rr["run_id"],"campaign_id":manifest.get("campaign_id"),"overall_campaign_id":manifest.get("overall_campaign_id"),
            "scenario":manifest["scenario"],"profile":manifest["profile"],"workload":manifest["generator_workload"],"reference_workload":manifest["reference_workload"],
            "mode":manifest["generator_mode"],"backend":manifest["generator_backend"],"rate":float(manifest["generator_rate"]),"rate_semantics":gen.get("rate_semantics"),"repetition":int(manifest["repetition"]),
            "artifact_versions":{"orchestrator":manifest.get("orchestrator_version"),"loadgen_profile":manifest.get("loadgen_profile",{}),"external_runner":gen.get("external_runner_version")},
            "validity":{"validation_status":validation.get("status"),"errors":validation.get("errors",[]),"warnings":warnings},
            "phase_boundaries_s":{"baseline_start":0.0,"load_start":load_start,"load_end":load_end,"reference_end":ref_duration,"recovery_final_start":ref_duration-final_len},
            "reference_schedule":{"configured_probe_interval_ms":configured_probe_interval_ms,"effective_probe_interval_ms":period_us/1000.0,"expected_opportunities":expected_opportunities,"reconstructed_opportunities":counted_opportunities},
            "baseline_stability":stability,"phases":{"baseline":baseline,"load":load,"recovery":recovery,"recovery_final":rec_final},
            "latency_triggers":triggers,"generator":gen,"dut_final":dut,"tee_final":tee,"dut_phase_counter_deltas":phase_counter_deltas,
            "recovery_assessment":recovery_eval,"performance_verdict":verdict,"saturated_reasons":saturated_reasons,"degraded_reasons":degraded_reasons,
            "clock_preflight":{"errors":clock.get("errors",[]),"hosts":{k:{"offset_ms":v.get("offset_ms"),"uncertainty_ms":v.get("uncertainty_ms")} for k,v in clock.get("hosts",{}).items()}},
            "_reference_rows":rows}


def _median_or_none(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def aggregate_runs(runs: list[dict[str,Any]], cfg: EvalConfig, campaign_type: str) -> dict[str,Any]:
    groups={}
    for r in runs:
        key=(r["scenario"],r["workload"],r["rate"])
        groups.setdefault(key,[]).append(r)
    points=[]
    rank={"INVALID":4,"INCONCLUSIVE":3,"SATURATED":2,"VALID / DEGRADED":1,"VALID / NO DEGRADATION":0}
    for key,rs in sorted(groups.items()):
        scenario,workload,rate=key
        verdicts=[r["performance_verdict"] for r in rs]
        if "INVALID" in verdicts: verdict="INVALID"
        elif "INCONCLUSIVE" in verdicts: verdict="INCONCLUSIVE"
        elif campaign_type=="repeated":
            support=sum(v in ("VALID / DEGRADED","SATURATED") for v in verdicts)/len(verdicts)
            if support>=cfg.repeated_support:
                verdict="SATURATED" if sum(v=="SATURATED" for v in verdicts)/len(verdicts)>=cfg.repeated_support else "VALID / DEGRADED"
            else: verdict="VALID / NO DEGRADATION"
        else:
            verdict=max(verdicts,key=lambda v:rank.get(v,-1))
        point={"scenario":scenario,"workload":workload,"rate":rate,"n":len(rs),"verdict":verdict,"run_ids":[r["run_id"] for r in rs],
               "rate_semantics":rs[0].get("rate_semantics"),
               "median_load_success_rate":_median_or_none([r["phases"]["load"]["success_rate"] for r in rs if r["phases"]["load"]["success_rate"] is not None]),
               "median_generator_completion":_median_or_none([r["generator"]["completion_ratio"] for r in rs if r["generator"]["completion_ratio"] is not None]),
               "median_external_observed_tx_pps":_median_or_none([r["generator"]["external_observed_tx_pps"] for r in rs if r["generator"].get("external_observed_tx_pps") is not None]),
               "median_external_observed_tx_mbps":_median_or_none([r["generator"]["external_observed_tx_mbps"] for r in rs if r["generator"].get("external_observed_tx_mbps") is not None]),
               "recovery_statuses":[r["recovery_assessment"]["status"] for r in rs]}
        for metric in ("probe_total_us","app_rtt_us","connection_establishment_us"):
            values=[r["phases"]["load"]["metrics"][metric]["median_ms"] for r in rs if r["phases"]["load"]["metrics"][metric]["median_ms"] is not None]
            point[f"median_run_load_{metric}_median_ms"]=_median_or_none(values)
            point[f"load_{metric}_run_count"]=len(values)
        points.append(point)
    knees=[]
    for scenario in sorted({p["scenario"] for p in points}):
        for workload in sorted({p["workload"] for p in points if p["scenario"]==scenario}):
            ps=sorted([p for p in points if p["scenario"]==scenario and p["workload"]==workload],key=lambda x:x["rate"])
            if workload == "tcp-syn":
                knees.append({"scenario":scenario,"workload":workload,"preliminary":False,"knee_rate":None,"last_non_degraded_rate":None,
                              "first_degraded_or_saturated_rate":None,"interval":None,"applicable":False,"note":"single external TCP stress condition; rate-knee inference is not applicable"})
                continue
            candidate=None
            for i,p in enumerate(ps):
                if p["verdict"] in ("VALID / DEGRADED","SATURATED") and all(q["verdict"] in ("VALID / DEGRADED","SATURATED") for q in ps[i:]):
                    candidate=p; break
            last_clean=max((p["rate"] for p in ps if p["verdict"]=="VALID / NO DEGRADATION"),default=None)
            knees.append({"scenario":scenario,"workload":workload,"preliminary":campaign_type=="pilot","knee_rate":candidate["rate"] if candidate else None,"last_non_degraded_rate":last_clean,
                          "first_degraded_or_saturated_rate":candidate["rate"] if candidate else None,
                          "interval":[last_clean,candidate["rate"]] if last_clean is not None and candidate else None,"applicable":True})

    # Higher-level verdicts are intentionally derived from matrix-point verdicts
    # rather than raw probe rows. This preserves the complete run as the
    # independent experimental unit for repeated campaigns.
    def group_verdict(vs: list[str]) -> str:
        if any(v == "INVALID" for v in vs): return "INVALID"
        if any(v == "INCONCLUSIVE" for v in vs): return "INCONCLUSIVE"
        if any(v == "SATURATED" for v in vs): return "SATURATED"
        if any(v == "VALID / DEGRADED" for v in vs): return "VALID / DEGRADED"
        return "VALID / NO DEGRADATION"

    workload_summaries=[]
    for scenario in sorted({p["scenario"] for p in points}):
        for workload in sorted({p["workload"] for p in points if p["scenario"]==scenario}):
            ps=[p for p in points if p["scenario"]==scenario and p["workload"]==workload]
            knee=next(k for k in knees if k["scenario"]==scenario and k["workload"]==workload)
            workload_summaries.append({"scenario":scenario,"workload":workload,"verdict":group_verdict([p["verdict"] for p in ps]),"tested_rates":[p["rate"] for p in sorted(ps,key=lambda x:x["rate"])],"knee":knee})
    scenario_summaries=[]
    for scenario in sorted({p["scenario"] for p in points}):
        ws=[w for w in workload_summaries if w["scenario"]==scenario]
        scenario_summaries.append({"scenario":scenario,"verdict":group_verdict([w["verdict"] for w in ws]),"workloads":[w["workload"] for w in ws]})

    # Direct Scenario-A comparisons are emitted only at exactly matched workload
    # and offered-rate points. Unmatched rates are never interpolated.
    comparisons=[]
    a={(p["workload"],p["rate"]):p for p in points if p["scenario"]=="A"}
    for p in points:
        if p["scenario"]=="A": continue
        ap=a.get((p["workload"],p["rate"]))
        if not ap: continue
        comp={"scenario":p["scenario"],"workload":p["workload"],"rate":p["rate"],"scenario_verdict":p["verdict"],"a_verdict":ap["verdict"],
              "load_success_delta_pp":100*(p["median_load_success_rate"]-ap["median_load_success_rate"]) if p["median_load_success_rate"] is not None and ap["median_load_success_rate"] is not None else None,
              "generator_completion_delta_pp":100*(p["median_generator_completion"]-ap["median_generator_completion"]) if p["median_generator_completion"] is not None and ap["median_generator_completion"] is not None else None,
              "external_observed_tx_pps_ratio_to_A":(p["median_external_observed_tx_pps"]/ap["median_external_observed_tx_pps"]) if p.get("median_external_observed_tx_pps") is not None and ap.get("median_external_observed_tx_pps") not in (None,0) else None,
              "external_observed_tx_mbps_ratio_to_A":(p["median_external_observed_tx_mbps"]/ap["median_external_observed_tx_mbps"]) if p.get("median_external_observed_tx_mbps") is not None and ap.get("median_external_observed_tx_mbps") not in (None,0) else None}
        # Repeated campaigns are compared using point-level medians of the
        # independent run medians.  Never let dictionary overwrite order pick
        # an arbitrary repetition for the Scenario-A latency ratio.
        for metric in ("probe_total_us","app_rtt_us","connection_establishment_us"):
            key=f"median_run_load_{metric}_median_ms"
            count_key=f"load_{metric}_run_count"
            sv=p.get(key); av=ap.get(key)
            if campaign_type=="repeated":
                required_s=math.ceil(cfg.repeated_support*p["n"]-1e-12)
                required_a=math.ceil(cfg.repeated_support*ap["n"]-1e-12)
            else:
                required_s=required_a=1
            supported=(p.get(count_key,0)>=required_s and ap.get(count_key,0)>=required_a)
            comp[f"{metric}_load_median_ratio_to_A"]=(sv/av) if supported and sv is not None and av not in (None,0) else None
            comp[f"{metric}_comparison_run_support"]={"scenario":p.get(count_key,0),"scenario_required":required_s,"scenario_A":ap.get(count_key,0),"scenario_A_required":required_a}
        comparisons.append(comp)
    return {"points":points,"knees":knees,"workloads":workload_summaries,"scenarios":scenario_summaries,"comparisons_to_A":comparisons}
