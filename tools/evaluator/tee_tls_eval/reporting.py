from __future__ import annotations
import csv, json, tempfile
from pathlib import Path
from typing import Any
from .analysis import reconstruct_reference_opportunities
import matplotlib.pyplot as plt
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, KeepTogether


def _fmt(v, digits=3):
    if v is None: return "N/A"
    if isinstance(v,float): return f"{v:.{digits}f}"
    return str(v)

def _pct(v): return "N/A" if v is None else f"{100*v:.1f}%"

def _status_summary(values:list[str])->str:
    if not values: return "N/A"
    labels={"recovered":"recovered","partially recovered":"partial","not recovered":"not recovered","N/A":"N/A"}
    ordered=[]
    for value in values:
        if value not in ordered: ordered.append(value)
    parts=[]
    for value in ordered:
        count=values.count(value)
        label=labels.get(value,value)
        parts.append(f"{count} {label}" if count>1 else label)
    return "; ".join(parts)

def _rate_label(workload, rate):
    return "external" if workload == "tcp-syn" else f"{rate:g}/s"

def write_json(path: Path, analysis: dict[str,Any]) -> None:
    def clean(x):
        if isinstance(x,dict): return {k:clean(v) for k,v in x.items() if not k.startswith("_")}
        if isinstance(x,list): return [clean(v) for v in x]
        return x
    path.write_text(json.dumps(clean(analysis),indent=2,sort_keys=True)+"\n",encoding="utf-8")


def write_csv(path: Path, analysis: dict[str,Any]) -> None:
    fields=["selection_id","campaign_type","scenario","workload","rate","repetition","run_id","verdict","recovery_status","baseline_stability",
            "baseline_success_rate","load_success_rate","recovery_success_rate","rate_semantics","generator_completion_ratio","generator_offered","generator_completed","generator_local_capacity_drop","external_process_completed","external_tool_exit_code","external_interface_tx_packets_delta","external_observed_tx_pps","external_observed_tx_mbps",
            "dut_dropped_no_slot","dut_hs_fail","dut_tee_conn_open_fail","dut_tee_conn_close_fail",
            "baseline_probe_median_ms","load_probe_median_ms","load_probe_p95_ms","baseline_app_rtt_median_ms","load_app_rtt_median_ms","load_app_rtt_p95_ms"]
    with path.open("w",newline="",encoding="utf-8") as fh:
        w=csv.DictWriter(fh,fieldnames=fields); w.writeheader()
        for r in analysis["runs"]:
            b,l,rec=r["phases"]["baseline"],r["phases"]["load"],r["phases"]["recovery"]
            row={"selection_id":analysis["selection"]["id"],"campaign_type":analysis["selection"]["campaign_type"],"scenario":r["scenario"],"workload":r["workload"],"rate":r["rate"],"repetition":r["repetition"],"run_id":r["run_id"],
                 "verdict":r["performance_verdict"],"recovery_status":r["recovery_assessment"]["status"],"baseline_stability":r["baseline_stability"]["status"],
                 "baseline_success_rate":b["success_rate"],"load_success_rate":l["success_rate"],"recovery_success_rate":rec["success_rate"],"rate_semantics":r.get("rate_semantics"),"generator_completion_ratio":r["generator"]["completion_ratio"],
                 "generator_offered":r["generator"]["offered"],"generator_completed":r["generator"]["completed"],"generator_local_capacity_drop":r["generator"]["local_capacity_drop_total"],"external_process_completed":r["generator"].get("external_process_completed"),"external_tool_exit_code":r["generator"].get("external_tool_exit_code"),"external_interface_tx_packets_delta":r["generator"].get("external_interface_tx_packets_delta"),"external_observed_tx_pps":r["generator"].get("external_observed_tx_pps"),"external_observed_tx_mbps":r["generator"].get("external_observed_tx_mbps"),
                 "dut_dropped_no_slot":r["dut_final"].get("dropped_no_slot"),"dut_hs_fail":r["dut_final"].get("hs_fail"),"dut_tee_conn_open_fail":r["dut_final"].get("tee_conn_open_fail"),"dut_tee_conn_close_fail":r["dut_final"].get("tee_conn_close_fail"),
                 "baseline_probe_median_ms":b["metrics"]["probe_total_us"]["median_ms"],"load_probe_median_ms":l["metrics"]["probe_total_us"]["median_ms"],"load_probe_p95_ms":l["metrics"]["probe_total_us"]["p95_ms"],
                 "baseline_app_rtt_median_ms":b["metrics"]["app_rtt_us"]["median_ms"],"load_app_rtt_median_ms":l["metrics"]["app_rtt_us"]["median_ms"],"load_app_rtt_p95_ms":l["metrics"]["app_rtt_us"]["p95_ms"]}
            w.writerow(row)


def _campaign_plot(analysis:dict[str,Any], scenario:str, workload:str, out:Path)->None:
    pts=sorted([p for p in analysis["aggregate"]["points"] if p["scenario"]==scenario and p["workload"]==workload],key=lambda x:x["rate"])
    if not pts:return
    if workload == "tcp-syn":
        succ=[100*p["median_load_success_rate"] for p in pts if p["median_load_success_rate"] is not None]
        if not succ:return
        fig,ax=plt.subplots(figsize=(7.2,3.6)); ax.bar(range(len(succ)),succ); ax.set_xticks(range(len(succ)),["external TCP"]*len(succ)); ax.set_ylabel("Reference load success (%)"); ax.set_ylim(0,102); ax.set_title(f"Scenario {scenario} - external TCP stress"); ax.grid(True,axis="y",alpha=.25); fig.tight_layout(); fig.savefig(out,dpi=160); plt.close(fig); return
    rates=[p["rate"] for p in pts]; succ=[100*p["median_load_success_rate"] for p in pts]; gen=[100*p["median_generator_completion"] for p in pts]
    fig,ax=plt.subplots(figsize=(7.2,3.6)); ax.plot(rates,succ,marker="o",label="Reference load success"); ax.plot(rates,gen,marker="o",label="Generator completion"); ax.set_xlabel("Offered rate"); ax.set_ylabel("Percent"); ax.set_ylim(-2,102); ax.set_title(f"Scenario {scenario} - {workload}"); ax.grid(True,alpha=.25); ax.legend(); fig.tight_layout(); fig.savefig(out,dpi=160); plt.close(fig)


def _reference_plot_points(rows:list[dict[str,Any]], metric:str, probe_interval_ms:float|None=None)->dict[str,list[float]]:
    """Return independent reference-probe points on the scheduled time axis.

    The same opportunity reconstruction used by phase accounting is reused for
    plotting.  This keeps successful, failed, and missed probe markers aligned
    to their intended schedule slots and avoids inventing observations between
    independent probes.
    """
    opportunities,_=reconstruct_reference_opportunities(rows,probe_interval_ms)
    success_x: list[float] = []
    success_y: list[float] = []
    failed_x: list[float] = []
    missed_x: list[float] = []
    for opportunity in opportunities:
        x=float(opportunity["_scheduled_elapsed_s"])
        if opportunity.get("_opportunity_kind")=="missed":
            missed_x.append(x)
            continue
        try:
            result=int(opportunity.get("result_code","-1"))
        except (TypeError,ValueError):
            result=-1
        if result == 0:
            try:
                value_ms=float(opportunity[metric])/1000.0
            except (TypeError,ValueError,KeyError):
                continue
            success_x.append(x)
            success_y.append(value_ms)
        else:
            failed_x.append(x)
    return {"success_x":success_x,"success_y":success_y,"failed_x":failed_x,"missed_x":missed_x}


def _timeseries_plot(r:dict[str,Any], out:Path)->None:
    rows=r.get("_reference_rows",[])
    metric="app_rtt_us" if r["workload"]=="record" else "probe_total_us"
    points=_reference_plot_points(rows,metric,r.get("reference_schedule",{}).get("effective_probe_interval_ms"))
    fig,ax=plt.subplots(figsize=(7.2,3.2))
    if points["success_x"]:
        ax.scatter(points["success_x"],points["success_y"],s=10,label="Successful reference probe")
    # Failure/missed-slot markers use axis-relative y positions so they do not
    # distort the latency scale.  Their x positions remain scheduled time.
    if points["failed_x"]:
        ax.scatter(points["failed_x"],[0.045]*len(points["failed_x"]),marker="x",s=22,transform=ax.get_xaxis_transform(),label="Failed emitted probe",clip_on=False)
    if points["missed_x"]:
        ax.scatter(points["missed_x"],[0.018]*len(points["missed_x"]),marker="|",s=45,transform=ax.get_xaxis_transform(),label="Missed scheduled probe",clip_on=False)
    b=r["phase_boundaries_s"]
    ax.axvspan(b["load_start"],b["load_end"],alpha=.15)
    ax.set_xlabel("Reference elapsed time (s)")
    ax.set_ylabel("App RTT (ms)" if metric=="app_rtt_us" else "Probe total (ms)")
    ax.set_title(f"{r['scenario']} {r['workload']} {_rate_label(r['workload'],r['rate'])} - {r['performance_verdict']}")
    ax.grid(True,alpha=.25)
    if points["success_x"] or points["failed_x"] or points["missed_x"]:
        ax.legend(fontsize=7,loc="best")
    fig.tight_layout()
    fig.savefig(out,dpi=150)
    plt.close(fig)


def write_pdf(path:Path,analysis:dict[str,Any],appendix:bool=True)->None:
    styles=getSampleStyleSheet(); styles.add(ParagraphStyle(name="Small",parent=styles["BodyText"],fontSize=7.5,leading=9)); styles.add(ParagraphStyle(name="CenterTitle",parent=styles["Title"],alignment=TA_CENTER))
    doc=SimpleDocTemplate(str(path),pagesize=A4,rightMargin=13*mm,leftMargin=13*mm,topMargin=13*mm,bottomMargin=13*mm,title="TEE/TLS campaign evaluation")
    story=[]; sel=analysis["selection"]
    story += [Paragraph("TEE/TLS Campaign Evaluation",styles["CenterTitle"]),Paragraph(f"Selection: {sel['type']} <b>{sel['id']}</b>",styles["BodyText"]),Spacer(1,4*mm)]
    story.append(Paragraph("Executive verdict",styles["Heading1"])); story.append(Paragraph(analysis["overall_verdict"],styles["Heading2"]));
    story.append(Paragraph(f"Campaign type: {sel['campaign_type']}; backend: {sel['backend']}; generator mode: {sel['mode']}; selected runs: {len(analysis['runs'])}. Pilot verdicts are preliminary when n=1.",styles["BodyText"]));
    if analysis.get("warnings"): story.append(Paragraph("Selection/report warnings: "+"; ".join(analysis["warnings"]),styles["Small"]))
    story.append(Spacer(1,3*mm)); story.append(Paragraph("Point verdicts",styles["Heading1"]));
    data=[["Scenario","Workload","Rate","n","Verdict","Load success","Gen completion","Recovery"]]
    byrun={(r["scenario"],r["workload"],r["rate"]):r for r in analysis["runs"]}
    for p in analysis["aggregate"]["points"]:
        r=byrun.get((p["scenario"],p["workload"],p["rate"]))
        data.append([p["scenario"],p["workload"],_rate_label(p["workload"],p["rate"]),p["n"],p["verdict"],_pct(p["median_load_success_rate"]),_pct(p["median_generator_completion"]),_status_summary(p["recovery_statuses"])])
    t=Table(data,repeatRows=1,colWidths=[13*mm,30*mm,15*mm,8*mm,40*mm,23*mm,26*mm,31*mm]); t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("GRID",(0,0),(-1,-1),.25,colors.grey),("FONTSIZE",(0,0),(-1,-1),7),("VALIGN",(0,0),(-1,-1),"TOP"),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.whitesmoke]) ])); story.append(t)
    story.append(Spacer(1,4*mm)); story.append(Paragraph("Scenario and workload verdicts",styles["Heading1"]));
    hd=[["Level","Scenario","Workload","Verdict"]]
    for ssum in analysis["aggregate"].get("scenarios",[]): hd.append(["scenario",ssum["scenario"],"-",ssum["verdict"]])
    for wsum in analysis["aggregate"].get("workloads",[]): hd.append(["workload",wsum["scenario"],wsum["workload"],wsum["verdict"]])
    ht=Table(hd,repeatRows=1,colWidths=[25*mm,25*mm,45*mm,70*mm]); ht.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("GRID",(0,0),(-1,-1),.25,colors.grey),("FONTSIZE",(0,0),(-1,-1),7.5)])); story.append(ht)
    if analysis["aggregate"].get("comparisons_to_A"):
        story.append(Spacer(1,4*mm)); story.append(Paragraph("Direct comparison to Scenario A at matched rates",styles["Heading1"]));
        cd=[["Scenario","Workload","Rate","Scenario verdict","A verdict","Success delta (pp)","Probe median ratio"]]
        for c in analysis["aggregate"]["comparisons_to_A"]:
            cd.append([c["scenario"],c["workload"],_rate_label(c["workload"],c["rate"]),c["scenario_verdict"],c["a_verdict"],_fmt(c["load_success_delta_pp"],1),_fmt(c.get("probe_total_us_load_median_ratio_to_A"),2)])
        ct=Table(cd,repeatRows=1,colWidths=[15*mm,28*mm,14*mm,35*mm,35*mm,28*mm,28*mm]); ct.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("GRID",(0,0),(-1,-1),.25,colors.grey),("FONTSIZE",(0,0),(-1,-1),6.8),("VALIGN",(0,0),(-1,-1),"TOP") ])); story.append(ct)
    syn_points=[p for p in analysis["aggregate"]["points"] if p["workload"]=="tcp-syn"]
    if syn_points:
        story.append(Spacer(1,4*mm)); story.append(Paragraph("External TCP stress control",styles["Heading1"]))
        story.append(Paragraph("The tcp-syn workload is generated by an operator-supplied external command. Configured rate 0 is a tool-controlled-rate sentinel, not a traffic rate. The evaluator reports observed transmit packet/s from the load-generator interface and does not infer a rate knee from this single condition.",styles["Small"]))
        sd=[["Scenario","n","Verdict","Load success","Observed TX kpps","Observed TX Mbit/s","Recovery"]]
        for p in syn_points:
            pps=p.get("median_external_observed_tx_pps")
            sd.append([p["scenario"],p["n"],p["verdict"],_pct(p["median_load_success_rate"]),_fmt(pps/1000.0 if pps is not None else None,1),_fmt(p.get("median_external_observed_tx_mbps"),1),_status_summary(p["recovery_statuses"])])
        st=Table(sd,repeatRows=1,colWidths=[16*mm,8*mm,38*mm,25*mm,27*mm,30*mm,40*mm]); st.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("GRID",(0,0),(-1,-1),.25,colors.grey),("FONTSIZE",(0,0),(-1,-1),7.2)])); story.append(st)
    applicable_knees=[k for k in analysis["aggregate"]["knees"] if k.get("applicable", True)]
    if applicable_knees:
        story.append(Spacer(1,4*mm)); story.append(Paragraph("Preliminary knees",styles["Heading1"])); kd=[["Scenario","Workload","Last non-degraded","First degraded/saturated","Knee interval"]]
        for k in applicable_knees:
            kd.append([k["scenario"],k["workload"],_fmt(k["last_non_degraded_rate"]),_fmt(k["first_degraded_or_saturated_rate"]),str(k["interval"]) if k["interval"] else "not bounded"])
        kt=Table(kd,repeatRows=1,colWidths=[20*mm,38*mm,35*mm,45*mm,45*mm]); kt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("GRID",(0,0),(-1,-1),.25,colors.grey),("FONTSIZE",(0,0),(-1,-1),7.5)])); story.append(kt)
    with tempfile.TemporaryDirectory(prefix="tee_tls_eval_") as td:
        td=Path(td)
        story.append(PageBreak()); story.append(Paragraph("Campaign plots",styles["Heading1"]));
        for scenario in sorted({r["scenario"] for r in analysis["runs"]}):
            for workload in ("full-handshake","resumption","record","tcp-syn"):
                pp=td/f"campaign_{scenario}_{workload}.png"; _campaign_plot(analysis,scenario,workload,pp)
                if pp.exists(): story += [Paragraph(f"Scenario {scenario}: {workload}",styles["Heading2"]),Image(str(pp),width=180*mm,height=90*mm)]
        story.append(PageBreak()); story.append(Paragraph("Selected run details",styles["Heading1"]));
        for r in analysis["runs"]:
            b,l=r["phases"]["baseline"],r["phases"]["load"]
            lines=[f"<b>{r['scenario']} / {r['workload']} / {_rate_label(r['workload'],r['rate'])} / repetition {r['repetition']}</b>",f"Run ID: {r['run_id']}",f"Verdict: {r['performance_verdict']}; recovery: {r['recovery_assessment']['status']}; baseline: {r['baseline_stability']['status']}",f"Reference load success: {_pct(l['success_rate'])}; generator completion: {_pct(r['generator']['completion_ratio'])}; DUT dropped_no_slot: {r['dut_final'].get('dropped_no_slot','N/A')}",f"Probe total median: baseline {_fmt(b['metrics']['probe_total_us']['median_ms'])} ms -> load {_fmt(l['metrics']['probe_total_us']['median_ms'])} ms; p95 load {_fmt(l['metrics']['probe_total_us']['p95_ms'])} ms",f"App RTT median: baseline {_fmt(b['metrics']['app_rtt_us']['median_ms'])} ms -> load {_fmt(l['metrics']['app_rtt_us']['median_ms'])} ms; p95 load {_fmt(l['metrics']['app_rtt_us']['p95_ms'])} ms"]
            if r["workload"] == "tcp-syn": lines.append(f"External TCP stress: observed TX {_fmt(r['generator'].get('external_observed_tx_pps'),1)} pkt/s; packets {r['generator'].get('external_interface_tx_packets_delta','N/A')}; interface TX {_fmt(r['generator'].get('external_observed_tx_mbps'),1)} Mbit/s")
            if r["latency_triggers"]: lines.append("Latency triggers: "+", ".join(f"{x['metric']}.{x['stat']} x{x['ratio']:.2f}" for x in r["latency_triggers"][:8]))
            if r["scenario"]!="A": lines.append(f"TEE final: conn_open_fail={r['dut_final'].get('tee_conn_open_fail','N/A')}, conn_close_fail={r['dut_final'].get('tee_conn_close_fail','N/A')}, transform_free_fail={r['dut_final'].get('tee_transform_free_fail','N/A')}")
            story.append(Paragraph("<br/>".join(lines),styles["Small"])); story.append(Spacer(1,2*mm))
        if appendix:
            story.append(PageBreak()); story.append(Paragraph("Appendix: selected-run reference time series",styles["Heading1"])); story.append(Paragraph("Shaded interval is the exact generator PHASE_RUN interval. Host identities, addresses and filesystem paths are intentionally omitted.",styles["Small"]));
            for i,r in enumerate(analysis["runs"]):
                pp=td/f"run_{i}.png"; _timeseries_plot(r,pp); story += [Paragraph(f"{r['scenario']} {r['workload']} {_rate_label(r['workload'],r['rate'])} - {r['run_id']}",styles["Heading2"]),Image(str(pp),width=180*mm,height=80*mm),Spacer(1,2*mm)]
        doc.build(story)
