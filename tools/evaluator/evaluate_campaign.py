#!/usr/bin/env python3
from __future__ import annotations
import argparse, sys
from pathlib import Path
from tee_tls_eval import __version__
from tee_tls_eval.config import load_config
from tee_tls_eval.campaign import select
from tee_tls_eval.analysis import analyze_run, aggregate_runs
from tee_tls_eval.reporting import write_json, write_csv, write_pdf


def main()->int:
    ap=argparse.ArgumentParser(description="TEE/TLS campaign evaluator")
    ap.add_argument("--results-root",required=True,type=Path)
    g=ap.add_mutually_exclusive_group(required=True); g.add_argument("--campaign-id"); g.add_argument("--overall-campaign-id")
    ap.add_argument("--config",type=Path,default=Path(__file__).with_name("evaluator_config.toml"))
    ap.add_argument("--output-dir",type=Path)
    ap.add_argument("--no-pdf",action="store_true"); ap.add_argument("--no-appendix",action="store_true"); ap.add_argument("--version",action="version",version=__version__)
    args=ap.parse_args(); cfg=load_config(args.config if args.config.exists() else None)
    sel=select(args.results_root.resolve(),args.campaign_id,args.overall_campaign_id)
    runs=[analyze_run(sel.results_root,item,cfg) for item in sel.runs]
    agg=aggregate_runs(runs,cfg,sel.campaign_type)
    verdicts=[p["verdict"] for p in agg["points"]]
    if any(v=="INVALID" for v in verdicts): overall="INVALID: at least one selected point is invalid."
    elif any(v=="SATURATED" for v in verdicts): overall="VALID CAMPAIGN WITH SATURATION: one or more points reached service saturation."
    elif any(v=="VALID / DEGRADED" for v in verdicts): overall="VALID CAMPAIGN WITH DEGRADATION: degradation observed without a saturated point."
    elif any(v=="INCONCLUSIVE" for v in verdicts): overall="INCONCLUSIVE: at least one point lacks a defensible performance verdict."
    else: overall="VALID CAMPAIGN / NO DEGRADATION at the tested points."
    analysis={"schema_version":1,"evaluator_version":__version__,"selection":{"type":sel.selection_type,"id":sel.selection_id,"campaign_type":sel.campaign_type,"backend":sel.backend,"mode":sel.mode},"overall_verdict":overall,"warnings":sel.warnings,"aggregate":agg,"runs":runs}
    out=args.output_dir or Path.cwd()/f"evaluation_{sel.selection_id}"; out.mkdir(parents=True,exist_ok=True)
    stem="campaign_analysis" if sel.selection_type=="campaign" else "overall_campaign_analysis"
    jp=out/f"{stem}.json"; cp=out/f"{stem}_summary.csv"; pp=out/f"{stem}_report.pdf"
    write_json(jp,analysis); write_csv(cp,analysis)
    if not args.no_pdf: write_pdf(pp,analysis,appendix=(cfg.appendix_time_series and not args.no_appendix))
    print(f"Evaluator version: {__version__}"); print(f"Selection: {sel.selection_type} {sel.selection_id}"); print(f"Runs: {len(runs)}"); print(f"Verdict: {overall}"); print(f"JSON: {jp}"); print(f"CSV: {cp}");
    if not args.no_pdf: print(f"PDF: {pp}")
    return 0

if __name__=="__main__":
    try: raise SystemExit(main())
    except RuntimeError as exc: print(f"ERROR: {exc}",file=sys.stderr); raise SystemExit(2)
