#!/usr/bin/env python3
"""Run a geometric offered-rate sweep and summarize generator validity counters."""
from __future__ import annotations
import argparse, csv, json, subprocess, sys, time
from pathlib import Path


def args():
    p=argparse.ArgumentParser()
    p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('--backend',choices=('posix','fstack'),required=True)
    p.add_argument('--workload',choices=('full-handshake','resumption','record'),required=True)
    p.add_argument('--mode',choices=('benign','flood'),default='benign')
    p.add_argument('--scenario',choices=list('ABCDE'),default='A')
    p.add_argument('--start-rate',type=float,default=10.0)
    p.add_argument('--factor',type=float,default=2.0)
    p.add_argument('--steps',type=int,default=8)
    p.add_argument('--duration',type=int,default=20)
    p.add_argument('--max-inflight',type=int,default=4096)
    p.add_argument('--record-connections',type=int,default=32)
    p.add_argument('--output-dir',type=Path,default=Path('./calibration'))
    p.add_argument('--fstack-conf',type=Path)
    p.add_argument('--stop-ratio',type=float,default=0.95)
    return p.parse_args()


def final_row(path: Path):
    with path.open(newline='',encoding='utf-8') as f:
        rows=list(csv.DictReader(f))
    if not rows: raise RuntimeError(f'no stats rows in {path}')
    return rows[-1]


def main():
    a=args(); a.output_dir.mkdir(parents=True,exist_ok=True)
    summary=a.output_dir/'calibration_summary.csv'
    fields=['rate','return_code','offered','attempted','completed','completion_ratio','local_capacity_drop','session_unavailable','handshake_fail','profile_fail','app_fail','timeout_fail','run_dir']
    with summary.open('w',newline='',encoding='utf-8') as sf:
        w=csv.DictWriter(sf,fieldnames=fields); w.writeheader()
        for i in range(a.steps):
            rate=a.start_rate*(a.factor**i)
            run_id=f'cal-{a.workload}-{rate:g}-{int(time.time())}'
            cmd=[str(a.binary),'--config',str(a.config),'--backend',a.backend,'--scenario',a.scenario,'--workload',a.workload,'--mode',a.mode,'--rate',str(rate),'--duration',str(a.duration),'--max-inflight',str(a.max_inflight),'--record-connections',str(a.record_connections),'--output-dir',str(a.output_dir),'--run-id',run_id]
            if a.backend=='fstack':
                if not a.fstack_conf: raise SystemExit('--fstack-conf is required for fstack')
                cmd += ['--fstack-conf',str(a.fstack_conf)]
            print('+',' '.join(cmd),flush=True)
            cp=subprocess.run(cmd)
            run_dir=a.output_dir/f'tls_loadgen_{a.scenario}_{a.workload}_{a.mode}_{run_id}'
            row={'rate':rate,'return_code':cp.returncode,'run_dir':str(run_dir)}
            stats=run_dir/'generator_stats.csv'
            if stats.exists():
                f=final_row(stats)
                offered=int(f['offered_total']); completed=int(f['completed_total'])
                row.update(offered=offered,attempted=int(f['attempted_total']),completed=completed,
                           completion_ratio=(completed/offered if offered else 0.0),
                           local_capacity_drop=int(f['local_capacity_drop_total']),
                           session_unavailable=int(f['session_unavailable_total']),
                           handshake_fail=int(f['handshake_fail_total']),profile_fail=int(f['profile_fail_total']),
                           app_fail=int(f['app_fail_total']),timeout_fail=int(f['timeout_fail_total']))
            w.writerow(row); sf.flush()
            if cp.returncode != 0: break
            if row.get('completion_ratio',1.0) < a.stop_ratio: break
    print(summary)
    return 0

if __name__=='__main__': raise SystemExit(main())
