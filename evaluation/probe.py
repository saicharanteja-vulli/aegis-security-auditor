"""Rerun fixed known-limit cases without changing their labels.

These eight cases informed repairs: passing them is regression evidence, not an
independent holdout. The original failing run remains in results/challenge.*.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
from aegis.scanner import scan_file
from evaluation.baseline.scanner import scan_file as baseline
from evaluation.run import score,summarize


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path('evaluation/results/v2/challenge'))
    args=parser.parse_args()
    raw=Path(__file__).with_name('challenge.json').read_bytes();fixtures=json.loads(raw)['cases']
    rows=[]
    for strategy,scanner in [('baseline',baseline),('static',scan_file)]:
        for case in fixtures:
            found,notes=scanner(case['path'],case['source'])
            row=dict(case,strategy=strategy,findings=found,warnings=notes,latency_ms=0)
            row.update(score(case,found,declined=any('parsing failed' in note for note in notes)))
            rows.append(row)
    report={'created_at':datetime.now(timezone.utc).isoformat(),'dataset_sha256':hashlib.sha256(raw).hexdigest(),
            'source_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path('aegis').glob('*.py'))},
            'notice':'v2 rerun of the original eight known-limit probes. Their unchanged labels informed the fixes, so this is development/regression evidence, not an independent test. The original failures are preserved in results/challenge.*. Original per-case rationales describe the v1 failure mechanisms.',
            'rows':rows,'summary':{s:summarize([r for r in rows if r['strategy']==s]) for s in ['baseline','static']}}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    Path(str(args.output)+'.json').write_text(json.dumps(report,indent=2)+'\n')
    Path(str(args.output)+'.md').write_text('# Repaired-case regression evaluation\n\n'+report['notice']+'\n\n'+'\n'.join(f"- {r['strategy']} / {r['id']}: TP={r['tp']}, FP={r['fp']}, FN={r['fn']}, pass={r['case_pass']}" for r in rows)+'\n')
    print(json.dumps(report['summary'],indent=2))
    return int(any(not r['case_pass'] for r in rows if r['strategy']=='static'))


if __name__=='__main__': raise SystemExit(main())
