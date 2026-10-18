"""Exercise the application's explanation contract; does not score semantic truth."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import time
import httpx
from aegis.scanner import scan_file
from aegis.intelligence import LocalReview,EXPLAIN_SYSTEM,Explanation,validate_explanation,endpoint

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    dataset=Path(__file__).with_name('benchmark.json').read_bytes()
    cases=json.loads(dataset)['cases'];chosen=[];seen=set()
    for case in cases:
        if case['split']!='test': continue
        findings,_=scan_file(case['path'],case['source'])
        if findings and case['family'] not in seen:
            seen.add(case['family']);chosen.append((case,findings[0]))
    rows=[];args.output.parent.mkdir(parents=True,exist_ok=True)
    with Path(str(args.output)+'.jsonl').open('w') as journal:
        for case,finding in chosen:
            start=time.perf_counter();raw=None;usage={};error=None;assessment=None
            try:
                # Same prompt, payload, schema and validator as LocalReview.explain.
                payload={key:finding[key] for key in ('rule','title','cwe','evidence','detail','remediation','line')}
                raw,usage=LocalReview(args.model).request(EXPLAIN_SYSTEM,payload,Explanation.model_json_schema())
                assessment=validate_explanation(raw,finding)
            except (httpx.HTTPError,ValueError,KeyError) as exc:
                error=f'{type(exc).__name__}: {exc}';raw=getattr(exc,'raw',raw);usage=getattr(exc,'usage',usage)
            row={'id':case['id'],'finding':finding,'raw':raw,'usage':usage,'assessment':assessment,'error':error,
                 'contract_pass':assessment is not None,'latency_ms':round((time.perf_counter()-start)*1000,3)}
            rows.append(row);journal.write(json.dumps(row)+'\n');journal.flush();print(case['id'],error or 'contract passed',flush=True)
    report={'created_at':datetime.now(timezone.utc).isoformat(),'model':args.model,
            'dataset_sha256':hashlib.sha256(dataset).hexdigest(),
            'source_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path('aegis').glob('*.py'))},
            'generation_settings':{'temperature':0,'seed':42,'num_ctx':8192,'num_predict':1100,'think':False},
            'selection':'First current-static finding per available test family in fixed dataset order.',
            'prompt':EXPLAIN_SYSTEM,'schema':Explanation.model_json_schema(),'cases':len(rows),
            'contract_passes':sum(row['contract_pass'] for row in rows),'rows':rows,
            'limitations':'Structural contract only: exact evidence, schema, bounded assumptions/verification steps, no generated URLs. No independent semantic review, exploit validation or fix testing; not explanation accuracy.'}
    with httpx.Client(timeout=5,trust_env=False) as client:
        response=client.get(endpoint()+'/api/tags');response.raise_for_status();report['installed_models']=response.json()['models']
    Path(str(args.output)+'.json').write_text(json.dumps(report,indent=2)+'\n')
    Path(str(args.output)+'.md').write_text(f"# Explanation contract evaluation\n\n{report['contract_passes']}/{len(rows)} responses passed the structural contract.\n\n{report['limitations']}\n\n"+'\n'.join(f"- {r['id']}: {r['error'] or 'contract passed'}" for r in rows)+'\n')
    print(json.dumps({key:value for key,value in report.items() if key not in {'rows','prompt','schema'}},indent=2))
    return int(any(not row['contract_pass'] for row in rows))

if __name__=='__main__': raise SystemExit(main())
