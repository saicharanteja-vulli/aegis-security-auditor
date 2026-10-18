"""Compare frozen static baseline, current static rules, AI, and their union.

python -m evaluation.run --split dev --models qwen3:1.7b --output evaluation/results/dev
"""
import argparse
from collections import Counter
from datetime import datetime,timezone
import hashlib
from importlib.metadata import version
import json
import math
from pathlib import Path
import platform
import subprocess
import time
import httpx
from aegis.scanner import scan_file
from aegis.intelligence import LocalReview, combine_findings, endpoint, DETECT_SYSTEM, DetectionResponse
from .baseline.scanner import scan_file as baseline_scan

ROOT=Path(__file__).resolve().parent


def score(case,findings,invalid=0,error=None,declined=False):
    expected={(f['rule'],f['line']) for f in case['expected']}
    actual={(f['rule'],f['line']) for f in findings}
    tp=expected&actual;fp=actual-expected;fn=expected-actual
    expected_decline=case.get('expected_parse_warning',False)
    passed=not error and not invalid and expected==actual and (declined==expected_decline)
    negative=not expected and not expected_decline
    return {'tp':len(tp),'fp':len(fp)+invalid,'fn':len(fn),'matched':sorted(tp),'false_positives':sorted(fp),
            'missed':sorted(fn),'invalid_predictions':invalid,'error':error,'coverage_declined':declined,
            'case_pass':passed,'negative_case':negative,'true_negative':negative and not actual and not invalid and not error and not declined,
            'false_positive_case':negative and bool(actual or invalid),
            'unreviewed_negative':negative and bool(error or declined)}


def ratio(n,d): return round(n/d,4) if d else None
def percentile(values,p): return round(sorted(values)[max(0,math.ceil(len(values)*p)-1)],2) if values else None


def summarize(rows):
    tp=sum(r['tp'] for r in rows);fp=sum(r['fp'] for r in rows);fn=sum(r['fn'] for r in rows)
    negatives=sum(r['negative_case'] for r in rows)
    return {'cases':len(rows),'tp':tp,'fp':fp,'fn':fn,'precision':ratio(tp,tp+fp),'recall':ratio(tp,tp+fn),
            'f1':ratio(2*tp,2*tp+fp+fn),'exact_case_pass_rate':ratio(sum(r['case_pass'] for r in rows),len(rows)),
            'negative_cases':negatives,'true_negative_cases':sum(r['true_negative'] for r in rows),
            'false_positive_cases':sum(r['false_positive_case'] for r in rows),
            'false_positive_case_rate':ratio(sum(r['false_positive_case'] for r in rows),negatives),
            'unreviewed_negative_cases':sum(r['unreviewed_negative'] for r in rows),
            'specificity':ratio(sum(r['true_negative'] for r in rows),negatives),
            'errors':sum(bool(r['error']) for r in rows),'declined_cases':sum(r['coverage_declined'] for r in rows),
            'invalid_predictions':sum(r['invalid_predictions'] for r in rows),
            'p50_ms':percentile([r['latency_ms'] for r in rows],.5),
            'p95_ms':percentile([r['latency_ms'] for r in rows],.95),
            'prompt_tokens':sum(r.get('usage',{}).get('prompt_tokens',0) for r in rows),
            'completion_tokens':sum(r.get('usage',{}).get('completion_tokens',0) for r in rows)}


def markdown(report):
    lines=['# Aegis review-lead evaluation','',f"Split: {report['split']} | Dataset: {report['dataset_version']} | Run: {report['created_at']}",'',
        'Original synthetic fixtures with hand-authored rule/line review labels. This is not a production vulnerability-detection accuracy claim.','',
        '| Strategy | Cases | TP | FP | FN | Precision | Recall | F1 | Errors |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for name,row in report['summary'].items():
        lines.append(f"| {name} | {row['cases']} | {row['tp']} | {row['fp']} | {row['fn']} | {row['precision']} | {row['recall']} | {row['f1']} | {row['errors']} |")
    lines.extend(['','## What is measured','','- A true positive matches the expected rule AND exact source line. Wrong-line predictions count as false positives and leave a missed expected finding.','- Invalid AI proposals count as false positives in the benchmark, even though the application withholds them. Duplicate valid identities are deduplicated and recorded.','- Model errors leave positive findings missed and are never counted as successful clean reviews. Unreviewed negative cases remain in the specificity denominator.','- Hybrid is the union of current static findings and source-validated AI leads. It never removes a static finding. AI and hybrid use the same model response per case.','- Labels describe local review patterns, not proven exploitability. All fixtures are synthetic and public; dev/test variants share rule families. The benchmark was co-designed with the implementation, so it is not independent generalization evidence.','- Precision/recall do not measure explanation entailment or whether a suggested fix works. The full source, labels, accepted findings, rejected proposals, raw model responses and usage are retained in JSON.','- Timing is one development-machine sample with cache/load effects and other verification activity; do not infer a universal model or performance ranking.','','## Misses and false positives',''])
    for row in report['rows']:
        if not row['case_pass']:
            lines.append(f"- {row['strategy']} / {row['id']}: TP={row['tp']}, FP={row['fp']}, FN={row['fn']}, declined={row['coverage_declined']}, error={row['error']}")
    return '\n'.join(lines)+'\n'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--split',choices=['dev','test'],default='dev')
    parser.add_argument('--models',default='',help='Comma-separated installed local models. Empty runs static comparisons only.')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    raw=(ROOT/'benchmark.json').read_bytes();data=json.loads(raw)
    cases=[case for case in data['cases'] if case['split']==args.split]
    report={'dataset_version':data['version'],'dataset_sha256':hashlib.sha256(raw).hexdigest(),
            'created_at':datetime.now(timezone.utc).isoformat(),'split':args.split,'python':platform.python_version(),
            'evaluation_revision':'v2-repaired-cases',
            'requirements_sha256':hashlib.sha256(Path('requirements.txt').read_bytes()).hexdigest(),
            'dependency_versions':{name:version(name) for name in ['tree-sitter','tree-sitter-javascript','tree-sitter-typescript','httpx','pydantic']},
            'platform':platform.platform(),'detection_prompt':DETECT_SYSTEM,'detection_schema':DetectionResponse.model_json_schema(),
            'generation_settings':{'temperature':0,'seed':42,'num_ctx':8192,'num_predict':1100,'think':False},
            'source_sha256':{str(path):hashlib.sha256(path.read_bytes()).hexdigest() for folder in ('aegis','evaluation') for path in sorted(Path(folder).rglob('*.py'))},
            'rows':[],'summary':{}}
    try: report['git_revision']=subprocess.check_output(['git','rev-parse','HEAD'],text=True,stderr=subprocess.DEVNULL).strip()
    except (OSError,subprocess.CalledProcessError): report['git_revision']=None
    models=[model.strip() for model in args.models.split(',') if model.strip()]
    if models:
        with httpx.Client(timeout=5,trust_env=False) as client:
            response=client.get(endpoint()+'/api/tags');response.raise_for_status();report['installed_models']=response.json()['models']
    current={}
    for strategy,scanner in [('baseline',baseline_scan),('static',scan_file)]:
        for case in cases:
            started=time.perf_counter();found,notes=scanner(case['path'],case['source'])
            row=dict(case,strategy=strategy,findings=found,warnings=notes,latency_ms=round((time.perf_counter()-started)*1000,3))
            row.update(score(case,found,declined=any('parsing failed' in note for note in notes)))
            report['rows'].append(row)
            if strategy=='static': current[case['id']]=found
    # Journal raw rows as they arrive; an interrupted local experiment retains evidence.
    args.output.parent.mkdir(parents=True,exist_ok=True)
    journal=Path(str(args.output)+'.jsonl')
    with journal.open('w') as stream:
        for row in report['rows']: stream.write(json.dumps(row)+'\n')
        for model in models:
            provider=LocalReview(model)
            for case in cases:
                started=time.perf_counter()
                try:
                    result=provider.detect(case['path'],case['source']);error=None
                    invalid=len(result['diagnostics']['invalid_predictions']);declined=not result['diagnostics']['reviewable']
                except (httpx.HTTPError,ValueError,KeyError) as exc:
                    result={'findings':[],'diagnostics':{},'usage':getattr(exc,'usage',{}),'raw':getattr(exc,'raw',None)};invalid=0;declined=False
                    error=f'{type(exc).__name__}: {exc}'
                elapsed=round((time.perf_counter()-started)*1000,3)
                for strategy in ('ai','hybrid'):
                    found=result['findings'] if strategy=='ai' else combine_findings(current[case['id']],result['findings'])
                    row=dict(case,strategy=strategy+':'+model,findings=found,model_response=result,usage=result['usage'],latency_ms=elapsed)
                    # A failed/declined AI stage leaves hybrid static coverage intact, but is still reported as an AI error.
                    row.update(score(case,found,invalid,error,declined))
                    report['rows'].append(row);stream.write(json.dumps(row)+'\n');stream.flush()
                print(model,case['id'],error or 'recorded',flush=True)
    for strategy in dict.fromkeys(row['strategy'] for row in report['rows']):
        rows=[row for row in report['rows'] if row['strategy']==strategy]
        summary=summarize(rows)
        summary['by_rule']={rule:summarize([row for row in rows if row['family']==rule]) for rule in sorted({row['family'] for row in rows})}
        report['summary'][strategy]=summary
    Path(str(args.output)+'.json').write_text(json.dumps(report,indent=2)+'\n')
    Path(str(args.output)+'.md').write_text(markdown(report))
    print(json.dumps({name:{k:v for k,v in row.items() if k!='by_rule'} for name,row in report['summary'].items()},indent=2))
    return int(any(row['errors'] for row in report['summary'].values()))


if __name__=='__main__': raise SystemExit(main())
