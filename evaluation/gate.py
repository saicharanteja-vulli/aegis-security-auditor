"""Fail CI on a current-static regression; model experiments remain opt-in."""
import json
from pathlib import Path
import sys

def check(report):
    current=report['summary']['static'];baseline=report['summary']['baseline']
    return (current['errors']==0 and current['fp']<=baseline['fp'] and current['fn']<=baseline['fn']
            and current['exact_case_pass_rate']>=baseline['exact_case_pass_rate'])

if __name__=='__main__':
    report=json.loads(Path(sys.argv[1]).read_text())
    if not check(report): raise SystemExit('Current static analysis regressed against the frozen baseline.')
    print('Static regression gate passed; this is not a security or generalization guarantee.')
