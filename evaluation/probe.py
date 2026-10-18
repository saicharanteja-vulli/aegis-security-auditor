from pathlib import Path
import json
from aegis.scanner import scan_file
from evaluation.baseline.scanner import scan_file as baseline
from evaluation.run import score,summarize
cases=[
 ('template-interpolation','js','const view = `${eval(input)}`;',[('JS002',1)],'Template interpolation is masked together with literal template text.'),
 ('optional-eval','js','eval?.(input);',[('JS002',1)],'Optional call syntax is outside the current regex.'),
 ('default-node-import','js','import cp from "node:child_process";\ncp.exec(command);',[('JS003',2)],'Default-import Node alias is not modeled.'),
 ('lambda-shadow','py','handler = lambda *eval: eval(user)',[],'Lambda varargs shadow a builtin; current lambda visitor does not bind varargs.'),
 ('comprehension-shadow','py','import pickle\nvalues = [pickle.loads(blob) for pickle in adapters]',[],'Comprehension target shadows the module; scope is not modeled.'),
 ('unrelated-method','js','customParser.eval(input);',[],'A method called eval is not the global JavaScript builtin.'),
 ('regex-after-return','js','function pattern() { return /eval(input)/; }',[],'The lexical slash heuristic misses regex after return.'),
 ('namespace-reassignment','js','const cp = require("child_process");\ncp = customAdapter;\ncp.exec(command);',[],'Node alias reassignment is not modeled; the custom adapter method is not a known shell API.')]
# Use let so the final example is a syntactically valid reassignment.
cases[-1]=tuple(v.replace('const cp','let cp') if isinstance(v,str) else v for v in cases[-1])
fixtures=[{'id':name,'family':'challenge','path':f'challenge/{name}.{ext}','source':source,
           'expected':[{'rule':rule,'line':line} for rule,line in expected],'rationale':reason}
          for name,ext,source,expected,reason in cases]
Path('evaluation/challenge.json').write_text(json.dumps({'description':'Post-test, hand-authored known-limit diagnostic probes. Not a hidden test or tuning set. No repairs made from these outcomes.','cases':fixtures},indent=2)+'\n')
rows=[]
for strategy,scanner in [('baseline',baseline),('static',scan_file)]:
 for case in fixtures:
  found,notes=scanner(case['path'],case['source']);row=dict(case,strategy=strategy,findings=found,warnings=notes,latency_ms=0)
  row.update(score(case,found));rows.append(row)
report={'notice':'Post-test known-limit probes, separate from the 72-case comparison; no model calls, no detector tuning. These failures bound the meaning of the perfect main synthetic static score.','rows':rows,'summary':{s:summarize([r for r in rows if r['strategy']==s]) for s in ['baseline','static']}}
Path('evaluation/results/challenge.json').write_text(json.dumps(report,indent=2)+'\n')
Path('evaluation/results/challenge.md').write_text('# Known-limit challenge probes\n\n'+report['notice']+'\n\n'+ '\n'.join(f"- {r['strategy']} / {r['id']}: TP={r['tp']}, FP={r['fp']}, FN={r['fn']}. {r['rationale']}" for r in rows)+'\n')
print(json.dumps(report['summary'],indent=2))
