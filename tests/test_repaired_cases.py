import json
from pathlib import Path
import pytest
from aegis.scanner import scan_file

CASES=json.loads((Path(__file__).parents[1]/'evaluation/challenge.json').read_text())['cases']

def identities(path,source): return {(f['rule'],f['line']) for f in scan_file(path,source)[0]}

@pytest.mark.parametrize('case',CASES,ids=[case['id'] for case in CASES])
def test_original_repaired_case(case):
    assert identities(case['path'],case['source'])=={(f['rule'],f['line']) for f in case['expected']}

@pytest.mark.parametrize('extension',['js','ts','tsx'])
@pytest.mark.parametrize('source,expected',[
 ('const view = `${eval(input)}`;', {('JS002',1)}),
 ('const view = `literal eval(input) ${`${eval(other)}`}`;', {('JS002',1)}),
 ('const view = `literal eval(input) \\${eval(other)}`;', set()),
 ('const view = `${({value: eval(input)}).value}`;', {('JS002',1)}),
 ('const view = `prefix\n${eval(input)}`;', {('JS002',2)}),
 ('eval?.(input);', {('JS002',1)}),
 ('customParser.eval?.(input);', set()),
 ('const eval = customParser; eval(input);', set()),
 ('function pattern() { return /eval(input)/; }', set()),
 ('const quotient = left / eval(input);', {('JS002',1)}),
 ('import cp from "node:child_process";\ncp.exec(command);', {('JS003',2)}),
 ('import cp from "child_process";\ncp.execSync(command);', {('JS003',2)}),
 ('let cp = require("child_process");\ncp.exec(command);\ncp=adapter;\ncp.exec(command);', {('JS003',2)}),
 ('let cp = adapter;\ncp = require("node:child_process");\ncp.exec(command);', {('JS003',3)}),
 ('import cp from "child_process";\nfunction run(cp) { cp.exec(command); }\ncp.exec(command);', {('JS003',3)}),
 ('import cp from "child_process";\n{let cp=adapter;cp.exec(command);}\ncp.exec(command);', {('JS003',3)}),
 ('const {exec: run} = require("node:child_process");\nrun(command);', {('JS003',2)}),
 ('import {exec as run} from "child_process";\nrun(command);', {('JS003',2)}),
 ('const msg = "import cp from \\\"child_process\\\"";\nconst cp=adapter;\ncp.exec(command);', set()),
])
def test_javascript_syntax_variants(extension,source,expected):
    assert identities('source.'+extension,source)==expected

@pytest.mark.parametrize('source,expected',[
 ('handler=lambda **eval: eval(user)',set()),
 ('handler=lambda *exec: exec(user)',set()),
 ('handler=lambda item=eval(user): item',{('PY002',1)}),
 ('import pickle\nvalues=[pickle.loads(blob) for pickle in adapters]\npickle.loads(blob)',{('PY004',3)}),
 ('import pickle\nvalues={pickle.loads(blob) for pickle in adapters}',set()),
 ('import pickle\nvalues={pickle: pickle.loads(blob) for pickle in adapters}',set()),
 ('import pickle\nvalues=(pickle.loads(blob) for pickle in adapters)',set()),
 ('import pickle\nvalues=[item for pickle in pickle.loads(blob) for item in pickle.loads(other)]',{('PY004',2)}),
 ('import pickle\nvalues=[pickle.loads(blob) for item in things]',{('PY004',2)}),
])
def test_python_scope_variants(source,expected): assert identities('source.py',source)==expected

@pytest.mark.parametrize('extension',['js','ts','tsx'])
def test_malformed_script_reports_coverage(extension):
    findings,warnings=scan_file('bad.'+extension,'function bad( { eval(input)')
    assert findings==[] and any('parsing failed' in note for note in warnings)

def test_inline_html_script_line_numbers():
    source='<p>eval(inertText)</p>\n<script>\neval(input);\n</script>'
    assert identities('index.html',source)=={('JS002',3)}

def test_typescript_types_and_jsx_remain_supported():
    source='import cp from "child_process";\nconst run=(input: string) => cp.exec(input);\nconst view=<div dangerouslySetInnerHTML={{__html:input}}/>;'
    assert identities('source.tsx',source)=={('JS003',2),('JS001',3)}

def test_repaired_labels_and_sources_unchanged_from_recorded_failures():
    history=json.loads((Path(__file__).parents[1]/'evaluation/results/v1/challenge.json').read_text())
    recorded={row['id']:row for row in history['rows'] if row['strategy']=='static'}
    for case in CASES:
        assert all(case[key]==recorded[case['id']][key] for key in ['source','path','expected'])

def test_comprehension_target_does_not_shadow_enclosing_function_import():
    source='import pickle\ndef run():\n    first=pickle.loads(blob)\n    values=[pickle.loads(blob) for pickle in adapters]\n    return pickle.loads(blob)'
    assert identities('source.py',source)=={('PY004',3),('PY004',5)}
