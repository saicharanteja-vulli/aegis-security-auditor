import pytest
from aegis.scanner import scan_file, allowed, redact, DEMO

def rules(code,path='app.py'): return {f['rule'] for f in scan_file(path,code)[0]}
@pytest.mark.parametrize('code,rule',[
 ('import os\nos.system(user)', 'PY001'),
 ('import subprocess as sp\nsp.run(command, shell=True)','PY001'),
 ('from subprocess import run as go\ngo(command,shell=True)','PY001'),
 ('eval(data)','PY002'),
 ('cursor.execute(f"SELECT * FROM users WHERE id={user}")','PY003'),
 ('cursor.execute("SELECT " + name)','PY003'),
 ('import pickle as p\np.loads(data)','PY004'),
 ('import httpx\nhttpx.get(url,verify=False)','PY005'),
 ('app.run(debug=True)','PY006'),
])
def test_python(code,rule): assert rule in rules(code)
@pytest.mark.parametrize('code',[
 'cursor.execute("SELECT * FROM users WHERE id = ?", (user,))',
 'import subprocess\nsubprocess.run(["echo", user],shell=False)',
 'import json\njson.loads(data)',
 '# eval(user)\ntext="eval(user)"',
 'import requests\nrequests.get(url,verify=True)',
])
def test_safe_python(code): assert not rules(code)
@pytest.mark.parametrize('code,rule',[
 ('el.innerHTML = user','JS001'),('eval(data)','JS002'),('child_process.exec(command)','JS003')])
def test_js(code,rule): assert rule in rules(code,'app.js')
def test_redaction():
    code='API_KEY = "abcdef1234567890"'
    findings,_=scan_file('a.py',code)
    assert findings[0]['rule']=='SEC001'
    assert 'abcdef1234567890' not in str(findings)
    assert 'abcdef1234567890' not in redact(code)
def test_bad_python_coverage_note():
    _,warnings=scan_file('bad.py','def ???')
    assert len(warnings)==1
def test_demo():
    found=[f for file in DEMO for f in scan_file(file['path'],file['content'])[0]]
    assert len(found)==5
    assert len({f['id'] for f in found})==5
@pytest.mark.parametrize('path',['../secret.py','/etc/a.py','node_modules/x.js','.git/config','x.exe','project/.venv/a.py'])
def test_path_rejection(path): assert not allowed(path)
def test_execution_never_happens(tmp_path):
    target=tmp_path/'should-not-exist'
    scan_file('evil.py',f'open({str(target)!r},"w").write("no")')
    assert not target.exists()


def test_json_secret():
    findings,_=scan_file('config.json', '\"password\": \"abcdef1234567890\"')
    assert findings[0]['rule']=='SEC001'
    assert 'abcdef1234567890' not in str(findings)

def test_uppercase_python():
    assert 'PY002' in rules('eval(data)','MAIN.PY')
