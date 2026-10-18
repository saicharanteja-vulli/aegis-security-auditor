import pytest
from aegis.scanner import scan_file

def keys(path,source): return {(f['rule'],f['line']) for f in scan_file(path,source)[0]}

@pytest.mark.parametrize('source',[
 'import subprocess as sp\ndef run(sp):\n    sp.run(command,shell=True)',
 'def use(eval):\n    eval(data)',
 'import pickle\ndef use():\n    pickle = service\n    pickle.loads(data)',
 'cursor.execute("SELECT " + "1")',
 'query="SELECT ?"\ncopy=query\ncursor.execute(copy,(value,))'])
def test_safer_bindings(source): assert not keys('x.py',source)

@pytest.mark.parametrize('source,expected',[
 ('query=f"SELECT {user}"\ncopy=query\ncursor.execute(copy)',('PY003',3)),
 ('execute=exec\nexecute(data)',('PY002',2)),
 ('from pickle import loads as restore\nrestore(data)',('PY004',2)),
 ('query="SELECT 1"\nif flag:\n    query=user\ncursor.execute(query)',('PY003',4))])
def test_local_flow(source,expected): assert expected in keys('x.py',source)

@pytest.mark.parametrize('source',[
 '// eval(user);\nconst x="element.innerHTML = data";',
 '/* child_process.exec(command); */\nconst regex=/eval\\(/;regex.exec(text);',
 'const text=`eval(user)`;'])
def test_inert_javascript(source): assert not keys('x.js',source)

@pytest.mark.parametrize('source,expected',[
 ('const {exec: launch} = require("node:child_process");\nlaunch(command);',('JS003',2)),
 ('import {exec as run} from "child_process";\nrun(command);',('JS003',2)),
 ('element\n.innerHTML\n= value;',('JS001',2)),
 ('eval\n(user)',('JS002',1))])
def test_javascript_aliases_and_lines(source,expected): assert expected in keys('x.js',source)
