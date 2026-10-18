import time
import json
import pytest
from fastapi.testclient import TestClient
from aegis import app as module
from aegis.scanner import DEMO

@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setattr(module,'DATA',tmp_path)
    with TestClient(module.app) as client: yield client
H={'X-Aegis-Client':'dashboard'}
def scan(client,files=DEMO):
    r=client.post('/api/scans',headers=H,json={'name':'Test project','files':files})
    assert r.status_code==202,r.text
    sid=r.json()['id']
    for _ in range(100):
        obj=client.get('/api/scans/'+sid).json()
        if obj['state'] in {'completed','failed'}: return obj
        time.sleep(.01)
    pytest.fail('Worker did not finish')
def test_complete_flow(client):
    obj=scan(client)
    assert obj['state']=='completed'
    assert len(obj['findings'])==5
    assert obj['progress']==100
    fid=obj['findings'][0]['id']
    r=client.patch(f"/api/scans/{obj['id']}/findings/{fid}",headers=H,json={'status':'reviewed','note':'Verified manually'})
    assert r.status_code==200
    saved=client.get('/api/scans/'+obj['id']).json()
    assert saved['findings'][0]['status']=='reviewed'
    report=client.get('/api/scans/'+obj['id']+'/report')
    assert report.status_code==200 and 'https://' in report.text and 'Verified manually' in report.text
    assert client.get('/api/scans/'+obj['id']+'/report?format=json').json()['files']==3
    assert client.get('/api/scans').json()[0]['count']==5
@pytest.mark.parametrize('headers',[{}, {'X-Aegis-Client':'dashboard','Origin':'https://evil.example'}, {'X-Aegis-Client':'dashboard','Sec-Fetch-Site':'cross-site'}, {'X-Aegis-Client':'dashboard','Host':'evil.example'}])
def test_request_boundary(client,headers):
    assert client.post('/api/scans',headers=headers,json={'name':'x','files':DEMO}).status_code==403
@pytest.mark.parametrize('files',[[{'path':'../x.py','content':'hi'}],[{'path':'x.py','content':'\0'}],[DEMO[0],DEMO[0]],[{'path':'x.py','content':'a'*150001}]])
def test_bad_input(client,files):
    assert client.post('/api/scans',headers=H,json={'name':'x','files':files}).status_code==422

def test_report_requires_completed(client):
    assert client.get('/api/scans/missing/report').status_code==404

def test_secret_not_persisted(client):
    secret='hardcoded-credential-value'
    obj=scan(client,[{'path':'config.py','content':f'password = "{secret}"'}])
    assert secret not in str(obj)
    assert secret.encode() not in (module.DATA/'aegis.db').read_bytes()

def test_ai_unavailable(client,monkeypatch):
    obj=scan(client)
    class Offline:
        def __init__(self,*a,**k): pass
        def __enter__(self): raise module.httpx.ConnectError('offline')
        def __exit__(self,*a): pass
    monkeypatch.setattr(module.httpx,'Client',Offline)
    result=client.post(f"/api/scans/{obj['id']}/findings/{obj['findings'][0]['id']}/explain",headers=H,json={'model':'test'})
    assert result.status_code==503
    assert client.get('/api/scans/'+obj['id']).json()['state']=='completed'

def test_ai_saved(client,monkeypatch):
    obj=scan(client)
    class MockResponse:
        def raise_for_status(self): pass
        def json(self):
            finding=obj['findings'][0]
            return {'done':True,'message':{'content':json.dumps({'status':'needs_review','source_line':finding['line'],'source_quote':finding['evidence'],'risk':'Potential risk if reachable.','assumptions':['Input may be external.'],'verification_steps':['Trace the input to its caller.'],'remediation':'Use the documented safe alternative.'})}}
    class LocalAI:
        def __init__(self,*a,**k): assert k['trust_env'] is False
        def __enter__(self): return self
        def __exit__(self,*a): pass
        def post(self,url,**kw):
            assert url=='http://127.0.0.1:11434/api/chat'
            assert 'tools' not in kw['json']
            return MockResponse()
    monkeypatch.setattr(module.httpx,'Client',LocalAI)
    result=client.post(f"/api/scans/{obj['id']}/findings/{obj['findings'][0]['id']}/explain",headers=H,json={'model':'test'})
    assert result.status_code==200
    assert client.get('/api/scans/'+obj['id']).json()['findings'][0]['ai']['model']=='test'

def test_security_headers(client):
    r=client.get('/')
    assert r.headers['x-frame-options']=='DENY'
    assert "script-src 'self'" in r.headers['content-security-policy']

def hybrid_scan(client,files,model='test'):
    result=client.post('/api/scans',headers=H,json={'name':'Hybrid','files':files,'analysis_mode':'hybrid','model':model})
    assert result.status_code==202,result.text
    for _ in range(100):
        obj=client.get('/api/scans/'+result.json()['id']).json()
        if obj['state'] in {'completed','failed'}: return obj
        time.sleep(.01)
    pytest.fail('Hybrid worker did not finish')


def test_hybrid_failure_retains_static(client,monkeypatch):
    def offline(*args): raise module.httpx.ConnectError('offline')
    monkeypatch.setattr(module.LocalReview,'detect',offline)
    obj=hybrid_scan(client,[{'path':'x.py','content':'# UNIQUE_FULL_SOURCE_MARKER\neval(user)'}])
    assert obj['state']=='completed' and len(obj['findings'])==1
    assert obj['analysis'][0]['status']=='failed' and obj['findings'][0]['origin']=='static'
    assert b'UNIQUE_FULL_SOURCE_MARKER' not in (module.DATA/'aegis.db').read_bytes()
    assert 'static results remain' in obj['warnings'][0]


def test_hybrid_busy_retains_static(client):
    assert module.AI_SLOT.acquire(blocking=False)
    try: obj=hybrid_scan(client,[{'path':'x.py','content':'eval(user)'}])
    finally: module.AI_SLOT.release()
    assert obj['state']=='completed' and len(obj['findings'])==1
    assert obj['analysis'][0]['status']=='skipped_busy'


def test_hybrid_union_and_export(client,monkeypatch):
    from aegis.intelligence import validate_detections
    def detect(self,path,source):
        findings,diagnostics=validate_detections({'reviewable':True,'findings':[{'rule':'PY002','line':1,'quote':source,'reason':'Potential dynamic execution.'}]},path,source)
        return {'findings':findings,'diagnostics':diagnostics,'usage':{'model':'test'}}
    monkeypatch.setattr(module.LocalReview,'detect',detect)
    obj=hybrid_scan(client,[{'path':'x.py','content':'eval(user)'}])
    assert len(obj['findings'])==1 and obj['findings'][0]['origin']=='static+ai'
    assert obj['analysis_mode']=='hybrid' and obj['analysis'][0]['status']=='completed'
    report=client.get('/api/scans/'+obj['id']+'/report')
    assert 'hybrid' in report.text and 'static+ai' in report.text


@pytest.mark.parametrize('files,model',[
    ([{'path':'x.py','content':'x'}],''),
    ([{'path':'x.py','content':'x'*12001}],'test'),
    ([{'path':f'{i}.py','content':'x'} for i in range(9)],'test')])
def test_hybrid_limits(client,files,model):
    assert client.post('/api/scans',headers=H,json={'name':'x','analysis_mode':'hybrid','model':model,'files':files}).status_code==422


def test_invalid_explanation_not_saved(client,monkeypatch):
    def invalid(*args): raise ValueError('fabricated source quote')
    monkeypatch.setattr(module.LocalReview,'explain',invalid)
    obj=scan(client)
    r=client.post(f"/api/scans/{obj['id']}/findings/{obj['findings'][0]['id']}/explain",headers=H,json={'model':'test'})
    assert r.status_code==503
    saved=client.get('/api/scans/'+obj['id']).json()
    assert saved['state']=='completed' and saved['findings'][0]['ai'] is None

def test_only_completion_models_listed(client,monkeypatch):
    class Reply:
        def __init__(self,data): self.data=data
        def raise_for_status(self): pass
        def json(self): return self.data
    class Models:
        def __init__(self,*a,**kw): assert kw['trust_env'] is False
        def __enter__(self): return self
        def __exit__(self,*a): pass
        def get(self,url): return Reply({'models':[{'name':'chat'},{'name':'vectors'}]})
        def post(self,url,json): return Reply({'capabilities':['completion'] if json['model']=='chat' else ['embedding']})
    monkeypatch.setattr(module.httpx,'Client',Models)
    assert client.get('/api/models').json()=={'available':True,'models':['chat']}


def test_existing_report_migration(tmp_path,monkeypatch):
    import sqlite3
    monkeypatch.setattr(module,'DATA',tmp_path)
    with sqlite3.connect(tmp_path/'aegis.db') as db:
        db.execute('CREATE TABLE scans(id TEXT PRIMARY KEY,name TEXT,created TEXT,state TEXT,progress INTEGER,files INTEGER,lines INTEGER,findings TEXT,warnings TEXT,events TEXT,error TEXT)')
        db.execute("INSERT INTO scans VALUES('old','Prior review','2026-01-01','completed',100,1,1,'[]','[]','[]','')")
    module.initialize();saved=module.get_scan('old')
    assert saved['state']=='completed' and saved['analysis_mode']=='static' and saved['analysis']==[]
