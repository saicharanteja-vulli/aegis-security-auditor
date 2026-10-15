import time
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
        def json(self): return {'message':{'content':'Verify input and use parameterized operations.'}}
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
