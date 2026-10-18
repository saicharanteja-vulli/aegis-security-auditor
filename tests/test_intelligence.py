import pytest
from aegis.intelligence import (validate_detections,combine_findings,source_for_model,
                                validate_explanation,endpoint,LocalReview,ReviewValidationError)
from aegis.scanner import scan_file
from evaluation.run import score,summarize

SOURCE='eval(user_input)'
def proposal(**changes):
    return dict(rule='PY002',line=1,quote=SOURCE,reason='Could execute input if externally controlled.',**changes)

def test_evidence_validation_and_union():
    raw={'reviewable':True,'findings':[proposal(),proposal()]}
    found,diagnostics=validate_detections(raw,'x.py',SOURCE)
    static,_=scan_file('x.py',SOURCE)
    assert len(found)==1 and diagnostics['duplicate_predictions']==1
    assert combine_findings(static,found)[0]['origin']=='static+ai'
    assert combine_findings(static,[])==static

@pytest.mark.parametrize('field,value',[('rule','FAKE'),('line',2),('quote','fabricated'),('line',True),('reason',' ')])
def test_invalid_proposals_withheld(field,value):
    item=proposal();item[field]=value
    found,diagnostics=validate_detections({'reviewable':True,'findings':[item]},'x.py',SOURCE)
    assert not found and len(diagnostics['invalid_predictions'])==1

@pytest.mark.parametrize('raw',[{}, {'reviewable':'true','findings':[]},{'reviewable':False,'findings':[proposal()]}])
def test_invalid_envelope(raw):
    with pytest.raises(ValueError): validate_detections(raw,'x.py',SOURCE)

def test_decline_is_explicit():
    found,diagnostics=validate_detections({'reviewable':False,'findings':[]},'x.py',SOURCE)
    assert found==[] and not diagnostics['reviewable']

def test_redaction_preserves_lines():
    source='password = "super-private-example"\n-----BEGIN PRIVATE KEY-----\nsecretbody\n-----END PRIVATE KEY-----'
    result=source_for_model(source)
    assert len(result.splitlines())==4
    assert 'super-private-example' not in result and 'secretbody' not in result
    assert 'BEGIN PRIVATE KEY' in result

@pytest.mark.parametrize('url',['https://127.0.0.1:11434','http://evil.example','http://127.0.0.1:11434/path','http://user:pass@localhost:11434'])
def test_reject_remote_endpoint(monkeypatch,url):
    monkeypatch.setenv('AEGIS_OLLAMA_URL',url)
    with pytest.raises(ValueError): endpoint()

def test_loopback_endpoint(monkeypatch):
    monkeypatch.setenv('AEGIS_OLLAMA_URL','http://127.0.0.1:11435')
    assert endpoint().endswith(':11435')

def explanation():
    return {'status':'insufficient_context','source_line':1,'source_quote':SOURCE,'risk':'Potential execution if reachable.',
            'assumptions':['Caller provenance is unknown.'],'verification_steps':['Inspect caller validation.'],'remediation':'Use a bounded parser.'}

@pytest.mark.parametrize('field,value',[('source_line',2),('source_quote','fake'),('status','confirmed'),('risk','https://invented.example'),('verification_steps',[' '])])
def test_bad_explanation(field,value):
    finding=scan_file('x.py',SOURCE)[0][0];raw=explanation();raw[field]=value
    with pytest.raises(ValueError): validate_explanation(raw,finding)

def test_explanation_contract():
    assert validate_explanation(explanation(),scan_file('x.py',SOURCE)[0][0])['status']=='insufficient_context'

def test_validation_error_retains_raw(monkeypatch):
    raw={'reviewable':False,'findings':[proposal()]}
    monkeypatch.setattr(LocalReview,'request',lambda *args:(raw,{'completion_tokens':3}))
    with pytest.raises(ReviewValidationError) as error: LocalReview('fake').detect('x.py',SOURCE)
    assert error.value.raw==raw and error.value.usage['completion_tokens']==3

def test_metric_wrong_line_and_error_denominators():
    positive={'expected':[{'rule':'PY002','line':1}]}
    wrong=score(positive,[{'rule':'PY002','line':2}]);assert (wrong['tp'],wrong['fp'],wrong['fn'])==(0,1,1)
    negative=score({'expected':[]},[],error='offline');negative['latency_ms']=1
    result=summarize([negative]);assert result['specificity']==0 and result['unreviewed_negative_cases']==1
    assert score({'expected':[]},[],invalid=1)['fp']==1

def test_regression_gate_rejects_misses():
    from evaluation.gate import check
    baseline={'errors':0,'fp':1,'fn':1,'exact_case_pass_rate':.8}
    assert check({'summary':{'baseline':baseline,'static':dict(baseline)}})
    worse=dict(baseline,fn=2)
    assert not check({'summary':{'baseline':baseline,'static':worse}})

@pytest.mark.parametrize('complete,content',[(True,'not JSON'),(False,'{}')])
def test_provider_raw_failures_retained(monkeypatch,complete,content):
    import aegis.intelligence as module
    class Reply:
        def raise_for_status(self): pass
        def json(self): return {'done':complete,'message':{'content':content},'eval_count':2}
    class Client:
        def __init__(self,*a,**kw): pass
        def __enter__(self): return self
        def __exit__(self,*a): pass
        def post(self,*a,**kw): return Reply()
    monkeypatch.setattr(module.httpx,'Client',Client)
    with pytest.raises(ReviewValidationError) as error: LocalReview('fixture').detect('x.py',SOURCE)
    assert error.value.raw['message']['content']==content and error.value.usage['completion_tokens']==2
