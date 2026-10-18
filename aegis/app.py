import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from .scanner import RULES, DEMO, allowed, scan_file, redact
from .intelligence import LocalReview, combine_findings, endpoint, explanation_text, MAX_SOURCE

BASE=Path(__file__).resolve().parent.parent
DATA=Path(os.environ.get('AEGIS_DATA',str(BASE/'data')))
POOL=ThreadPoolExecutor(max_workers=2)
SLOTS=threading.BoundedSemaphore(4)
AI_SLOT=threading.BoundedSemaphore(1)

def now(): return datetime.now(timezone.utc).isoformat()
def connect():
    db=sqlite3.connect(DATA/'aegis.db',timeout=15)
    db.row_factory=sqlite3.Row
    return db

def initialize():
    DATA.mkdir(parents=True,exist_ok=True,mode=0o700)
    with connect() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY,name TEXT,created TEXT,state TEXT,progress INTEGER,files INTEGER,lines INTEGER,findings TEXT,warnings TEXT,events TEXT,error TEXT)')
        columns={row['name'] for row in db.execute('PRAGMA table_info(scans)')}
        for name,definition in [('analysis_mode',"TEXT NOT NULL DEFAULT 'static'"),('model',"TEXT NOT NULL DEFAULT ''"),('analysis',"TEXT NOT NULL DEFAULT '[]'")]:
            if name not in columns: db.execute(f'ALTER TABLE scans ADD COLUMN {name} {definition}')
        db.execute("UPDATE scans SET state='failed',error='Scan interrupted by restart. Please submit again.' WHERE state IN ('queued','running')")

def get_scan(sid):
    with connect() as db: row=db.execute('SELECT * FROM scans WHERE id=?',(sid,)).fetchone()
    if not row: raise HTTPException(404,'Scan not found.')
    obj=dict(row)
    for k in ('findings','warnings','events','analysis'): obj[k]=json.loads(obj[k])
    return obj

def update(sid,**fields):
    for k in ('findings','warnings','events','analysis'):
        if k in fields: fields[k]=json.dumps(fields[k])
    with connect() as db:
        db.execute('UPDATE scans SET '+','.join(k+'=?' for k in fields)+' WHERE id=?',[*fields.values(),sid])

def work(sid,files,analysis_mode='static',model=''):
    events=[{'at':now(),'text':'Source received. Read-only scan started.'}]
    found=[]; warnings=[];analysis=[]
    try:
        update(sid,state='running',events=events)
        for i,f in enumerate(files):
            findings,notes=scan_file(f['path'],f['content'])
            if analysis_mode=='hybrid':
                if not AI_SLOT.acquire(blocking=False):
                    notes.append(f"{f['path']}: Local AI was busy; only static checks completed.")
                    analysis.append({'path':f['path'],'status':'skipped_busy'})
                else:
                    try:
                        result=LocalReview(model).detect(f['path'],f['content'])
                        findings=combine_findings(findings,result['findings'])
                        invalid=len(result['diagnostics']['invalid_predictions'])
                        analysis.append({'path':f['path'],'status':'completed','usage':result['usage'],
                                         'diagnostics':result['diagnostics']})
                        if invalid: notes.append(f"{f['path']}: {invalid} AI proposals failed source validation and were withheld.")
                        if not result['diagnostics']['reviewable']: notes.append(f"{f['path']}: AI declined source review; static results remain available.")
                    except (httpx.HTTPError,ValueError,KeyError) as exc:
                        notes.append(f"{f['path']}: Local AI review failed; static results remain available.")
                        analysis.append({'path':f['path'],'status':'failed','error':type(exc).__name__})
                    finally: AI_SLOT.release()
            found.extend(findings); warnings.extend(notes)
            update(sid,progress=round((i+1)/len(files)*90))
        found.sort(key=lambda f:({'high':0,'medium':1,'low':2}[f['severity']],f['path'],f['line']))
        events.extend([{'at':now(),'text':f'Inspected {len(files)} files with {len(RULES)} static rules.'},{'at':now(),'text':f'{len(found)} review leads collected. Source discarded from working memory; report saved locally.'}])
        if analysis_mode=='hybrid': events.append({'at':now(),'text':'Optional AI review finished. AI-origin leads and exact-quote validation remain unverified interpretations.'})
        update(sid,state='completed',progress=100,findings=found,warnings=warnings,events=events,analysis=analysis)
    except Exception:
        update(sid,state='failed',error='Scan could not finish. Try a smaller set of source files.')
    finally: SLOTS.release()

@asynccontextmanager
async def lifespan(app):
    initialize()
    yield

app=FastAPI(title='Aegis — Security Auditor',lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)
@app.middleware('http')
async def boundary(request:Request,call_next):
    if request.url.hostname not in {'127.0.0.1','localhost','testserver'}:
        return JSONResponse({'detail':'Aegis is a local, single-user workspace.'},403)
    origin=request.headers.get('origin')
    if origin and origin!=str(request.base_url).rstrip('/'):
        return JSONResponse({'detail':'Cross-origin request blocked.'},403)
    if request.headers.get('sec-fetch-site')=='cross-site':
        return JSONResponse({'detail':'Cross-site request blocked.'},403)
    if request.method not in {'GET','HEAD'}:
        if request.headers.get('x-aegis-client')!='dashboard': return JSONResponse({'detail':'Dashboard header required.'},403)
        if request.headers.get('content-type','').split(';')[0]!='application/json': return JSONResponse({'detail':'JSON required.'},415)
        size=0; chunks=[]
        async for chunk in request.stream():
            size+=len(chunk)
            if size>4_000_000: return JSONResponse({'detail':'Upload is too large (4 MB request limit).'},413)
            chunks.append(chunk)
        request._body=b''.join(chunks)
    response=await call_next(request)
    response.headers.update({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
    return response

class Input(BaseModel):
    model_config=ConfigDict(extra='forbid')
class Source(Input):
    path:str=Field(min_length=1,max_length=240)
    content:str=Field(max_length=150000)
class ScanInput(Input):
    name:str=Field(min_length=1,max_length=80)
    files:list[Source]=Field(min_length=1,max_length=100)
    analysis_mode:Literal['static','hybrid']='static'
    model:str=Field(default='',max_length=100,pattern=r'^[a-zA-Z0-9_.:/-]*$')
class Review(Input):
    status:Literal['open','reviewed','dismissed']
    note:str=Field(default='',max_length=1000)
class AIInput(Input):
    model:str=Field(min_length=1,max_length=100,pattern=r'^[a-zA-Z0-9_.:/-]+$')

@app.get('/api/health')
def health(): return {'status':'ok','mode':'local','rules':len(RULES)}
@app.get('/api/rules')
def rules(): return [dict(id=k,title=v[0],severity=v[1],cwe=v[2],remediation=v[3],reference=v[4]) for k,v in RULES.items()]
@app.get('/api/demo')
def demo(): return {'name':'Sample · small web app','files':DEMO}
@app.get('/api/scans')
def scans():
    with connect() as db: rows=db.execute('SELECT id,name,created,state,progress,files,lines,findings FROM scans ORDER BY created DESC LIMIT 100').fetchall()
    result=[]
    for row in rows:
        obj=dict(row); found=json.loads(obj.pop('findings')); obj['count']=len(found); obj['high']=sum(f['severity']=='high' and f['status']=='open' for f in found); result.append(obj)
    return result
@app.post('/api/scans',status_code=202)
def create(body:ScanInput):
    paths=set(); total=0
    for f in body.files:
        if not allowed(f.path) or any(ord(c)<32 for c in f.path) or ':' in f.path: raise HTTPException(422,'Unsupported or unsafe file path: '+f.path)
        if f.path in paths: raise HTTPException(422,'Duplicate file paths are not allowed.')
        paths.add(f.path); total+=len(f.content.encode())
        if '\0' in f.content: raise HTTPException(422,'Binary files are not supported.')
    if total>2_000_000: raise HTTPException(413,'Source must be under 2 MB.')
    if body.analysis_mode=='hybrid':
        if not body.model: raise HTTPException(422,'Choose an installed local model for AI-assisted review.')
        if len(body.files)>8 or any(len(f.content)>MAX_SOURCE for f in body.files) or sum(len(f.content) for f in body.files)>48000:
            raise HTTPException(422,'AI-assisted review allows 8 files, 12,000 characters each and 48,000 characters total. Use static review for larger uploads.')
    if not SLOTS.acquire(blocking=False): raise HTTPException(429,'Scan queue is full. Try again shortly.')
    sid=uuid4().hex
    try:
        with connect() as db: db.execute('INSERT INTO scans(id,name,created,state,progress,files,lines,findings,warnings,events,error,analysis_mode,model,analysis) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(sid,body.name,now(),'queued',0,len(body.files),sum(len(f.content.splitlines()) for f in body.files),'[]','[]','[]','',body.analysis_mode,body.model,'[]'))
        POOL.submit(work,sid,[f.model_dump() for f in body.files],body.analysis_mode,body.model)
    except Exception:
        SLOTS.release(); raise
    return {'id':sid}
@app.get('/api/scans/{sid}')
def detail(sid:str): return get_scan(sid)
@app.patch('/api/scans/{sid}/findings/{fid}')
def review(sid:str,fid:str,body:Review):
    # Serialize read-modify-write to avoid lost updates across findings.
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT findings,state,events FROM scans WHERE id=?',(sid,)).fetchone()
        if not row: raise HTTPException(404,'Scan not found.')
        if row['state']!='completed': raise HTTPException(409,'Wait for the scan to complete.')
        found=json.loads(row['findings']); target=next((f for f in found if f['id']==fid),None)
        if not target: raise HTTPException(404,'Finding not found.')
        target.update(status=body.status,note=redact(body.note))
        events=json.loads(row['events'])
        events.append({'at':now(),'text':f"Review decision: {target['rule']} at {target['path']}:{target['line']} marked {body.status}."})
        db.execute('UPDATE scans SET findings=?,events=? WHERE id=?',(json.dumps(found),json.dumps(events),sid))
    return target

@app.get('/api/models')
def models():
    try:
        with httpx.Client(timeout=3,trust_env=False) as client:
            resp=client.get(endpoint()+'/api/tags'); resp.raise_for_status()
            names=[]
            for model in resp.json().get('models',[]):
                metadata=client.post(endpoint()+'/api/show',json={'model':model['name']})
                metadata.raise_for_status()
                if 'completion' in metadata.json().get('capabilities',[]): names.append(model['name'])
            return {'available':True,'models':names}
    except Exception: return {'available':False,'models':[]}
@app.post('/api/scans/{sid}/findings/{fid}/explain')
def explain(sid:str,fid:str,body:AIInput):
    scan=get_scan(sid)
    target=next((f for f in scan['findings'] if f['id']==fid),None)
    if not target: raise HTTPException(404,'Finding not found.')
    if not AI_SLOT.acquire(blocking=False): raise HTTPException(429,'An AI review is already running.')
    try:
        assessment,usage,_=LocalReview(body.model).explain(target)
        answer=explanation_text(assessment)
        with connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT findings FROM scans WHERE id=?',(sid,)).fetchone()
            found=json.loads(row['findings'])
            for f in found:
                if f['id']==fid: f['ai']={'text':answer,'model':body.model,'at':now(),'assessment':assessment,'usage':usage}
            db.execute('UPDATE scans SET findings=? WHERE id=?',(json.dumps(found),sid))
        return {'text':answer,'model':body.model,'assessment':assessment,'usage':usage}
    except (httpx.HTTPError,KeyError,ValueError): raise HTTPException(503,'Local AI was unavailable or its response failed evidence validation. Static findings remain available.')
    finally: AI_SLOT.release()

@app.get('/api/scans/{sid}/report')
def report(sid:str,format:Literal['md','json']='md'):
    scan=get_scan(sid)
    if scan['state']!='completed': raise HTTPException(409,'The report is ready after the scan completes.')
    if format=='json': content=json.dumps(scan,indent=2); media='application/json'
    else:
        out=['# Aegis security review',scan['name'],f"Scanned: {scan['created']}",f"Scope: {scan['files']} files · {scan['lines']} lines · {len(RULES)} rules",'Static and optional AI review leads, not confirmed exploits. No source was executed. No findings does not prove security. JavaScript checks are heuristic; no dependency CVE lookup, runtime testing, or whole-program dataflow analysis is performed.','## Coverage notes',*scan['warnings'],'## Findings']
        out.extend(['Analysis mode: '+scan['analysis_mode'],'AI coverage: '+json.dumps(scan['analysis'])])
        for f in scan['findings']:
            out.extend([f"### {f['title']} ({f['severity']})",f"Location: {f['path']}:{f['line']} | {f['rule']} | {f['cwe']} | Confidence: {f['confidence']} | Origin: {f.get('origin','static')} | Status: {f['status']}",'Evidence: '+f['evidence'],f['detail'],'Remediation: '+f['remediation'],'Reference: '+f['reference'],'Reviewer note: '+f['note']])
            if f['ai']: out.extend(['AI explanation (unverified):',f['ai']['text']])
        content='\n\n'.join(out); media='text/markdown'
    return Response(content,media_type=media,headers={'Content-Disposition':f'attachment; filename="aegis-{sid[:8]}.{format}"'})

@app.get('/api/evaluation')
def evaluation():
    path=BASE/'evaluation'/'results'/'summary.json'
    if not path.is_file(): return {'status':'not_run','notice':'No recorded benchmark is included in this checkout.'}
    return json.loads(path.read_text())

app.mount('/static',StaticFiles(directory=BASE/'static'),name='static')
@app.get('/')
def home(): return FileResponse(BASE/'static/index.html')
