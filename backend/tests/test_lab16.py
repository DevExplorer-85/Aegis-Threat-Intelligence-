from datetime import date, datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import lab16_api as lab16
from app.auth import SESSIONS


class Cursor:
    def __init__(self, rows): self.rows=list(rows)
    def sort(self, key, direction=-1):
        if isinstance(key,list): key,direction=key[0]
        self.rows.sort(key=lambda x:x.get(key) or datetime.min.replace(tzinfo=timezone.utc),reverse=direction==-1);return self
    def limit(self,n):self.rows=self.rows[:n];return self
    def __iter__(self):return iter(self.rows)

class Collection:
    def __init__(self,rows=None):self.rows=list(rows or [])
    def insert_one(self,d):self.rows.append(dict(d));return type('R',(),{'inserted_id':len(self.rows)})()
    def update_one(self,q,u):
        row=next((x for x in self.rows if all(x.get(k)==v for k,v in q.items())),None)
        if row:row.update(u.get('$set',{}))
    def count_documents(self,q):
        total=0
        for row in self.rows:
            if all((k not in row) if isinstance(v,dict) and v.get('$exists') is False else (k in row) if isinstance(v,dict) and v.get('$exists') else row.get(k)==v for k,v in q.items()):total+=1
        return total
    def find(self,q=None,projection=None):
        q=q or {}; rows=[]
        for row in self.rows:
            if all(row.get(k)==v for k,v in q.items()):rows.append(dict(row))
        return Cursor(rows)
    def find_one(self,q,projection=None):
        return next((dict(x) for x in self.rows if all(x.get(k)==v for k,v in q.items())),None)

class Database:
    def __init__(self):self.collections={}
    def __getitem__(self,key):return self.collections.setdefault(key,Collection())

class QueryResult:
    def __init__(self,rows):self.rows=rows
    def __iter__(self):return iter(self.rows)
    def one(self):return self.rows[0] if self.rows else None
    def single(self,strict=False):return self.rows[0] if self.rows else {'ok':1}

class AuditSession:
    def __init__(self,rows=None):self.rows=rows or [];self.calls=[]
    def execute(self,query,args=None,**kwargs):
        self.calls.append((query,args));rows=self.rows
        if args and isinstance(args[0],date):rows=[r for r in rows if getattr(r,'event_day',args[0])==args[0]]
        elif args and len(args)>1 and isinstance(args[1],date):rows=[r for r in rows if getattr(r,'event_day',args[1])==args[1]]
        return QueryResult(rows)

class GraphResult:
    def single(self,strict=False):return {'nodes':[],'relationships':[]}

class NeoSession:
    def __init__(self,rows=None):self.rows=rows or []
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def run(self,*args,**kwargs):return QueryResult(self.rows)

class NeoDriver:
    def __init__(self,rows=None):self.rows=rows or []
    def session(self,**kwargs):return NeoSession(self.rows)

@pytest.fixture
def app_client(monkeypatch):
    db=Database();monkeypatch.setattr(lab16,'db',db)
    monkeypatch.setattr(lab16,'mongo_client',type('Mongo',(),{'topology_description':type('Topology',(),{'has_writable_server':lambda self:True})()})())
    SESSIONS.clear()
    SESSIONS['admin']={'id':'admin1','name':'Admin','email':'admin@x','role':'admin','permissions':['all','audit_logs','moderate_alerts','monitoring_admin','view_unredacted_pii']}
    SESSIONS['hunter']={'id':'hunter1','name':'Hunter','email':'hunter@x','role':'threat_hunter','permissions':['moderate_alerts','view_unredacted_pii']}
    SESSIONS['analyst']={'id':'analyst1','name':'Analyst','email':'analyst@x','role':'soc_analyst','permissions':['view_redacted_pii']}
    for name in lab16._breakers:lab16._breakers[name].update(state='closed',failures=0,opened_at=None,last_success=None,last_error=None)
    app=FastAPI();app.include_router(lab16.router)
    with TestClient(app) as client:yield client,db
    SESSIONS.clear()

def h(token):return {'Authorization':f'Bearer {token}'}

def test_role_gates_service_audit_and_fraud_apis(app_client):
    c,_=app_client
    assert c.get('/api/services/lab16',headers=h('analyst')).status_code==403
    assert c.post('/api/services/lab16/start',headers=h('analyst'),json={}).status_code==403
    assert c.get('/api/ops/audit',headers=h('analyst')).status_code==403
    assert c.get('/api/moderation/fraud',headers=h('analyst')).status_code==403
    assert c.get('/api/moderation/fraud',headers=h('hunter')).status_code==200

def test_real_health_results_and_circuit_breaker_skip(app_client,monkeypatch):
    c,_=app_client
    monkeypatch.setattr(lab16,'_mongo_ping',lambda:{'connected':True,'latency_ms':2})
    monkeypatch.setattr(lab16,'_cassandra',lambda:AuditSession())
    monkeypatch.setattr(lab16,'_neo4j',lambda:NeoDriver())
    health=c.get('/api/services/lab16',headers=h('admin')).json()['services']
    assert all(health[n]['connected'] for n in ('mongodb','cassandra','neo4j'))
    lab16._breakers['cassandra'].update(state='open',opened_at=__import__('time').time())
    result=lab16._audit_query(date.today(),None,200,{})
    assert result['skipped'] is True and result['database_succeeded'] is False

def test_start_stop_controls_and_neo4j_password_requirement(app_client,monkeypatch):
    c,_=app_client
    monkeypatch.setenv('LAB16_NEO4J_PASSWORD','short')
    result=c.post('/api/services/lab16/start',headers=h('admin'),json={'services':['neo4j']})
    assert result.status_code==409
    monkeypatch.setenv('LAB16_NEO4J_PASSWORD','long-enough-secret')
    calls=[];monkeypatch.setattr(lab16,'_manage_service',lambda name,action:calls.append((name,action)) or {'service':name,'container_state':action})
    assert c.post('/api/services/lab16/start',headers=h('admin'),json={'services':['cassandra']}).json()['results'][0]['container_state']=='start'
    assert c.post('/api/services/lab16/stop',headers=h('admin'),json={'services':['cassandra']}).json()['results'][0]['container_state']=='stop'
    assert calls==[('cassandra','start'),('cassandra','stop')]

def test_docker_manager_creates_and_stops_real_service_container(app_client,monkeypatch):
    c,_=app_client
    class NotFound(Exception):pass
    class Container:
        status='running'
        def __init__(self):self.started=0;self.stopped=0
        def reload(self):pass
        def start(self):self.started+=1;self.status='running'
        def stop(self,timeout):self.stopped+=1;self.status='exited'
    container=Container();created={}
    class Containers:
        def get(self,name):
            if name not in created:raise NotFound()
            return created[name]
        def run(self,image,**kwargs):created[kwargs['name']]=container;return container
    class Networks:
        def get(self,name):return SimpleNamespace(name=name)
    class Volumes:
        def create(self,name):return SimpleNamespace(name=name)
    daemon=SimpleNamespace(containers=Containers(),networks=Networks(),volumes=Volumes(),close=lambda:None)
    monkeypatch.setitem(__import__('sys').modules,'docker',SimpleNamespace(from_env=lambda **kwargs:daemon,errors=SimpleNamespace(NotFound=NotFound)))
    monkeypatch.setattr(lab16,'service_health',lambda name:{'connected':False,'service':name})
    started=lab16._manage_service('cassandra','start')
    assert started['container_state']=='running' and container.started==0
    stopped=lab16._manage_service('cassandra','stop')
    assert stopped['container_state']=='exited' and container.stopped==1

def test_audit_outbox_persists_before_cassandra_and_retrieval_filters(app_client,monkeypatch):
    c,db=app_client;session=AuditSession();monkeypatch.setattr(lab16,'_cassandra',lambda:session)
    event=lab16.record_audit({'id':'user-1','name':'A User','role':'admin'},'case_create','case-1',{'source':'case'})
    assert event=={'mongo_persisted':True,'cassandra_persisted':True,'pending':False}
    assert len(db[lab16.AUDIT_OUTBOX].rows)==1 and len(session.calls)==4
    # The actor filter and optional day are combined into an indexed Cassandra partition query.
    result=c.get('/api/ops/audit?day=2026-01-01&actor=user-1&limit=200',headers=h('admin')).json()
    assert 'audit_by_actor_day WHERE actor_id = %s AND event_day = %s' in result['query']
    assert result['database_succeeded'] is True

def test_username_filter_uses_username_partition_and_target_filter_uses_target_partition(app_client,monkeypatch):
    c,_=app_client;row=type('Row',(),dict(event_id='1',actor_id='a',username='Alice',role='admin',action='case_create',target='acct-1',details='',outcome='ok',event_time=datetime.now(timezone.utc),event_day=date.today()))()
    session=AuditSession([row]);monkeypatch.setattr(lab16,'_cassandra',lambda:session)
    by_user=c.get('/api/ops/audit?username=Alice',headers=h('admin')).json()
    assert 'audit_by_user_day WHERE username = %s' in by_user['query']
    by_target=c.get('/api/ops/audit?target=acct-1&day='+date.today().isoformat(),headers=h('admin')).json()
    assert 'audit_by_target_day WHERE target = %s' in by_target['query']

def test_audit_summary_counts_categories_and_failure_outcomes(app_client,monkeypatch):
    c,_=app_client;today=date.today()
    rows=[type('Row',(),dict(event_id='1',actor_id='a',username='A',role='admin',action='sign_in',target='',details='',outcome='ok',event_time=datetime.now(timezone.utc),event_day=today))(),type('Row',(),dict(event_id='2',actor_id='b',username='B',role='admin',action='case_create',target='',details='',outcome='refused',event_time=datetime.now(timezone.utc),event_day=today))()]
    monkeypatch.setattr(lab16,'_cassandra',lambda:AuditSession(rows))
    data=c.get('/api/ops/audit/summary?days=7',headers=h('admin')).json()
    assert data['database_succeeded'] and data['events_today']==2 and data['failed_or_refused']==1
    assert data['daily'][0]['sign_ins']==1 and data['daily'][0]['cases']==1

def test_fraud_review_and_three_hop_graph_evidence(app_client,monkeypatch):
    c,db=app_client
    db['lab10_accounts'].rows=[{'account_id':'acct-A','risk_level':'high','fraud_flag':True,'risk_signals':['shared_device'],'device_ids':['device-A'],'email':'private@example.test'}]
    overview={'acct-A':{'devices':['device-A'],'peers':['acct-B']}}
    monkeypatch.setattr(lab16,'_graph_overview',lambda ids:(overview,{'succeeded':True,'skipped':False,'query_time_ms':1}))
    listing=c.get('/api/moderation/fraud',headers=h('hunter')).json()
    assert listing['accounts'][0]['risk_indicator']=='high' and listing['accounts'][0]['related_accounts']==['acct-B']
    assert listing['accounts'][0]['shared_devices']==['device-A']
    account={'account_id':'acct-A','risk_level':'high','fraud_flag':True,'risk_signals':['shared_device'],'email':'private@example.test'}
    monkeypatch.setattr(lab16,'_mongo_account',lambda aid:(account,[{'source_id':'acct-A','amount':250}],3,None))
    graph={'succeeded':True,'skipped':False,'query_time_ms':4,'query':'MATCH p=(a)-[*1..3]-(n)','nodes':[],'relationships':[],'related_accounts':['acct-B'],'circuit_breaker':{'state':'closed'}}
    monkeypatch.setattr(lab16,'_graph_query',lambda aid,hops:graph)
    monkeypatch.setattr(lab16,'_audit_query',lambda *args:{'events':[],'query':'CQL','query_time_ms':2,'database_succeeded':True,'skipped':False})
    detail=c.get('/api/moderation/fraud/acct-A',headers=h('hunter')).json()
    assert detail['verdict']=='flagged by MongoDB account evidence' and detail['neo4j']['related_accounts']==['acct-B']
    assert detail['mongo']['query_time_ms']==3 and detail['cassandra']['query_time_ms']==2

def test_partial_source_failure_is_not_reported_as_clean(app_client,monkeypatch):
    c,_=app_client
    monkeypatch.setattr(lab16,'_mongo_account',lambda aid:(None,[],2,'MongoDB query skipped; circuit breaker is open.'))
    monkeypatch.setattr(lab16,'_graph_query',lambda aid,hops:{'succeeded':False,'skipped':True,'error':'Neo4j circuit open','query_time_ms':None,'nodes':[],'relationships':[],'related_accounts':[],'circuit_breaker':{'state':'open'}})
    monkeypatch.setattr(lab16,'_audit_query',lambda *args:{'events':[],'query':'not executed','query_time_ms':None,'database_succeeded':False,'skipped':True,'error':'Cassandra breaker open'})
    data=c.get('/api/moderation/fraud/unknown',headers=h('hunter')).json()
    assert data['verdict']=='evidence unavailable'
    assert data['mongo']['succeeded'] is False and data['mongo']['skipped'] is True
    assert data['neo4j']['skipped'] is True and data['cassandra']['skipped'] is True

def test_graph_sync_uses_explicit_mongo_device_ids_only(app_client,monkeypatch):
    c,db=app_client;db['lab10_accounts'].rows=[{'account_id':'acct','device_ids':['dev-1']}]
    calls=[]
    class Session(NeoSession):
        def run(self,*args,**kwargs):calls.append((args,kwargs));return []
    monkeypatch.setattr(lab16,'_neo4j',lambda:NeoDriver())
    driver=NeoDriver();driver.session=lambda **kwargs:Session()
    monkeypatch.setattr(lab16,'_neo4j',lambda:driver)
    result=c.post('/api/ops/lab16/graph/sync',headers=h('admin'),json={})
    assert result.status_code==200 and result.json()['created_synthetic_relationships'] is False
    assert any('USES_DEVICE' in call[0][0] for call in calls)

def test_graph_query_uses_real_bounded_three_hop_cypher(app_client,monkeypatch):
    c,_=app_client;captured=[]
    class FakeSession:
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def run(self,query,*args,**kwargs):captured.append(query);return GraphResult()
    class FakeDriver:
        def session(self,**kwargs):return FakeSession()
    monkeypatch.setattr(lab16,'_neo4j',lambda:FakeDriver())
    result=lab16._graph_query('acct-root',3)
    assert result['succeeded'] and '[*1..3]' in captured[0] and 'acct-root' not in captured[0]

def test_frontend_includes_workspace_graph_rendering_and_required_tabs():
    from pathlib import Path
    root=Path(__file__).resolve().parents[2]/'frontend'
    html=(root/'lab16.html').read_text()
    script=(root/'lab16.js').read_text()
    assert all(name in html for name in ('Overview','Service Management','Audit Log','Fraud Review','Graph Investigation'))
    assert 'aria-label="Neo4j account and device relationship graph"' in script
    assert 'data-node' in script and 'Node details' in html

def test_main_app_exposes_chapter16_api_and_page_aliases():
    from app.main import app
    paths=set(app.openapi()['paths'])
    assert {'/api/services/lab16','/api/services/lab16/start','/api/services/lab16/stop','/api/ops/audit','/api/ops/audit/summary','/api/moderation/fraud','/api/moderation/fraud/{account}','/api/ops/lab16/graph/sync'} <= paths
    page_routes={getattr(route,'path',None) for route in app.routes}
    assert {'/extras/lab16','/admin/ops','/moderation'} <= page_routes

