from copy import deepcopy

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import cases_api
from app.auth import SESSIONS


def matches(row, query):
    for key, value in query.items():
        if key == "$or":
            if not any(matches(row, part) for part in value): return False
        elif key == "$and":
            if not all(matches(row, part) for part in value): return False
        elif isinstance(value, dict) and "$regex" in value:
            import re
            if not re.search(value["$regex"], str(row.get(key, "")), re.I): return False
        elif isinstance(value, dict) and "$in" in value:
            if row.get(key) not in value["$in"]: return False
        elif row.get(key) != value: return False
    return True


class Cursor:
    def __init__(self, rows): self.rows=rows
    def sort(self, key, direction=-1):
        if isinstance(key, list): key,direction=key[0]
        self.rows.sort(key=lambda d:d.get(key,""), reverse=direction==-1); return self
    def limit(self, n): self.rows=self.rows[:n]; return self
    def __iter__(self): return iter(self.rows)


class Collection:
    def __init__(self): self.rows=[]
    def create_index(self,*a,**kw): pass
    def find(self,q=None,*a,**kw): return Cursor([deepcopy(x) for x in self.rows if matches(x,q or {})])
    def find_one(self,q=None,*a,**kw): return next((deepcopy(x) for x in self.rows if matches(x,q or {})),None)
    def insert_one(self,d):
        self.rows.append(deepcopy(d)); return type("R",(),{"inserted_id":len(self.rows)})()
    def update_one(self,q,u,upsert=False):
        row=next((x for x in self.rows if matches(x,q)),None)
        if row is None and upsert:
            row=deepcopy(q); row.update(deepcopy(u.get("$setOnInsert",{}))); self.rows.append(row)
        if row: row.update(deepcopy(u.get("$set",{})))
    def find_one_and_update(self,q,u,upsert=False,return_document=None):
        row=next((x for x in self.rows if matches(x,q)),None)
        if row is None and upsert:
            row=deepcopy(q); row.update(deepcopy(u.get("$setOnInsert",{}))); row["count"]=0; self.rows.append(row)
        if row: row["count"]+=u.get("$inc",{}).get("count",0); return deepcopy(row)
    def delete_one(self,q):
        row=next((x for x in self.rows if matches(x,q)),None)
        if row: self.rows.remove(row)
        return type("R",(),{"deleted_count":int(row is not None)})()
    def count_documents(self,q=None): return sum(matches(x,q or {}) for x in self.rows)


class Database:
    def __init__(self): self.c={}
    def __getattr__(self,k): return self[k]
    def __getitem__(self,k): return self.c.setdefault(k,Collection())


@pytest.fixture
def client(monkeypatch):
    db=Database(); monkeypatch.setattr(cases_api,"db",db)
    SESSIONS.clear()
    SESSIONS["admin-token"]={"id":"admin1","name":"Org Admin","email":"a@x","organization":"Tenant A","role":"admin","permissions":["all"]}
    SESSIONS["member-token"]={"id":"member1","name":"Member","organization":"Tenant A","role":"soc_analyst","permissions":[]}
    SESSIONS["other-token"]={"id":"other1","name":"Other","organization":"Tenant B","role":"soc_analyst","permissions":[]}
    # Pre-provision member in the same tenant for assignment checks.
    db.organization_memberships.insert_one({"organization_id":"org_admin1","user_id":"member1","role":"member","status":"active"})
    app=FastAPI(); app.include_router(cases_api.router)
    with TestClient(app) as test_client: yield test_client,db
    SESSIONS.clear()


def auth(token): return {"Authorization":f"Bearer {token}"}


def test_create_read_update_and_delete_case(client):
    c,_=client
    created=c.post("/api/cases",headers=auth("admin-token"),json={"title":"Investigate phishing","description":"Mailbox evidence","severity":"high","assignee_id":"member1"})
    assert created.status_code==201
    item=created.json()["case"]
    assert item["organization_id"]=="org_admin1" and item["assignee_id"]=="member1"
    assert c.get(f"/api/cases/{item['case_id']}",headers=auth("member-token")).status_code==200
    assert c.patch(f"/api/cases/{item['case_id']}",headers=auth("member-token"),json={"status":"In Progress"}).status_code==200
    assert c.delete(f"/api/cases/{item['case_id']}",headers=auth("admin-token")).json()["deleted"] is True


def test_cross_tenant_case_read_update_delete_are_hidden(client):
    c,_=client
    item=c.post("/api/cases",headers=auth("admin-token"),json={"title":"Tenant private investigation"}).json()["case"]
    path=f"/api/cases/{item['case_id']}"
    assert c.get(path,headers=auth("other-token")).status_code==404
    assert c.patch(path,headers=auth("other-token"),json={"status":"Closed"}).status_code==404
    assert c.delete(path,headers=auth("other-token")).status_code==403


def test_member_case_scope_and_role_permissions(client):
    c,_=client
    private=c.post("/api/cases",headers=auth("admin-token"),json={"title":"Admin-only case"}).json()["case"]
    assert c.get("/api/cases",headers=auth("member-token")).json()["count"]==0
    assert c.patch(f"/api/cases/{private['case_id']}",headers=auth("member-token"),json={"description":"attempt"}).status_code==404
    assert c.delete(f"/api/cases/{private['case_id']}",headers=auth("member-token")).status_code==403


def test_organization_analytics_are_platform_admin_only_and_metadata_only(client):
    c,_=client
    c.post("/api/cases",headers=auth("admin-token"),json={"title":"Private incident","description":"SECRET DESCRIPTION"})
    denied=c.get("/api/moderation/organisations",headers=auth("member-token"))
    assert denied.status_code==403
    result=c.get("/api/moderation/organisations",headers=auth("admin-token"))
    assert result.status_code==200
    assert "SECRET DESCRIPTION" not in result.text and "Private incident" not in result.text
    assert result.json()["total_cases"]==1


def test_rate_limit_returns_real_limit_and_retry_after(client,monkeypatch):
    c,_=client
    monkeypatch.setattr(cases_api,"now",lambda: __import__("datetime").datetime(2026,1,1,0,0,30,tzinfo=__import__("datetime").timezone.utc))
    for i in range(30):
        response=c.post("/api/cases",headers=auth("admin-token"),json={"title":f"Case number {i}"})
        assert response.status_code==201
    response=c.post("/api/cases",headers=auth("admin-token"),json={"title":"one too many"})
    assert response.status_code==429
    assert response.headers["X-RateLimit-Limit"]=="30"
    assert response.headers["Retry-After"]=="30"
    assert response.json()["detail"]["limit"]==30


def test_event_link_is_validated_and_minimized(client):
    c,db=client
    db.feed_events.insert_one({"feed_id":"feedA","event_uuid":"evtA","title":"Do not copy event body"})
    ok=c.post("/api/cases",headers=auth("admin-token"),json={"title":"Linked event","linked_event":{"feed_id":"feedA","event_uuid":"evtA","title":"untrusted extra"}})
    assert ok.status_code==201
    assert ok.json()["case"]["linked_event"]=={"feed_id":"feedA","event_uuid":"evtA"}
    bad=c.post("/api/cases",headers=auth("admin-token"),json={"title":"Bad event","linked_event":{"feed_id":"missing","event_uuid":"x"}})
    assert bad.status_code==422
