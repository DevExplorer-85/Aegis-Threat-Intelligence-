"""Tenant-scoped case management APIs for Chapter 15."""
from datetime import datetime, timezone, timedelta
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.database import db
from app.auth import SESSIONS

router = APIRouter(tags=["Chapter 15 · Case Management"])

def now():
    return datetime.now(timezone.utc)

def stamp():
    return now().isoformat()

def org_id_for(user_id: str) -> str:
    return f"org_{user_id}"

def ensure_membership(user: dict) -> dict:
    """Provision a private workspace for legacy/demo accounts; never merge by name."""
    uid = str(user.get("id") or "guest")
    if uid == "guest":
        raise HTTPException(401, "Sign in to use case management.")
    existing_membership = None
    try:
        existing_membership = db.organization_memberships.find_one({"user_id": uid, "status": "active"})
    except Exception:
        pass
    org_id = user.get("organization_id") or (existing_membership or {}).get("organization_id") or org_id_for(uid)
    org_name = user.get("organization") or "Security Operations"
    default_role = "org_admin" if user.get("role") == "admin" else "member"
    try:
        db.organizations.update_one({"organization_id": org_id}, {"$setOnInsert": {
            "organization_id": org_id, "name": org_name, "status": "active", "created_at": stamp()
        }}, upsert=True)
        db.organization_memberships.update_one(
            {"organization_id": org_id, "user_id": uid},
            {"$setOnInsert": {"membership_id": str(uuid4()), "organization_id": org_id,
             "user_id": uid, "role": default_role, "status": "active", "created_at": stamp()}}, upsert=True)
        membership = db.organization_memberships.find_one({"organization_id": org_id, "user_id": uid}) or {}
        user.update({"organization_id": org_id, "organization_role": membership.get("role", default_role)})
        return membership
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Case workspace database is unavailable.") from exc

def ensure_indexes():
    for coll, keys, unique in (("organizations", [("organization_id", 1)], True),
                               ("organization_memberships", [("organization_id", 1), ("user_id", 1)], True),
                               ("cases", [("organization_id", 1), ("updated_at", -1)], False),
                               ("case_rate_limits", [("bucket_id", 1)], True),
                               ("case_rate_limit_refusals", [("created_at", -1)], False)):
        try:
            db[coll].create_index(keys, unique=unique)
        except Exception:
            pass
    try:
        db.case_rate_limits.create_index("expires_at", expireAfterSeconds=0)
        db.case_rate_limit_refusals.create_index("created_at", expireAfterSeconds=60*60*24*90)
    except Exception:
        pass

def current_user(authorization: Optional[str]):
    if not authorization:
        raise HTTPException(401, "Sign in to use case management.")
    token = authorization.removeprefix("Bearer ").strip()
    user = SESSIONS.get(token)
    if not user:
        raise HTTPException(401, "Session expired or invalid.")
    membership = ensure_membership(user)
    return user, membership

def require_role(user, membership, roles):
    role = membership.get("role")
    if role not in roles and "all" not in user.get("permissions", []):
        raise HTTPException(403, "Your organization role cannot perform this action.")

def check_rate_limit(user, response, action="write"):
    limit = 30 if action == "write" else 120
    now_dt = now()
    minute = now_dt.strftime("%Y%m%d%H%M")
    bucket_id = f"{user['organization_id']}:{user['id']}:{action}:{minute}"
    try:
        doc = db.case_rate_limits.find_one_and_update(
            {"bucket_id": bucket_id}, {"$inc": {"count": 1}, "$setOnInsert": {"expires_at": now_dt + timedelta(minutes=3)}},
            upsert=True, return_document=True)
        count = int((doc or {}).get("count", 1))
    except Exception:
        # Fail closed when limiter persistence is unavailable.
        raise HTTPException(503, "Rate limit service is unavailable.")
    response.headers["X-RateLimit-Limit"] = str(limit)
    response.headers["X-RateLimit-Remaining"] = str(max(0, limit-count))
    if count > limit:
        retry = 60 - now_dt.second
        try:
            db.case_rate_limit_refusals.insert_one({"organization_id": user["organization_id"], "user_id": user["id"], "created_at": now_dt})
        except Exception:
            pass
        raise HTTPException(429, detail={"message": f"Rate limit reached ({limit} requests/minute). Try again in {retry} seconds.", "limit": limit, "retry_after": retry}, headers={"Retry-After": str(retry), "X-RateLimit-Limit": str(limit)})

def can_see_case(case, user, membership):
    role = membership.get("role")
    return role in ("org_admin", "case_manager") or case.get("created_by") == user["id"] or case.get("assignee_id") == user["id"]

def case_output(doc):
    if not doc: return None
    return {k: v for k, v in doc.items() if not k.startswith("_")}

def _audit_case(user, action: str, case_id: str, outcome: str = "ok"):
    try:
        from app.lab16_api import record_audit
        record_audit(user, action, case_id, {"source": "case-management"}, outcome)
    except Exception:
        pass

class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=180)
    description: str = Field(default="", max_length=10000)
    severity: str = "medium"
    status: str = "Open"
    assignee_id: Optional[str] = None
    linked_event: Optional[dict] = None
    linked_threat: Optional[dict] = None

class CasePatch(BaseModel):
    title: Optional[str] = Field(default=None, min_length=3, max_length=180)
    description: Optional[str] = Field(default=None, max_length=10000)
    severity: Optional[str] = None
    status: Optional[str] = None
    assignee_id: Optional[str] = None
    linked_event: Optional[dict] = None
    linked_threat: Optional[dict] = None

def validate_links(payload):
    event = payload.get("linked_event")
    if event:
        feed_id, event_uuid = event.get("feed_id"), event.get("event_uuid")
        if not feed_id or not event_uuid or not db.feed_events.find_one({"feed_id": feed_id, "event_uuid": event_uuid}):
            raise HTTPException(422, "Linked event was not found in the threat feed.")
        payload["linked_event"] = {"feed_id": feed_id, "event_uuid": event_uuid}
    threat = payload.get("linked_threat")
    if threat:
        report_id = threat.get("report_id") or threat.get("id")
        if not report_id or not db.threat_reports.find_one({"$or": [{"report_id": report_id}, {"id": report_id}, {"_id": report_id}]}):
            raise HTTPException(422, "Linked threat report was not found.")
        payload["linked_threat"] = {"report_id": str(report_id)}
    return payload

@router.get("/api/cases/me")
def my_cases(response: Response, authorization: Optional[str] = Header(None)):
    user, member = current_user(authorization); check_rate_limit(user, response, "read")
    query = {"organization_id": user["organization_id"]}
    if member.get("role") == "member": query["$or"] = [{"created_by": user["id"]}, {"assignee_id": user["id"]}]
    docs = db.cases.find(query).sort("updated_at", -1).limit(300)
    return {"cases": [case_output(x) for x in docs], "organization": {"id": user["organization_id"], "name": user["organization"]}, "role": member.get("role")}

@router.get("/api/cases")
def list_cases(response: Response, status_filter: Optional[str] = None, q: Optional[str] = None, authorization: Optional[str] = Header(None)):
    user, member = current_user(authorization); check_rate_limit(user, response, "read")
    query = {"organization_id": user["organization_id"]}
    if member.get("role") == "member": query["$or"] = [{"created_by": user["id"]}, {"assignee_id": user["id"]}]
    if status_filter in ("Open", "In Progress", "Closed"): query["status"] = status_filter
    if q: query["$and"] = [{"$or": [{"title": {"$regex": q[:100], "$options": "i"}}, {"description": {"$regex": q[:100], "$options": "i"}}]}]
    docs = list(db.cases.find(query).sort("updated_at", -1).limit(500))
    return {"cases": [case_output(x) for x in docs], "count": len(docs)}

@router.post("/api/cases", status_code=201)
def create_case(body: CaseCreate, response: Response, authorization: Optional[str] = Header(None)):
    user, member = current_user(authorization); check_rate_limit(user, response)
    if body.status not in ("Open", "In Progress", "Closed") or body.severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(422, "Invalid status or severity.")
    data = validate_links(body.model_dump(exclude_none=True))
    if data.get("assignee_id"):
        require_role(user, member, ("org_admin", "case_manager"))
        if not db.organization_memberships.find_one({"organization_id": user["organization_id"], "user_id": data["assignee_id"], "status": "active"}): raise HTTPException(422, "Assignee must be an active member of this organization.")
    doc = {**data, "case_id": str(uuid4()), "organization_id": user["organization_id"], "created_by": user["id"], "created_by_name": user["name"], "created_at": stamp(), "updated_at": stamp()}
    db.cases.insert_one(doc)
    _audit_case(user, "case_create", doc["case_id"])
    return {"case": case_output(doc)}

@router.get("/api/cases/org/members")
def org_members(response: Response, authorization: Optional[str] = Header(None)):
    user, member = current_user(authorization); check_rate_limit(user, response, "read")
    docs = db.organization_memberships.find({"organization_id": user["organization_id"], "status": "active"})
    users = {str(u["_id"]): u for u in db.users.find({})}
    result=[]
    for m in docs:
        u=users.get(m["user_id"], {})
        result.append({"user_id": m["user_id"], "name": u.get("name", m["user_id"]), "email": u.get("email", ""), "role": m.get("role")})
    return {"members": result}

def provision_membership(organization_id: str, body: dict):
    target=str(body.get("user_id", "")); role=body.get("role", "member")
    existing_user=db.users.find_one({"_id": target})
    if not existing_user:
        try:
            from bson import ObjectId
            existing_user=db.users.find_one({"_id": ObjectId(target)})
        except Exception:
            existing_user=None
    is_demo_user = target in {"admin_master_1", "analyst_1"}
    if role not in ("org_admin", "case_manager", "member") or (not existing_user and not is_demo_user):
        raise HTTPException(422, "Choose an existing user ID and a valid organization role.")
    if not db.organizations.find_one({"organization_id": organization_id}):
        raise HTTPException(404, "Organization not found.")
    membership={"membership_id": str(uuid4()), "organization_id": organization_id, "user_id": target, "role": role, "status": "active", "created_at": stamp()}
    try: db.organization_memberships.insert_one(membership)
    except Exception: raise HTTPException(409, "User is already a member of this organization.")
    return {"membership": {k:v for k,v in membership.items() if k != "_id"}}

@router.post("/api/cases/org/members", status_code=201)
def add_tenant_member(body: dict, authorization: Optional[str] = Header(None)):
    user, member=current_user(authorization)
    require_role(user, member, ("org_admin",))
    return provision_membership(user["organization_id"], body)

@router.get("/api/cases/{case_id}")
def get_case(case_id: str, response: Response, authorization: Optional[str] = Header(None)):
    user, member = current_user(authorization); check_rate_limit(user, response, "read")
    doc = db.cases.find_one({"case_id": case_id, "organization_id": user["organization_id"]})
    if not doc or not can_see_case(doc, user, member): raise HTTPException(404, "Case not found.")
    return {"case": case_output(doc)}

@router.patch("/api/cases/{case_id}")
def update_case(case_id: str, body: CasePatch, response: Response, authorization: Optional[str] = Header(None)):
    user, member = current_user(authorization); check_rate_limit(user, response)
    doc=db.cases.find_one({"case_id": case_id, "organization_id": user["organization_id"]})
    if not doc or not can_see_case(doc, user, member): raise HTTPException(404, "Case not found.")
    changes=body.model_dump(exclude_unset=True)
    if not changes: return {"case": case_output(doc)}
    if "linked_event" in changes or "linked_threat" in changes:
        changes=validate_links(changes)
    if "status" in changes and changes["status"] not in ("Open", "In Progress", "Closed"): raise HTTPException(422, "Invalid case status.")
    if "severity" in changes and changes["severity"] not in ("low", "medium", "high", "critical"): raise HTTPException(422, "Invalid severity.")
    if "assignee_id" in changes:
        require_role(user, member, ("org_admin", "case_manager"))
        aid=changes["assignee_id"]
        if aid and not db.organization_memberships.find_one({"organization_id": user["organization_id"], "user_id": aid, "status": "active"}): raise HTTPException(422, "Assignee must be an active member of this organization.")
    if member.get("role") == "member" and (set(changes)-{"status"}): require_role(user, member, ("case_manager", "org_admin"))
    changes["updated_at"]=stamp()
    db.cases.update_one({"case_id": case_id, "organization_id": user["organization_id"]}, {"$set": changes})
    _audit_case(user, "case_update", case_id)
    return {"case": case_output(db.cases.find_one({"case_id": case_id, "organization_id": user["organization_id"]}))}

@router.delete("/api/cases/{case_id}")
def delete_case(case_id: str, response: Response, authorization: Optional[str] = Header(None)):
    user, member=current_user(authorization); check_rate_limit(user, response)
    require_role(user, member, ("org_admin",))
    result=db.cases.delete_one({"case_id": case_id, "organization_id": user["organization_id"]})
    if not result.deleted_count: raise HTTPException(404, "Case not found.")
    _audit_case(user, "case_delete", case_id)
    return {"deleted": True, "case_id": case_id}

def is_platform_admin(user):
    return user.get("role") == "admin" or "all" in user.get("permissions", [])

@router.get("/api/moderation/organisations")
def organizations(authorization: Optional[str] = Header(None)):
    user, _ = current_user(authorization)
    if not is_platform_admin(user): raise HTTPException(403, "Platform administrator access required.")
    orgs=list(db.organizations.find({}, {"_id": 0, "organization_id": 1, "name": 1, "status": 1}))
    result=[]
    for o in orgs:
        oid=o["organization_id"]
        result.append({**o, "member_count": db.organization_memberships.count_documents({"organization_id": oid, "status": "active"}), "case_count": db.cases.count_documents({"organization_id": oid}), "rate_limit_refusals": db.case_rate_limit_refusals.count_documents({"organization_id": oid})})
    return {"organisations": result, "total_organisations": len(orgs), "total_members": db.organization_memberships.count_documents({"status": "active"}), "total_cases": db.cases.count_documents({}), "total_rate_limit_refusals": db.case_rate_limit_refusals.count_documents({})}

@router.post("/api/moderation/organisations", status_code=201)
def create_organization(body: dict, authorization: Optional[str] = Header(None)):
    user, _=current_user(authorization)
    if not is_platform_admin(user): raise HTTPException(403, "Platform administrator access required.")
    name=str(body.get("name", "")).strip()
    if not 2 <= len(name) <= 120: raise HTTPException(422, "Organization name must be 2–120 characters.")
    oid=f"org_{uuid4()}"
    db.organizations.insert_one({"organization_id": oid, "name": name, "status": "active", "created_at": stamp()})
    return {"organization": {"organization_id": oid, "name": name, "status": "active"}}

@router.post("/api/moderation/organisations/{organization_id}/members", status_code=201)
def add_org_member(organization_id: str, body: dict, authorization: Optional[str] = Header(None)):
    user, _=current_user(authorization)
    if not is_platform_admin(user): raise HTTPException(403, "Platform administrator access required.")
    return provision_membership(organization_id, body)
