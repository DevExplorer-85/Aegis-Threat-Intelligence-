import hashlib
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Header, status
from pydantic import BaseModel, EmailStr, Field
from app.database import db

router = APIRouter(prefix="/api/auth", tags=["Authentication & User Management"])

# In-memory session store (token -> session dict), persisted to MongoDB when connected
SESSIONS = {}

class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., min_length=5, max_length=150)
    password: str = Field(..., min_length=6)
    organization: Optional[str] = "Global SOC Operations"
    role: Optional[str] = "soc_analyst"  # admin, threat_hunter, soc_analyst, compliance_auditor

class LoginRequest(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    organization: str
    role: str
    role_display: str
    permissions: list[str]

ROLE_CONFIGS = {
    "admin": {
        "display": "Global Security Admin",
        "permissions": ["all", "manage_users", "view_unredacted_pii", "execute_playbooks", "cluster_ops", "audit_logs", "monitoring_admin", "moderate_alerts"]
    },
    "threat_hunter": {
        "display": "Lead Threat Hunter",
        "permissions": ["ioc_search", "threat_actors", "view_unredacted_pii", "execute_playbooks", "export_intel", "moderate_alerts"]
    },
    "soc_analyst": {
        "display": "Tier-1 SOC Analyst (Redacted)",
        "permissions": ["ioc_search", "view_threat_feeds", "view_redacted_pii"]
    },
    "compliance_auditor": {
        "display": "Compliance Auditor (Read-Only)",
        "permissions": ["audit_logs", "view_compliance_reports", "view_redacted_pii"]
    }
}

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def _audit_auth(action: str, target: str, user: Optional[dict] = None, outcome: str = "ok") -> None:
    try:
        from app.lab16_api import record_audit
        record_audit(user, action, target, {"source": "authentication"}, outcome)
    except Exception:
        # Authentication remains available when optional Chapter 16 audit stores are down.
        pass

def ensure_users_collection():
    if db is not None:
        try:
            db.users.create_index("email", unique=True)
        except Exception:
            pass

@router.post("/register")
def register(req: RegisterRequest):
    # Platform privileges are assigned only by trusted provisioning, never public signup.
    role = "soc_analyst"
    email_clean = req.email.strip().lower()
    
    if db is not None:
        existing = db.users.find_one({"email": email_clean})
        if existing:
            raise HTTPException(status_code=400, detail="User with this email already exists")
        
        user_doc = {
            "name": req.name.strip(),
            "email": email_clean,
            "password_hash": hash_password(req.password),
            "organization": req.organization.strip(),
            "role": role,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        res = db.users.insert_one(user_doc)
        user_id = str(res.inserted_id)
    else:
        user_id = secrets.token_hex(8)

    token = secrets.token_hex(24)
    user_info = {
        "id": user_id,
        "name": req.name.strip(),
        "email": email_clean,
        "organization": req.organization.strip(),
        "role": role,
        "role_display": ROLE_CONFIGS[role]["display"],
        "permissions": ROLE_CONFIGS[role]["permissions"]
    }
    SESSIONS[token] = user_info
    _audit_auth("sign_in", email_clean, user_info)

    return {"token": token, "user": user_info}

@router.post("/login")
def login(req: LoginRequest):
    email_clean = req.email.strip().lower()
    password_hash = hash_password(req.password)
    
    user = None
    if db is not None:
        user = db.users.find_one({"email": email_clean, "password_hash": password_hash})
    
    # Fallback default demo account if DB has no users or for quick start
    if not user and email_clean == "admin@cti.platform" and req.password == "admin123":
        user = {
            "_id": "admin_master_1",
            "name": "CTI Platform Administrator",
            "email": "admin@cti.platform",
            "organization": "Enterprise Cyber Defense",
            "role": "admin"
        }
    elif not user and email_clean == "analyst@cti.platform" and req.password == "analyst123":
        user = {
            "_id": "analyst_1",
            "name": "Alex Carter (SOC Tier 1)",
            "email": "analyst@cti.platform",
            "organization": "Security Operations Center",
            "role": "soc_analyst"
        }

    if not user:
        _audit_auth("sign_in", email_clean, outcome="refused")
        raise HTTPException(status_code=401, detail="Invalid email or password")

    role = user.get("role", "soc_analyst")
    if role not in ROLE_CONFIGS:
        role = "soc_analyst"

    token = secrets.token_hex(24)
    user_info = {
        "id": str(user.get("_id", "1")),
        "name": user.get("name", "Security User"),
        "email": email_clean,
        "organization": user.get("organization", "Global SOC"),
        "role": role,
        "role_display": ROLE_CONFIGS[role]["display"],
        "permissions": ROLE_CONFIGS[role]["permissions"]
    }
    SESSIONS[token] = user_info
    _audit_auth("sign_in", email_clean, user_info)

    return {"token": token, "user": user_info}

@router.get("/me")
def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        # Return guest/demo profile
        return {
            "authenticated": False,
            "user": {
                "id": "guest",
                "name": "Guest Analyst",
                "email": "guest@cti.platform",
                "organization": "Trial Workspace",
                "role": "soc_analyst",
                "role_display": ROLE_CONFIGS["soc_analyst"]["display"],
                "permissions": ROLE_CONFIGS["soc_analyst"]["permissions"]
            }
        }
    
    token = authorization.replace("Bearer ", "").strip()
    user = SESSIONS.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    
    return {"authenticated": True, "user": user}

@router.get("/roles")
def list_available_roles():
    return ROLE_CONFIGS
