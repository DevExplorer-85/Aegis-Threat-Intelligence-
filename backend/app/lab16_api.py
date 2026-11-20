"""Chapter 16 real MongoDB, Cassandra and Neo4j operations."""
from __future__ import annotations

import os
import threading
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from app.auth import SESSIONS
from app.database import client as mongo_client, db

router = APIRouter(tags=["Chapter 16 · Polyglot Investigations"])
AUDIT_OUTBOX = "lab16_audit_outbox"
_lock = threading.RLock()
_cassandra_session = None
_cassandra_cluster = None
_neo4j_driver = None
_breakers: dict[str, dict[str, Any]] = {
    name: {"state": "closed", "failures": 0, "opened_at": None, "last_success": None, "last_error": None}
    for name in ("mongodb", "cassandra", "neo4j")
}
_BREAK_THRESHOLD = max(1, int(os.getenv("LAB16_CIRCUIT_FAILURE_THRESHOLD", "3")))
_RESET_SECONDS = max(5, int(os.getenv("LAB16_CIRCUIT_RESET_SECONDS", "30")))


def ensure_indexes() -> None:
    try:
        db[AUDIT_OUTBOX].create_index("event_id", unique=True)
        db[AUDIT_OUTBOX].create_index([("cassandra_written_at", 1), ("timestamp", 1)])
    except Exception:
        pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_error(error: Exception) -> str:
    # Keep driver errors useful without ever returning configured URIs/passwords.
    return f"{type(error).__name__}: database operation failed"


def _check_breaker(name: str) -> tuple[bool, str]:
    with _lock:
        breaker = _breakers[name]
        if breaker["state"] == "open":
            elapsed = time.time() - (breaker["opened_at"] or 0)
            if elapsed < _RESET_SECONDS:
                return False, "open"
            breaker["state"] = "half_open"
        return True, breaker["state"]


def _success(name: str) -> None:
    with _lock:
        _breakers[name].update(state="closed", failures=0, opened_at=None, last_success=utcnow().isoformat(), last_error=None)


def _failure(name: str, error: Exception) -> None:
    with _lock:
        breaker = _breakers[name]
        breaker["failures"] += 1
        breaker["last_error"] = _safe_error(error)
        if breaker["failures"] >= _BREAK_THRESHOLD or breaker["state"] == "half_open":
            breaker["state"] = "open"
            breaker["opened_at"] = time.time()


def _breaker_state(name: str) -> dict[str, Any]:
    with _lock:
        item = dict(_breakers[name])
    return {"state": item["state"], "failures": item["failures"], "last_success": item["last_success"], "last_error": item["last_error"]}


def authenticated_user(authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Sign in to access Chapter 16.")
    user = SESSIONS.get(authorization.split(None, 1)[1].strip())
    if not user:
        raise HTTPException(401, "Session expired or invalid.")
    return user


def admin_user(user: dict[str, Any] = Depends(authenticated_user)) -> dict[str, Any]:
    if user.get("role") not in {"admin", "global_admin"} and "monitoring_admin" not in user.get("permissions", []):
        raise HTTPException(403, "Administrator permission is required.")
    return user


def audit_user(user: dict[str, Any] = Depends(authenticated_user)) -> dict[str, Any]:
    if user.get("role") not in {"admin", "global_admin"} and "audit_logs" not in user.get("permissions", []):
        raise HTTPException(403, "Audit log permission is required.")
    return user


def moderator_user(user: dict[str, Any] = Depends(authenticated_user)) -> dict[str, Any]:
    if user.get("role") not in {"admin", "global_admin", "threat_hunter"} and "moderate_alerts" not in user.get("permissions", []):
        raise HTTPException(403, "Fraud review permission is required.")
    return user


def _cassandra():
    global _cassandra_session, _cassandra_cluster
    if _cassandra_session is not None:
        return _cassandra_session
    points = [x.strip() for x in os.getenv("LAB16_CASSANDRA_CONTACT_POINTS", "localhost").split(",") if x.strip()]
    port = int(os.getenv("LAB16_CASSANDRA_PORT", "9042"))
    try:
        from cassandra.auth import PlainTextAuthProvider
        from cassandra.cluster import Cluster
        username, password = os.getenv("LAB16_CASSANDRA_USERNAME"), os.getenv("LAB16_CASSANDRA_PASSWORD")
        kwargs: dict[str, Any] = {"contact_points": points, "port": port, "connect_timeout": float(os.getenv("LAB16_CASSANDRA_TIMEOUT_SECONDS", "3"))}
        if username and password:
            kwargs["auth_provider"] = PlainTextAuthProvider(username=username, password=password)
        cluster = Cluster(**kwargs)
        session = cluster.connect()
        keyspace = os.getenv("LAB16_CASSANDRA_KEYSPACE", "aegis_intel")
        if not keyspace.replace("_", "").isalnum():
            raise ValueError("Invalid Cassandra keyspace name")
        session.execute(f"CREATE KEYSPACE IF NOT EXISTS {keyspace} WITH replication = {{'class':'SimpleStrategy','replication_factor':1}}")
        session.set_keyspace(keyspace)
        session.execute("""CREATE TABLE IF NOT EXISTS audit_by_day (
            event_day date, event_time timestamp, event_id text, actor_id text, username text,
            role text, action text, target text, details text, outcome text,
            PRIMARY KEY ((event_day), event_time, event_id)) WITH CLUSTERING ORDER BY (event_time DESC)""")
        session.execute("""CREATE TABLE IF NOT EXISTS audit_by_actor_day (
            actor_id text, event_day date, event_time timestamp, event_id text, username text,
            role text, action text, target text, details text, outcome text,
            PRIMARY KEY ((actor_id, event_day), event_time, event_id)) WITH CLUSTERING ORDER BY (event_time DESC)""")
        session.execute("""CREATE TABLE IF NOT EXISTS audit_by_user_day (
            username text, event_day date, event_time timestamp, event_id text, actor_id text,
            role text, action text, target text, details text, outcome text,
            PRIMARY KEY ((username, event_day), event_time, event_id)) WITH CLUSTERING ORDER BY (event_time DESC)""")
        session.execute("""CREATE TABLE IF NOT EXISTS audit_by_target_day (
            target text, event_day date, event_time timestamp, event_id text, actor_id text, username text,
            role text, action text, details text, outcome text,
            PRIMARY KEY ((target, event_day), event_time, event_id)) WITH CLUSTERING ORDER BY (event_time DESC)""")
        _cassandra_cluster, _cassandra_session = cluster, session
        return session
    except Exception:
        raise


def _neo4j():
    global _neo4j_driver
    if _neo4j_driver is not None:
        return _neo4j_driver
    uri = os.getenv("LAB16_NEO4J_URI", "bolt://localhost:7687")
    username = os.getenv("LAB16_NEO4J_USERNAME", "neo4j")
    password = os.getenv("LAB16_NEO4J_PASSWORD", "")
    if not password:
        raise RuntimeError("LAB16_NEO4J_PASSWORD is not configured")
    from neo4j import GraphDatabase
    _neo4j_driver = GraphDatabase.driver(uri, auth=(username, password), connection_timeout=float(os.getenv("LAB16_NEO4J_TIMEOUT_SECONDS", "3")))
    return _neo4j_driver


def _mongo_ping() -> dict[str, Any]:
    start = time.perf_counter()
    mongo_client.admin.command("ping")
    return {"connected": True, "latency_ms": round((time.perf_counter()-start)*1000, 2)}


def service_health(name: str) -> dict[str, Any]:
    allowed, state = _check_breaker(name)
    if not allowed:
        return {"service": name, "configured": True, "connected": False, "skipped": True, "reason": "Circuit breaker is open; health probe skipped until the reset interval expires.", "latency_ms": None, "circuit_breaker": _breaker_state(name)}
    configured = True
    start = time.perf_counter()
    try:
        if name == "mongodb":
            result = _mongo_ping()
        elif name == "cassandra":
            _cassandra().execute("SELECT release_version FROM system.local", timeout=float(os.getenv("LAB16_CASSANDRA_TIMEOUT_SECONDS", "3"))).one()
            result = {"connected": True}
        else:
            with _neo4j().session(database=os.getenv("LAB16_NEO4J_DATABASE", "neo4j")) as session:
                session.run("RETURN 1 AS ok", timeout=float(os.getenv("LAB16_NEO4J_TIMEOUT_SECONDS", "3"))).single(strict=True)
            result = {"connected": True}
        _success(name)
        return {"service": name, "configured": configured, "connected": True, "skipped": False, "latency_ms": round((time.perf_counter()-start)*1000, 2), "circuit_breaker": _breaker_state(name), "last_success": _breaker_state(name)["last_success"], **result}
    except Exception as error:
        if name == "neo4j" and not os.getenv("LAB16_NEO4J_PASSWORD"):
            configured = False
        if isinstance(error, ModuleNotFoundError):
            configured = False
        _failure(name, error)
        return {"service": name, "configured": configured, "connected": False, "skipped": False, "latency_ms": round((time.perf_counter()-start)*1000, 2), "error": "Connection or health query failed; verify service and environment configuration.", "circuit_breaker": _breaker_state(name), "last_success": _breaker_state(name)["last_success"]}


def _outbox_pending_count() -> Optional[int]:
    try:
        return db[AUDIT_OUTBOX].count_documents({"cassandra_written_at": {"$exists": False}})
    except Exception:
        return None


def _to_cassandra(event: dict[str, Any]) -> bool:
    if not _check_breaker("cassandra")[0]:
        return False
    try:
        session = _cassandra()
        day = event["timestamp"].date()
        args = (day, event["timestamp"], event["event_id"], event["actor_id"], event["username"], event["role"], event["action"], event["target"], event["details"], event["outcome"])
        session.execute("INSERT INTO audit_by_day (event_day,event_time,event_id,actor_id,username,role,action,target,details,outcome) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", args)
        session.execute("INSERT INTO audit_by_actor_day (actor_id,event_day,event_time,event_id,username,role,action,target,details,outcome) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (event["actor_id"], day, event["timestamp"], event["event_id"], event["username"], event["role"], event["action"], event["target"], event["details"], event["outcome"]))
        session.execute("INSERT INTO audit_by_user_day (username,event_day,event_time,event_id,actor_id,role,action,target,details,outcome) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (event["username"], day, event["timestamp"], event["event_id"], event["actor_id"], event["role"], event["action"], event["target"], event["details"], event["outcome"]))
        session.execute("INSERT INTO audit_by_target_day (target,event_day,event_time,event_id,actor_id,username,role,action,details,outcome) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (event["target"], day, event["timestamp"], event["event_id"], event["actor_id"], event["username"], event["role"], event["action"], event["details"], event["outcome"]))
        _success("cassandra")
        return True
    except Exception as error:
        _failure("cassandra", error)
        return False


def record_audit(actor: Optional[dict[str, Any]], action: str, target: str = "", details: Optional[dict[str, Any]] = None, outcome: str = "ok") -> dict[str, Any]:
    """Persist an outbox event in Mongo before attempting idempotent Cassandra inserts."""
    user = actor or {}
    event = {"event_id": str(uuid.uuid4()), "timestamp": utcnow(), "actor_id": str(user.get("id", "system")),
             "username": str(user.get("name") or user.get("email") or "system")[:160], "role": str(user.get("role", "system"))[:80],
             "action": str(action)[:120], "target": str(target)[:240], "details": str(details or {})[:2000],
             "outcome": outcome if outcome in {"ok", "refused", "failed"} else "failed"}
    # PyMongo's background monitor supplies this cached signal without a network wait.
    # Avoid stalling login/case actions for the full server-selection timeout when MongoDB
    # is already known to be unavailable. We do not claim the event was persisted.
    try:
        if not mongo_client.topology_description.has_writable_server():
            return {"mongo_persisted": False, "cassandra_persisted": False, "pending": None}
    except Exception:
        pass
    try:
        db[AUDIT_OUTBOX].insert_one(event)
    except Exception:
        return {"mongo_persisted": False, "cassandra_persisted": False, "pending": None}
    written = _to_cassandra(event)
    if written:
        try:
            db[AUDIT_OUTBOX].update_one({"event_id": event["event_id"]}, {"$set": {"cassandra_written_at": utcnow()}})
        except Exception:
            written = False
    return {"mongo_persisted": True, "cassandra_persisted": written, "pending": not written}


def flush_pending(limit: int = 100) -> dict[str, int]:
    try:
        pending = list(db[AUDIT_OUTBOX].find({"cassandra_written_at": {"$exists": False}}).sort("timestamp", 1).limit(limit))
    except Exception:
        return {"attempted": 0, "written": 0}
    written = 0
    for item in pending:
        if not _to_cassandra(item):
            break
        db[AUDIT_OUTBOX].update_one({"event_id": item["event_id"]}, {"$set": {"cassandra_written_at": utcnow()}})
        written += 1
    return {"attempted": len(pending), "written": written}


def _container_status() -> dict[str, Any]:
    names = {"cassandra": "lab16-cassandra", "neo4j": "lab16-neo4j"}
    result = {}
    try:
        import docker
        daemon = docker.from_env(timeout=3)
        for service, name in names.items():
            try:
                container = daemon.containers.get(name)
                result[service] = {"container_exists": True, "container_state": container.status}
            except docker.errors.NotFound:
                result[service] = {"container_exists": False, "container_state": "absent"}
        daemon.close()
    except Exception:
        for service in names:
            result[service] = {"container_exists": None, "container_state": "docker daemon unavailable"}
    return result


def _manage_service(service: str, action: str) -> dict[str, Any]:
    password = os.getenv("LAB16_NEO4J_PASSWORD", "")
    if service == "neo4j" and action == "start" and len(password) < 8:
        raise HTTPException(409, "Set LAB16_NEO4J_PASSWORD to at least 8 characters before starting Neo4j.")
    try:
        import docker
        daemon = docker.from_env(timeout=5)
        name = f"lab16-{service}"
        try:
            container = daemon.containers.get(name)
        except docker.errors.NotFound:
            if action == "stop":
                return {"service": service, "container_state": "absent", "message": "Service container does not exist; nothing was stopped."}
            network_name = os.getenv("LAB16_DOCKER_NETWORK", "mongodb-labs-net")
            try:
                network = daemon.networks.get(network_name)
            except docker.errors.NotFound:
                network = daemon.networks.create(network_name, driver="bridge")
            volumes = daemon.volumes
            image = os.getenv("LAB16_CASSANDRA_IMAGE", "cassandra:4.1") if service == "cassandra" else os.getenv("LAB16_NEO4J_IMAGE", "neo4j:5")
            if service == "cassandra":
                container = daemon.containers.run(image, name=name, detach=True, network=network.name, ports={"9042/tcp": ("127.0.0.1", 9042)}, volumes={volumes.create("lab16_cassandra_data").name: {"bind": "/var/lib/cassandra", "mode": "rw"}}, environment={"MAX_HEAP_SIZE": os.getenv("LAB16_CASSANDRA_HEAP", "1G"), "HEAP_NEWSIZE": os.getenv("LAB16_CASSANDRA_NEW_HEAP", "256M")}, mem_limit=os.getenv("LAB16_CASSANDRA_MEMORY_LIMIT", "2g"), labels={"aegis.chapter": "16", "aegis.service": service})
            else:
                container = daemon.containers.run(image, name=name, detach=True, network=network.name, ports={"7474/tcp": ("127.0.0.1", 7474), "7687/tcp": ("127.0.0.1", 7687)}, volumes={volumes.create("lab16_neo4j_data").name: {"bind": "/data", "mode": "rw"}}, environment={"NEO4J_AUTH": f"{os.getenv('LAB16_NEO4J_USERNAME','neo4j')}/{password}"}, mem_limit=os.getenv("LAB16_NEO4J_MEMORY_LIMIT", "1g"), labels={"aegis.chapter": "16", "aegis.service": service})
        container.reload()
        if action == "start":
            if container.status != "running": container.start()
        elif container.status == "running":
            container.stop(timeout=15)
        container.reload()
        state = container.status
        daemon.close()
        if action == "start":
            # Running containers are not advertised as online until the DB probe works.
            return {"service": service, "container_state": state, "health": service_health(service), "message": "Container start requested; database is online only after a successful driver health query."}
        return {"service": service, "container_state": state, "health": service_health(service), "message": "Stop requested; health is determined by the actual database connection."}
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(503, "Docker service management failed; check Docker socket access and daemon state.") from error


def _audit_days(days: int) -> list[date]:
    today = utcnow().date()
    return [today - timedelta(days=offset) for offset in range(days)]


def _audit_query(day: Optional[date], actor: Optional[str], limit: int, filters: dict[str, str], range_days: int = 30) -> dict[str, Any]:
    allowed, _ = _check_breaker("cassandra")
    if not allowed:
        return {"events": [], "query": "not executed (Cassandra circuit breaker open)", "query_time_ms": None, "database_succeeded": False, "skipped": True, "error": "Cassandra query skipped while circuit breaker is open."}
    started = time.perf_counter()
    query_text = "SELECT event_day,event_time,event_id,actor_id,username,role,action,target,details,outcome FROM audit_by_day WHERE event_day = %s LIMIT %s"
    try:
        session = _cassandra()
        events = []
        days = [day] if day else _audit_days(range_days)
        for event_day in days:
            if actor:
                rows = session.execute("SELECT event_day,event_time,event_id,actor_id,username,role,action,target,details,outcome FROM audit_by_actor_day WHERE actor_id = %s AND event_day = %s LIMIT %s", (actor, event_day, limit))
                query_text = "SELECT ... FROM audit_by_actor_day WHERE actor_id = %s AND event_day = %s LIMIT %s"
            elif filters.get("username"):
                rows = session.execute("SELECT event_day,event_time,event_id,actor_id,username,role,action,target,details,outcome FROM audit_by_user_day WHERE username = %s AND event_day = %s LIMIT %s", (filters["username"], event_day, limit))
                query_text = "SELECT ... FROM audit_by_user_day WHERE username = %s AND event_day = %s LIMIT %s"
            elif filters.get("target"):
                rows = session.execute("SELECT event_day,event_time,event_id,actor_id,username,role,action,target,details,outcome FROM audit_by_target_day WHERE target = %s AND event_day = %s LIMIT %s", (filters["target"], event_day, limit))
                query_text = "SELECT ... FROM audit_by_target_day WHERE target = %s AND event_day = %s LIMIT %s"
            else:
                rows = session.execute("SELECT event_day,event_time,event_id,actor_id,username,role,action,target,details,outcome FROM audit_by_day WHERE event_day = %s LIMIT %s", (event_day, limit))
            for row in rows:
                item = {key: getattr(row, key, None) for key in ("event_id", "actor_id", "username", "role", "action", "target", "details", "outcome", "event_time", "event_day")}
                if filters.get("username") and filters["username"].casefold() not in (item["username"] or "").casefold(): continue
                if filters.get("target") and filters["target"] != (item["target"] or ""): continue
                if filters.get("role") and filters["role"].casefold() != (item["role"] or "").casefold(): continue
                if filters.get("action") and filters["action"].casefold() not in (item["action"] or "").casefold(): continue
                if filters.get("outcome") and filters["outcome"].casefold() != (item["outcome"] or "").casefold(): continue
                events.append(item)
            if len(events) >= limit: break
        events.sort(key=lambda item: item.get("event_time") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        _success("cassandra")
        return {"events": events[:limit], "query": query_text, "query_time_ms": round((time.perf_counter()-started)*1000, 2), "database_succeeded": True, "skipped": False}
    except Exception as error:
        _failure("cassandra", error)
        return {"events": [], "query": query_text, "query_time_ms": round((time.perf_counter()-started)*1000, 2), "database_succeeded": False, "skipped": False, "error": _safe_error(error)}


@router.get("/api/services/lab16")
def get_services(_user: dict[str, Any] = Depends(admin_user)):
    pending = _outbox_pending_count()
    if pending and _check_breaker("cassandra")[0]:
        flush_pending()
        pending = _outbox_pending_count()
    containers = _container_status()
    return {"services": {name: {**service_health(name), **(containers.get(name, {}) if name in containers else {})} for name in ("mongodb", "cassandra", "neo4j")}, "pending_audit_events": pending, "memory_note": "Cassandra and Neo4j are optional services. Allow approximately 2 GB RAM for Cassandra and 1 GB for Neo4j before starting both."}


@router.post("/api/services/lab16/start")
def start_services(payload: dict[str, Any] | None = None, user: dict[str, Any] = Depends(admin_user)):
    payload = payload or {}
    services = payload.get("services", ["cassandra", "neo4j"])
    if not isinstance(services, list) or not services or any(service not in {"cassandra", "neo4j"} for service in services):
        raise HTTPException(422, "services must contain cassandra and/or neo4j.")
    results=[]
    for service in services:
        try:
            result=_manage_service(service, "start")
            record_audit(user, "lab16_service_start", service, {"container_state": result.get("container_state")})
            results.append(result)
        except HTTPException as error:
            record_audit(user, "lab16_service_start", service, {"http_status": error.status_code}, "failed")
            raise
    return {"results": results, "memory_note": "Starting both optional databases may require approximately 3 GB of available RAM."}


@router.post("/api/services/lab16/stop")
def stop_services(payload: dict[str, Any] | None = None, user: dict[str, Any] = Depends(admin_user)):
    payload = payload or {}
    services = payload.get("services", ["cassandra", "neo4j"])
    if not isinstance(services, list) or not services or any(service not in {"cassandra", "neo4j"} for service in services):
        raise HTTPException(422, "services must contain cassandra and/or neo4j.")
    results=[]
    for service in services:
        try:
            result=_manage_service(service, "stop")
            record_audit(user, "lab16_service_stop", service, {"container_state": result.get("container_state")})
            results.append(result)
        except HTTPException as error:
            record_audit(user, "lab16_service_stop", service, {"http_status": error.status_code}, "failed")
            raise
    return {"results": results}


@router.get("/api/ops/audit")
def get_audit(day: Optional[date] = None, actor: Optional[str] = Query(None, max_length=160), limit: int = Query(200, ge=1, le=1000), username: Optional[str] = Query(None, max_length=160), role: Optional[str] = Query(None, max_length=80), action: Optional[str] = Query(None, max_length=120), outcome: Optional[str] = Query(None, pattern="^(ok|refused|failed)$"), target: Optional[str] = Query(None, max_length=240), _user: dict[str, Any] = Depends(audit_user)):
    return _audit_query(day, actor, limit, {"username": username or "", "role": role or "", "action": action or "", "outcome": outcome or "", "target": target or ""})


@router.get("/api/ops/audit/summary")
def audit_summary(days: int = Query(7, ge=1, le=90), _user: dict[str, Any] = Depends(audit_user)):
    query = _audit_query(None, None, 10000, {}, max(days, 7))
    if not query["database_succeeded"]:
        return {"days": days, "database_succeeded": False, "skipped": query.get("skipped", False), "error": query.get("error"), "query_time_ms": query.get("query_time_ms"), "daily": [], "events_today": None, "events_seven_days": None, "most_frequent_action": None, "failed_or_refused": None}
    cutoff = utcnow().date() - timedelta(days=days-1)
    counts: dict[str, dict[str, int]] = {}
    actions: dict[str, int] = {}
    failed = 0
    seven_cutoff = utcnow().date() - timedelta(days=6)
    total_seven = 0
    for event in query["events"]:
        event_day = event.get("event_day")
        if event_day and event_day >= seven_cutoff: total_seven += 1
        if event_day and event_day < cutoff: continue
        kind = _event_category(event.get("action", ""))
        key = event_day.isoformat() if event_day else "unknown"
        counts.setdefault(key, {name: 0 for name in ("sign_ins", "cases", "accounts", "labs", "reviews", "other")})[kind] += 1
        actions[event.get("action") or "Unknown"] = actions.get(event.get("action") or "Unknown", 0) + 1
        if event.get("outcome") in {"failed", "refused"}: failed += 1
    daily = [{"day": key, **values} for key, values in sorted(counts.items())]
    today_key = utcnow().date().isoformat()
    return {"days": days, "database_succeeded": True, "skipped": False, "daily": daily, "events_today": sum(counts.get(today_key, {}).values()), "events_seven_days": total_seven, "most_frequent_action": max(actions, key=actions.get) if actions else None, "failed_or_refused": failed, "query_time_ms": query["query_time_ms"], "query": query["query"]}


def _event_category(action: str) -> str:
    value = action.casefold()
    if "sign" in value or "login" in value or "auth" in value: return "sign_ins"
    if "case" in value: return "cases"
    if "account" in value or "transaction" in value: return "accounts"
    if "lab" in value or "service" in value: return "labs"
    if "review" in value or "fraud" in value or "moderation" in value: return "reviews"
    return "other"


def _account_collection(): return db[os.getenv("LAB16_ACCOUNTS_COLLECTION", "lab10_accounts")]
def _transaction_collection(): return db[os.getenv("LAB16_TRANSACTIONS_COLLECTION", "lab10_transfer_history")]


def _mongo_account(account_id: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]], float, str | None]:
    started = time.perf_counter()
    allowed, _ = _check_breaker("mongodb")
    if not allowed: return None, [], round((time.perf_counter()-started)*1000,2), "MongoDB query skipped; circuit breaker is open."
    try:
        account = _account_collection().find_one({"account_id": account_id}, {"_id": 0})
        transactions = list(_transaction_collection().find({"$or": [{"source_id": account_id}, {"destination_id": account_id}, {"account_id": account_id}]}, {"_id": 0}).sort("created_at", -1).limit(100))
        _success("mongodb")
        return account, transactions, round((time.perf_counter()-started)*1000,2), None
    except Exception as error:
        _failure("mongodb", error)
        return None, [], round((time.perf_counter()-started)*1000,2), _safe_error(error)


def _graph_query(account_id: str, max_hops: int = 3) -> dict[str, Any]:
    started = time.perf_counter()
    allowed, state = _check_breaker("neo4j")
    if not allowed: return {"succeeded": False, "skipped": True, "error": "Neo4j query skipped; circuit breaker is open.", "query_time_ms": None, "circuit_breaker": _breaker_state("neo4j"), "nodes": [], "relationships": [], "related_accounts": []}
    hops = max(1, min(3, max_hops))
    query = f"MATCH p=(a:Account {{account_id: $account_id}})-[*1..{hops}]-(n) WITH p LIMIT 200 UNWIND nodes(p) AS node WITH collect(DISTINCT node) AS node_list, collect(DISTINCT p) AS paths WITH node_list[0..100] AS nodes, paths UNWIND paths AS path UNWIND relationships(path) AS rel WITH nodes, collect(DISTINCT rel)[0..200] AS relationships RETURN nodes, relationships"
    try:
        with _neo4j().session(database=os.getenv("LAB16_NEO4J_DATABASE", "neo4j")) as session:
            row = session.run(query, account_id=account_id, timeout=float(os.getenv("LAB16_NEO4J_TIMEOUT_SECONDS", "5"))).single()
        graph_nodes, relations = [], []
        for node in (row["nodes"] if row else []):
            props = dict(node)
            graph_nodes.append({"id": str(node.element_id), "labels": list(node.labels), "properties": props})
        for rel in (row["relationships"] if row else []):
            relations.append({"id": str(rel.element_id), "type": rel.type, "source": str(rel.start_node.element_id), "target": str(rel.end_node.element_id), "properties": dict(rel)})
        related = sorted({n["properties"].get("account_id") for n in graph_nodes if "Account" in n["labels"] and n["properties"].get("account_id") != account_id})
        _success("neo4j")
        return {"succeeded": True, "skipped": False, "query_time_ms": round((time.perf_counter()-started)*1000,2), "query": query, "circuit_breaker": _breaker_state("neo4j"), "nodes": graph_nodes, "relationships": relations, "related_accounts": related}
    except Exception as error:
        _failure("neo4j", error)
        return {"succeeded": False, "skipped": False, "error": _safe_error(error), "query_time_ms": round((time.perf_counter()-started)*1000,2), "query": query, "circuit_breaker": _breaker_state("neo4j"), "nodes": [], "relationships": [], "related_accounts": []}


def _graph_overview(account_ids: list[str]) -> tuple[dict[str, dict[str, list[str]]], dict[str, Any]]:
    started = time.perf_counter()
    allowed, _ = _check_breaker("neo4j")
    if not allowed:
        return {}, {"succeeded": False, "skipped": True, "query_time_ms": None, "error": "Neo4j query skipped; circuit breaker is open."}
    query = "MATCH (a:Account)-[:USES_DEVICE]->(d:Device) WHERE a.account_id IN $ids OPTIONAL MATCH (d)<-[:USES_DEVICE]-(other:Account) RETURN a.account_id AS account_id, collect(DISTINCT d.device_id) AS devices, collect(DISTINCT other.account_id) AS peers LIMIT 5000"
    try:
        with _neo4j().session(database=os.getenv("LAB16_NEO4J_DATABASE", "neo4j")) as session:
            rows = list(session.run(query, ids=account_ids, timeout=float(os.getenv("LAB16_NEO4J_TIMEOUT_SECONDS", "5"))))
        output = {str(row["account_id"]): {"devices": [str(x) for x in (row["devices"] or []) if x], "peers": [str(x) for x in (row["peers"] or []) if x]} for row in rows}
        _success("neo4j")
        return output, {"succeeded": True, "skipped": False, "query_time_ms": round((time.perf_counter()-started)*1000,2), "query": query, "circuit_breaker": _breaker_state("neo4j")}
    except Exception as error:
        _failure("neo4j", error)
        return {}, {"succeeded": False, "skipped": False, "query_time_ms": round((time.perf_counter()-started)*1000,2), "query": query, "circuit_breaker": _breaker_state("neo4j"), "error": _safe_error(error)}


@router.get("/api/moderation/fraud")
def fraud_accounts(_user: dict[str, Any] = Depends(moderator_user)):
    started = time.perf_counter()
    try:
        allowed, _ = _check_breaker("mongodb")
        if not allowed:
            accounts, succeeded, skipped, error = [], False, True, "MongoDB query skipped; circuit breaker is open."
        else:
            accounts = list(_account_collection().find({}, {"_id": 0}).limit(500))
            succeeded, skipped, error = True, False, None
            _success("mongodb")
    except Exception as exc:
        accounts, succeeded, skipped, error = [], False, False, _safe_error(exc)
        _failure("mongodb", exc)
    ids = [str(account.get("account_id")) for account in accounts if account.get("account_id")]
    graph_map, graph_status = _graph_overview(ids) if ids else ({}, {"succeeded": True, "skipped": False, "query_time_ms": 0})
    result=[]
    for account in accounts:
        account_id = str(account.get("account_id", ""))
        if not account_id: continue
        graph = graph_map.get(account_id, {})
        devices = graph.get("devices", [])
        risk_signals = account.get("risk_signals") or account.get("flags") or []
        risk = account.get("risk_level") or ("flagged" if account.get("fraud_flag") is True else f"score {account['risk_score']}" if account.get("risk_score") is not None else "unscored")
        result.append({"account_id": account_id, "risk_indicator": risk, "risk_signals": risk_signals if isinstance(risk_signals, list) else [str(risk_signals)], "shared_devices": devices, "related_accounts": graph.get("peers", []), "investigation_status": account.get("investigation_status", "not started")})
    result.sort(key=lambda item: (item["risk_indicator"] == "unscored", item["account_id"]))
    record_audit(_user, "fraud_review_list", "accounts", {"count": len(result)})
    return {"accounts": result, "database": "MongoDB accounts + Neo4j explicit graph edges", "mongo": {"succeeded": succeeded, "skipped": skipped, "query_time_ms": round((time.perf_counter()-started)*1000,2), "error": error}, "neo4j": graph_status}


@router.get("/api/moderation/fraud/{account}")
def fraud_investigation(account: str, user: dict[str, Any] = Depends(moderator_user)):
    if len(account) > 160: raise HTTPException(422, "Account identifier is too long.")
    account_doc, transactions, mongo_ms, mongo_error = _mongo_account(account)
    cass_started = time.perf_counter()
    day = utcnow().date()
    audit = _audit_query(day, None, 200, {"target": account})
    audit["query_time_ms"] = round((audit.get("query_time_ms") or (time.perf_counter()-cass_started)*1000), 2)
    graph = _graph_query(account, 3)
    # Keep only role-permitted account attributes. Admins/hunters with unredacted PII can see contact data.
    permitted = {"account_id", "balance", "version", "risk_level", "risk_score", "risk_signals", "fraud_flag", "investigation_status", "device_ids", "created_at"}
    account_out = {key: value for key, value in (account_doc or {}).items() if key in permitted}
    if "view_unredacted_pii" in user.get("permissions", []) or "all" in user.get("permissions", []):
        for key in ("name", "email", "phone", "address"):
            if account_doc and key in account_doc: account_out[key] = account_doc[key]
    signals = (account_doc or {}).get("risk_signals") or (account_doc or {}).get("flags") or []
    if not isinstance(signals, list): signals = [str(signals)]
    if not account_doc and mongo_error is None:
        verdict = "no account record"
    elif not account_doc:
        verdict = "evidence unavailable"
    elif account_doc.get("fraud_flag") is True or account_doc.get("risk_level") in {"high", "critical", "fraud"}:
        verdict = "flagged by MongoDB account evidence"
    elif account_doc.get("risk_level") or account_doc.get("risk_score") is not None:
        verdict = "risk data recorded; review required"
    else:
        verdict = "unscored; no fraud conclusion"
    scored_transactions = [item for item in transactions if item.get("risk_score") is not None or item.get("risk_signals") or item.get("fraud_flag") is True]
    risky_tx = max(scored_transactions, key=lambda item: float(item.get("risk_score", 0) or 0), default=None)
    record_audit(user, "fraud_investigation", account, {"mongo_succeeded": account_doc is not None, "neo4j_succeeded": graph["succeeded"], "cassandra_succeeded": audit["database_succeeded"]})
    return {"account_id": account, "verdict": verdict, "risk_signals": signals, "account": account_out, "riskiest_transaction": risky_tx, "transactions": transactions, "mongo": {"succeeded": account_doc is not None or mongo_error is None, "skipped": mongo_error is not None and "skipped" in mongo_error, "query_time_ms": mongo_ms, "error": mongo_error, "source": os.getenv("LAB16_ACCOUNTS_COLLECTION", "lab10_accounts")}, "cassandra": {"succeeded": audit["database_succeeded"], "skipped": audit.get("skipped", False), "query_time_ms": audit["query_time_ms"], "events": audit["events"], "query": audit["query"], "error": audit.get("error"), "circuit_breaker": _breaker_state("cassandra")}, "neo4j": graph}


@router.post("/api/ops/lab16/graph/sync")
def sync_graph(_user: dict[str, Any] = Depends(admin_user)):
    started = time.perf_counter()
    mongo_allowed, _ = _check_breaker("mongodb")
    if not mongo_allowed:
        raise HTTPException(503, "MongoDB account read skipped because its circuit breaker is open.")
    try:
        rows = list(_account_collection().find({}, {"_id": 0, "account_id": 1, "device_ids": 1, "risk_level": 1, "fraud_flag": 1}).limit(5000))
        _success("mongodb")
    except Exception as error:
        _failure("mongodb", error)
        raise HTTPException(503, "MongoDB account query failed; no graph sync was performed.") from error
    try:
        driver = _neo4j()
        with driver.session(database=os.getenv("LAB16_NEO4J_DATABASE", "neo4j")) as session:
            session.run("CREATE CONSTRAINT lab16_account_id IF NOT EXISTS FOR (a:Account) REQUIRE a.account_id IS UNIQUE")
            session.run("CREATE CONSTRAINT lab16_device_id IF NOT EXISTS FOR (d:Device) REQUIRE d.device_id IS UNIQUE")
            for row in rows:
                account_id = row.get("account_id")
                if not account_id: continue
                session.run("MERGE (a:Account {account_id:$id}) SET a.risk_level=$risk, a.fraud_flag=$flag", id=str(account_id), risk=row.get("risk_level"), flag=row.get("fraud_flag"))
                for device in row.get("device_ids", []) if isinstance(row.get("device_ids"), list) else []:
                    if not isinstance(device, str) or not device.strip(): continue
                    session.run("MERGE (a:Account {account_id:$account}) MERGE (d:Device {device_id:$device}) MERGE (a)-[:USES_DEVICE]->(d)", account=str(account_id), device=device.strip())
        _success("neo4j")
        record_audit(_user, "lab16_graph_sync", os.getenv("LAB16_ACCOUNTS_COLLECTION", "lab10_accounts"), {"accounts_read": len(rows)})
        return {"status": "completed", "accounts_read": len(rows), "query_time_ms": round((time.perf_counter()-started)*1000,2), "relationship_source": "MongoDB account.device_ids field", "created_synthetic_relationships": False}
    except Exception as error:
        _failure("neo4j", error)
        raise HTTPException(503, "Graph sync failed; verify MongoDB and Neo4j connectivity and the account schema.") from error
