"""Live monitoring, alert moderation, and isolated backup verification."""

from __future__ import annotations

import hmac
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError
from pymongo.uri_parser import parse_uri

from app.database import client as source_client, db
from app.auth import SESSIONS

router = APIRouter(tags=["Chapter 14 - Monitoring & Backup"])

METRICS = "lab14_metrics"
ALERTS = "lab14_alerts"
BACKUPS = "lab14_backups"
VERIFICATIONS = "lab14_restore_verifications"
CACHE_HIT_WARNING = 80.0
REPLICATION_LAG_WARNING_SECONDS = 10.0
SAMPLE_INTERVAL_SECONDS = max(5, int(os.getenv("LAB14_SAMPLE_INTERVAL_SECONDS", "30")))
BACKUP_INTERVAL_SECONDS = max(60, int(os.getenv("LAB14_BACKUP_INTERVAL_SECONDS", "3600")))
RPO_TARGET_SECONDS = max(1, int(os.getenv("LAB14_RPO_TARGET_SECONDS", "3600")))
RTO_TARGET_SECONDS = max(1, int(os.getenv("LAB14_RTO_TARGET_SECONDS", "900")))

_sampler_stop = threading.Event()
_sampler_thread: threading.Thread | None = None
_counter_lock = threading.Lock()
_last_counters: dict[str, int] | None = None
_last_sample_epoch: float | None = None
_last_sampler_error: str | None = None
_backup_lock = threading.Lock()


def authenticated_user(authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Sign in to access Chapter 14 operations.")
    token = authorization.split(None, 1)[1].strip()
    user = SESSIONS.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid.")
    return user


def admin_user(user: dict[str, Any] = Depends(authenticated_user)) -> dict[str, Any]:
    if user.get("role") not in {"admin", "global_admin"} and "monitoring_admin" not in user.get("permissions", []):
        raise HTTPException(status_code=403, detail="Administrator permission is required.")
    return user


def moderator_user(user: dict[str, Any] = Depends(authenticated_user)) -> dict[str, Any]:
    if user.get("role") not in {"admin", "global_admin", "threat_hunter"} and "moderate_alerts" not in user.get("permissions", []):
        raise HTTPException(status_code=403, detail="Moderator permission is required.")
    return user


def _now() -> datetime:
    return datetime.now(timezone.utc)


def cache_hit_ratio(cache_stats: dict[str, Any]) -> float | None:
    requested = cache_stats.get("pages requested from the cache")
    read = cache_stats.get("pages read into cache")
    if not isinstance(requested, (int, float)) or not isinstance(read, (int, float)) or requested <= 0:
        return None
    return round(max(0.0, min(100.0, (1 - read / requested) * 100)), 2)


def replication_lags(replica_status: dict[str, Any]) -> list[dict[str, Any]]:
    members = replica_status.get("members") or []
    primary = next((m for m in members if m.get("stateStr") == "PRIMARY"), None)
    if not primary:
        return []
    primary_time = primary.get("optimeDate")
    if not isinstance(primary_time, datetime):
        return []
    result = []
    for member in members:
        if member.get("stateStr") != "SECONDARY":
            continue
        secondary_time = member.get("optimeDate")
        if not isinstance(secondary_time, datetime):
            lag = None
        else:
            lag = round(max(0.0, (primary_time - secondary_time).total_seconds()), 3)
        result.append({"member": member.get("name", "unknown"), "lag_seconds": lag})
    return result


def _metric_alert_candidates(sample: dict[str, Any]) -> list[dict[str, Any]]:
    alerts = []
    hit_ratio = sample.get("cache_hit_ratio_percent")
    if hit_ratio is not None and hit_ratio < CACHE_HIT_WARNING:
        alerts.append({
            "metric": "cache_hit_ratio_percent",
            "actual_value": hit_ratio,
            "threshold": CACHE_HIT_WARNING,
            "member": "cluster",
            "severity": "WARNING",
        })
    for lag in sample.get("replication_lag_by_member", []):
        value = lag.get("lag_seconds")
        if value is not None and value > REPLICATION_LAG_WARNING_SECONDS:
            alerts.append({
                "metric": "replication_lag_seconds",
                "actual_value": value,
                "threshold": REPLICATION_LAG_WARNING_SECONDS,
                "member": lag.get("member", "unknown"),
                "severity": "WARNING",
            })
    return alerts


def _resolve_recovered_alerts(active_alerts: list[dict[str, Any]], sample: dict[str, Any]) -> None:
    active_keys = {f"{alert['metric']}:{alert.get('member') or 'cluster'}" for alert in active_alerts}
    for alert in db[ALERTS].find({"status": "open", "source": "monitoring"}):
        metric = alert.get("metric")
        if metric == "cache_hit_ratio_percent":
            # Do not resolve cache warnings when the cache counters were unavailable.
            if sample.get("cache_hit_ratio_percent") is None:
                continue
        if metric == "replication_lag_seconds" and not sample.get("replica_set"):
            continue
        if alert.get("dedupe_key") not in active_keys:
            db[ALERTS].update_one(
                {"alert_id": alert.get("alert_id"), "status": "open"},
                {"$set": {"status": "resolved", "resolved_at": _now()}},
            )


def ensure_indexes() -> None:
    db[METRICS].create_index([("sampled_at", DESCENDING)])
    db[ALERTS].create_index([("created_at", DESCENDING)])
    db[ALERTS].create_index(
        [("dedupe_key", ASCENDING)],
        unique=True,
        partialFilterExpression={"status": "open"},
        name="one_open_alert_per_metric_member",
    )
    db[BACKUPS].create_index([("created_at", DESCENDING)])
    db[VERIFICATIONS].create_index([("created_at", DESCENDING)])


def _jsonable(document: dict[str, Any]) -> dict[str, Any]:
    result = dict(document)
    result.pop("_id", None)
    for key, value in tuple(result.items()):
        if isinstance(value, datetime):
            normalized = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
            result[key] = normalized.isoformat()
    return result


def _record_alert(alert: dict[str, Any], source: str = "monitoring") -> dict[str, Any]:
    now = _now()
    metric = str(alert["metric"])
    member = str(alert.get("member") or "cluster")
    key = f"{metric}:{member}"
    document = {
        "alert_id": uuid.uuid4().hex,
        "dedupe_key": key,
        "metric": metric,
        "actual_value": alert["actual_value"],
        "threshold": alert["threshold"],
        "member": member,
        "severity": str(alert.get("severity", "WARNING")).upper(),
        "source": source,
        "created_at": alert.get("timestamp") or now,
        "status": "open",
        "acknowledged_at": None,
        "acknowledged_by": None,
    }
    try:
        db[ALERTS].update_one(
            {"dedupe_key": key, "status": "open"},
            {"$set": {k: v for k, v in document.items() if k not in {"alert_id", "created_at"}},
             "$setOnInsert": {"alert_id": document["alert_id"], "created_at": document["created_at"]}},
            upsert=True,
        )
    except DuplicateKeyError:
        # Another sampler/webhook stored the same open alert concurrently.
        pass
    return db[ALERTS].find_one({"dedupe_key": key, "status": "open"}) or document


def collect_metrics() -> dict[str, Any]:
    global _last_counters, _last_sample_epoch, _last_sampler_error
    sampled_at = _now()
    server_status = source_client.admin.command("serverStatus")
    try:
        replica_status = source_client.admin.command("replSetGetStatus")
        lags = replication_lags(replica_status)
        replica_set = replica_status.get("set")
    except Exception:
        # Standalone MongoDB deployments legitimately have no replication lag.
        lags = []
        replica_set = None

    counters = {name: int(value) for name, value in (server_status.get("opcounters") or {}).items() if isinstance(value, (int, float))}
    epoch = sampled_at.timestamp()
    with _counter_lock:
        if _last_counters is None or _last_sample_epoch is None or epoch <= _last_sample_epoch:
            rates = None
        else:
            elapsed = epoch - _last_sample_epoch
            rates = {name: round(max(0, value - _last_counters.get(name, value)) / elapsed, 3) for name, value in counters.items()}
        _last_counters = counters
        _last_sample_epoch = epoch

    cache = (server_status.get("wiredTiger") or {}).get("cache") or {}
    sample = {
        "sampled_at": sampled_at,
        "connected": True,
        "connections": (server_status.get("connections") or {}).get("current"),
        "operations_per_type": rates,
        "operations_per_second": round(sum(rates.values()), 3) if rates is not None else None,
        "cache_hit_ratio_percent": cache_hit_ratio(cache),
        "cache_usage_mb": round(cache.get("bytes currently in the cache", 0) / (1024 * 1024), 2) if "bytes currently in the cache" in cache else None,
        "replication_lag_by_member": lags,
        "replica_set": replica_set,
    }
    db[METRICS].insert_one(sample)
    _last_sampler_error = None
    candidates = _metric_alert_candidates(sample)
    for alert in candidates:
        _record_alert(alert)
    _resolve_recovered_alerts(candidates, sample)
    return sample


def _public_backup(record: dict[str, Any]) -> dict[str, Any]:
    safe = _jsonable(record)
    safe.pop("path", None)
    safe.pop("uri", None)
    size_bytes = record.get("size_bytes")
    safe["size_mb"] = round(size_bytes / (1024 * 1024), 3) if size_bytes is not None else None
    return safe


def _backup_configuration() -> tuple[Path | None, str | None, str | None]:
    backup_dir = os.getenv("LAB14_BACKUP_DIR")
    dump_tool = os.getenv("LAB14_MONGODUMP_PATH") or shutil.which("mongodump")
    if not backup_dir:
        return None, dump_tool, "Set LAB14_BACKUP_DIR to a dedicated writable backup directory."
    if not dump_tool:
        return Path(backup_dir), None, "MongoDB Database Tools (mongodump) are not installed or LAB14_MONGODUMP_PATH is unset."
    path = Path(backup_dir).expanduser().resolve()
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)
        probe = path / f".lab14-write-check-{uuid.uuid4().hex}"
        probe.touch(mode=0o600, exist_ok=False)
        probe.unlink()
    except OSError:
        return path, dump_tool, "LAB14_BACKUP_DIR is not writable."
    return path, dump_tool, None


def _secure_config(uri: str, directory: Path) -> Path:
    config = directory / f".lab14-tool-{uuid.uuid4().hex}.yaml"
    descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(f"uri: {json.dumps(uri)}\n")
    return config


def _run_tool(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)


def _redact_error(message: str) -> str:
    redacted = re.sub(r"mongodb(?:\+srv)?://[^\s\"']+", "[connection string redacted]", message, flags=re.IGNORECASE)
    return redacted[-1200:]


def _safe_tool_error(result: subprocess.CompletedProcess[str], tool: str) -> str:
    message = result.stderr.strip() or result.stdout.strip() or f"{tool} exited with status {result.returncode}."
    return _redact_error(message)


def execute_backup(trigger: str = "manual") -> dict[str, Any]:
    with _backup_lock:
        directory, dump_tool, error = _backup_configuration()
        if error or not directory or not dump_tool:
            raise RuntimeError(error or "Backup service is not configured.")
        database_name = os.getenv("DATABASE_NAME", "cyber_threat_intelligence")
        uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
        stamp = _now().strftime("%Y%m%dT%H%M%SZ")
        backup_id = uuid.uuid4().hex
        name = f"aegis-{database_name}-{stamp}-{backup_id[:8]}.archive.gz"
        target = directory / name
        partial = directory / f".{name}.partial"
        config = _secure_config(uri, directory)
        started = time.monotonic()
        try:
            collection_counts = {name: db[name].count_documents({}) for name in db.list_collection_names()}
            result = _run_tool(
                [dump_tool, f"--config={config}", f"--db={database_name}", f"--archive={partial}", "--gzip", "--quiet"],
                timeout=max(30, int(os.getenv("LAB14_BACKUP_TIMEOUT_SECONDS", "3600"))),
            )
            if result.returncode != 0:
                raise RuntimeError(_safe_tool_error(result, "mongodump"))
            if not partial.is_file() or partial.stat().st_size <= 0:
                raise RuntimeError("mongodump returned success without creating a non-empty archive.")
            checksum = hashlib.sha256()
            with partial.open("rb") as archive_stream:
                for chunk in iter(lambda: archive_stream.read(1024 * 1024), b""):
                    checksum.update(chunk)
            partial.replace(target)
            target.chmod(0o600)
            duration = round(time.monotonic() - started, 3)
            record = {
                "backup_id": backup_id,
                "name": name,
                "path": str(target),
                "size_bytes": target.stat().st_size,
                "sha256": checksum.hexdigest(),
                "collection_counts": collection_counts,
                "created_at": _now(),
                "duration_seconds": duration,
                "trigger": trigger,
                "status": "completed",
            }
            db[BACKUPS].insert_one(record)
            return _public_backup(record)
        except Exception as error:
            for artifact in (partial, target):
                try:
                    artifact.unlink(missing_ok=True)
                except OSError:
                    pass
            try:
                db[BACKUPS].insert_one({
                    "backup_id": backup_id,
                    "name": name,
                    "created_at": _now(),
                    "trigger": trigger,
                    "status": "failed",
                    "error": _redact_error(str(error)),
                })
            except Exception:
                pass
            raise
        finally:
            config.unlink(missing_ok=True)


def _endpoint_fingerprint(uri: str) -> tuple[str, ...]:
    parsed = parse_uri(uri, validate=True)
    if parsed.get("fqdn"):
        return ("srv:" + str(parsed["fqdn"]).lower(),)
    hosts = parsed.get("nodelist") or []
    return tuple(sorted(f"{host.lower()}:{port}" for host, port in hosts))


def execute_restore_verification(backup: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    verify_client = None
    safe_target = False
    config: Path | None = None
    result_record: dict[str, Any] | None = None
    verify_db_name = f"lab14_verify_{uuid.uuid4().hex[:16]}"
    try:
        restore_tool = os.getenv("LAB14_MONGORESTORE_PATH") or shutil.which("mongorestore")
        target_uri = os.getenv("LAB14_RESTORE_VERIFY_URI")
        if not restore_tool or not target_uri:
            raise RuntimeError("Set LAB14_RESTORE_VERIFY_URI and install mongorestore to enable isolated restore verification.")
        source_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
        try:
            source_hosts = set(_endpoint_fingerprint(source_uri))
            target_hosts = set(_endpoint_fingerprint(target_uri))
            if not target_hosts or source_hosts.intersection(target_hosts):
                raise RuntimeError("Restore target must be a separate MongoDB deployment from the source.")
        except ValueError as error:
            raise RuntimeError("Could not validate that the restore target is isolated.") from error
        safe_target = True
        archive = Path(backup.get("path", ""))
        if not archive.is_file() or archive.stat().st_size <= 0:
            raise RuntimeError("The selected backup archive is missing or empty.")
        expected_hash = backup.get("sha256")
        if expected_hash:
            checksum = hashlib.sha256()
            with archive.open("rb") as archive_stream:
                for chunk in iter(lambda: archive_stream.read(1024 * 1024), b""):
                    checksum.update(chunk)
            if not hmac.compare_digest(checksum.hexdigest(), expected_hash):
                raise RuntimeError("Backup archive checksum verification failed.")
        verify_client = MongoClient(target_uri, serverSelectionTimeoutMS=4000, connectTimeoutMS=4000)
        verify_client.admin.command("ping")
        source_db_name = os.getenv("DATABASE_NAME", "cyber_threat_intelligence")
        target_dir = Path(os.getenv("LAB14_BACKUP_DIR", str(archive.parent))).expanduser().resolve()
        config = _secure_config(target_uri, target_dir)
        result = _run_tool(
            [restore_tool, f"--config={config}", f"--archive={archive}", "--gzip",
             f"--nsFrom={source_db_name}.*", f"--nsTo={verify_db_name}.*", "--quiet"],
            timeout=max(30, int(os.getenv("LAB14_RESTORE_TIMEOUT_SECONDS", "3600"))),
        )
        if result.returncode != 0:
            raise RuntimeError(_safe_tool_error(result, "mongorestore"))
        restored_db = verify_client[verify_db_name]
        actual = {name: restored_db[name].count_documents({}) for name in restored_db.list_collection_names()}
        duration = round(time.monotonic() - started, 3)
        result_record = {
            "verification_id": uuid.uuid4().hex,
            "backup_id": backup.get("backup_id"),
            "backup_name": backup.get("name"),
            "created_at": _now(),
            "duration_seconds": duration,
            "collections_verified": len(actual),
            "documents_verified": sum(actual.values()),
            "status": "verified",
            "error": None,
        }
        return result_record
    except Exception as error:
        result_record = {
            "verification_id": uuid.uuid4().hex,
            "backup_id": backup.get("backup_id"),
            "backup_name": backup.get("name"),
            "created_at": _now(),
            "duration_seconds": round(time.monotonic() - started, 3),
            "collections_verified": 0,
            "documents_verified": 0,
            "status": "failed",
            "error": _redact_error(str(error)),
        }
        raise RuntimeError(_redact_error(str(error))) from error
    finally:
        if result_record is not None:
            db[VERIFICATIONS].insert_one(result_record)
        # Only this randomly named scratch database is removed; production is never targeted.
        if safe_target and verify_client is not None:
            try:
                verify_client.drop_database(verify_db_name)
            except Exception:
                pass
        if config:
            config.unlink(missing_ok=True)
        if verify_client is not None:
            verify_client.close()


def _latest_backup() -> dict[str, Any] | None:
    row = db[BACKUPS].find_one({"status": "completed"}, sort=[("created_at", DESCENDING)])
    if not row:
        return None
    path = Path(row.get("path", ""))
    if not path.is_file():
        return None
    try:
        actual_size = path.stat().st_size
    except OSError:
        return None
    if actual_size <= 0:
        return None
    row["size_bytes"] = actual_size
    return row


def _backup_rows(limit: int = 100) -> list[dict[str, Any]]:
    rows = []
    for row in db[BACKUPS].find({}).sort("created_at", DESCENDING).limit(limit):
        if row.get("status") != "completed":
            rows.append(_public_backup(row))
            continue
        path = Path(row.get("path", ""))
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size <= 0:
            continue
        row["size_bytes"] = size
        rows.append(_public_backup(row))
    return rows


def _current_state() -> dict[str, Any]:
    latest_sample = db[METRICS].find_one(sort=[("sampled_at", DESCENDING)])
    latest_backup = _latest_backup()
    latest_verification = db[VERIFICATIONS].find_one(sort=[("created_at", DESCENDING)])
    now = _now()
    if latest_backup:
        backup_age = max(0, int((now - latest_backup["created_at"]).total_seconds()))
    else:
        backup_age = None
    sample_payload = _jsonable(latest_sample) if latest_sample else None
    sample_age = None
    if latest_sample and isinstance(latest_sample.get("sampled_at"), datetime):
        sampled = latest_sample["sampled_at"]
        sampled = sampled.replace(tzinfo=timezone.utc) if sampled.tzinfo is None else sampled.astimezone(timezone.utc)
        sample_age = max(0, int((now - sampled).total_seconds()))
        sample_payload["stale"] = sample_age > SAMPLE_INTERVAL_SECONDS * 3
    rpo = {
        "target_seconds": RPO_TARGET_SECONDS,
        "current_seconds": backup_age,
        "within_target": bool(backup_age is not None and backup_age <= RPO_TARGET_SECONDS),
    }
    verified_seconds = latest_verification.get("duration_seconds") if latest_verification and latest_verification.get("status") == "verified" else None
    rto = {
        "target_seconds": RTO_TARGET_SECONDS,
        "last_verified_seconds": verified_seconds,
        "within_target": bool(verified_seconds is not None and verified_seconds <= RTO_TARGET_SECONDS),
    }
    latest_alerts = [_jsonable(row) for row in db[ALERTS].find({"status": "open"}).sort("created_at", DESCENDING).limit(100)]
    benchmark = None
    if latest_backup:
        duration = latest_backup.get("duration_seconds")
        size_mb = round(latest_backup["size_bytes"] / (1024 * 1024), 3)
        benchmark = {
            "backup_id": latest_backup.get("backup_id"),
            "duration_seconds": duration,
            "size_mb": size_mb,
            "throughput_mib_s": round(size_mb / duration, 3) if duration and duration > 0 else None,
        }
    backup_dir, dump_tool, backup_error = _backup_configuration()
    restore_target = os.getenv("LAB14_RESTORE_VERIFY_URI")
    restore_tool = os.getenv("LAB14_MONGORESTORE_PATH") or shutil.which("mongorestore")
    restore_error = None if restore_target and restore_tool else "Set LAB14_RESTORE_VERIFY_URI and install mongorestore to enable isolated restore verification."
    return {
        "sampled_at": sample_payload.get("sampled_at") if sample_payload else None,
        "sample_age_seconds": sample_age,
        "metrics": sample_payload,
        "monitoring_error": _last_sampler_error,
        "alerts": latest_alerts,
        "unacknowledged_alert_count": db[ALERTS].count_documents({"status": "open"}),
        "backup_history": _backup_rows(),
        "latest_backup": _public_backup(latest_backup) if latest_backup else None,
        "backup_benchmark": benchmark,
        "latest_restore_verification": _jsonable(latest_verification) if latest_verification else None,
        "rpo": rpo,
        "rto": rto,
        "backup_configuration": {
            "configured": backup_error is None,
            "error": backup_error,
            "schedule_interval_seconds": BACKUP_INTERVAL_SECONDS,
        },
        "restore_configuration": {"configured": restore_error is None, "error": restore_error},
    }


def _monitoring_loop() -> None:
    global _last_sampler_error
    next_backup = time.monotonic() + BACKUP_INTERVAL_SECONDS
    while not _sampler_stop.is_set():
        try:
            collect_metrics()
        except Exception as error:
            # Keep the live dashboard honest and make sampler failures diagnosable.
            _last_sampler_error = _redact_error(str(error))
            print(f"Chapter 14 metric collection failed: {_last_sampler_error}")
        if os.getenv("LAB14_BACKUP_ENABLED", "true").lower() in {"1", "true", "yes"} and time.monotonic() >= next_backup:
            try:
                execute_backup(trigger="hourly")
            except Exception:
                pass
            next_backup = time.monotonic() + BACKUP_INTERVAL_SECONDS
        _sampler_stop.wait(SAMPLE_INTERVAL_SECONDS)


def start_sampler() -> None:
    global _sampler_thread
    if _sampler_thread and _sampler_thread.is_alive():
        return
    _sampler_stop.clear()
    _sampler_thread = threading.Thread(target=_monitoring_loop, name="lab14-monitor", daemon=True)
    _sampler_thread.start()


def stop_sampler() -> None:
    _sampler_stop.set()
    if _sampler_thread and _sampler_thread.is_alive():
        _sampler_thread.join(timeout=2)


class WebhookAlert(BaseModel):
    metric: str = Field(min_length=1, max_length=100)
    actual_value: float
    threshold: float
    member: str = Field(default="cluster", max_length=255)
    timestamp: datetime | None = None
    severity: str = Field(default="WARNING", pattern="^(WARNING|CRITICAL)$")


@router.get("/api/services/lab14")
def get_services_lab14(_user: dict[str, Any] = Depends(admin_user)):
    global _last_sampler_error
    try:
        latest = db[METRICS].find_one(sort=[("sampled_at", DESCENDING)])
        stale = latest is None
        if latest and isinstance(latest.get("sampled_at"), datetime):
            sampled_at = latest["sampled_at"]
            sampled_at = sampled_at.replace(tzinfo=timezone.utc) if sampled_at.tzinfo is None else sampled_at.astimezone(timezone.utc)
            stale = (_now() - sampled_at).total_seconds() > SAMPLE_INTERVAL_SECONDS * 3
        if stale:
            collect_metrics()
    except Exception as error:
        _last_sampler_error = _redact_error(str(error))
    return _current_state()


@router.get("/api/ops/metrics/monitoring")
def get_monitoring_metrics(minutes: int = Query(30), _user: dict[str, Any] = Depends(admin_user)):
    if minutes not in {30, 120, 720}:
        raise HTTPException(status_code=422, detail="minutes must be one of 30, 120, or 720.")
    cutoff = _now() - timedelta(minutes=minutes)
    samples = [_jsonable(row) for row in db[METRICS].find({"sampled_at": {"$gte": cutoff}}).sort("sampled_at", ASCENDING)]
    alerts = [_jsonable(row) for row in db[ALERTS].find({"created_at": {"$gte": cutoff}}).sort("created_at", ASCENDING)]
    return {"minutes": minutes, "samples": samples, "alerts": alerts, "sample_interval_seconds": SAMPLE_INTERVAL_SECONDS}


@router.get("/api/moderation/alerts")
def get_moderation_alerts(_user: dict[str, Any] = Depends(moderator_user), status: str = Query("open", pattern="^(open|acknowledged|all)$")):
    query = {} if status == "all" else {"status": status}
    rows = [_jsonable(row) for row in db[ALERTS].find(query).sort("created_at", DESCENDING).limit(500)]
    return {"alerts": rows, "unacknowledged_count": db[ALERTS].count_documents({"status": "open"})}


@router.post("/api/moderation/alerts/ack")
def acknowledge_alert(payload: dict[str, Any], user: dict[str, Any] = Depends(moderator_user)):
    alert_id = str(payload.get("alert_id", ""))
    if not alert_id:
        raise HTTPException(status_code=422, detail="alert_id is required.")
    result = db[ALERTS].find_one_and_update(
        {"alert_id": alert_id, "status": "open"},
        {"$set": {"status": "acknowledged", "acknowledged_at": _now(), "acknowledged_by": user.get("name") or user.get("email")}},
        return_document=True,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Open alert not found; it may already be acknowledged.")
    updated = db[ALERTS].find_one({"alert_id": alert_id}) or result
    return {"alert": _jsonable(updated), "unacknowledged_count": db[ALERTS].count_documents({"status": "open"})}


@router.post("/api/webhooks/lab14/alerts", status_code=202)
def receive_alert_webhook(payload: WebhookAlert, x_lab14_webhook_token: Optional[str] = Header(default=None)):
    expected = os.getenv("LAB14_ALERT_WEBHOOK_TOKEN")
    if not expected:
        raise HTTPException(status_code=503, detail="Alert webhook is not configured.")
    if not x_lab14_webhook_token or not hmac.compare_digest(x_lab14_webhook_token, expected):
        raise HTTPException(status_code=401, detail="Invalid webhook token.")
    stored = _record_alert(payload.model_dump(exclude_none=True), source="webhook")
    return {"accepted": True, "alert_id": stored["alert_id"]}


@router.post("/api/ops/lab14/backup")
def backup_now(user: dict[str, Any] = Depends(admin_user)):
    try:
        backup = execute_backup(trigger=f"manual:{user.get('name', 'admin')}")
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except subprocess.TimeoutExpired as error:
        raise HTTPException(status_code=504, detail="mongodump timed out; no successful backup was recorded.") from error
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Backup failed: {_redact_error(str(error))}") from error
    return {"status": "completed", "backup": backup, "message": "Backup archive was created and its file size verified."}


@router.post("/api/ops/lab14/verify")
def verify_latest_backup(_user: dict[str, Any] = Depends(admin_user)):
    backup = _latest_backup()
    if not backup:
        raise HTTPException(status_code=409, detail="No existing, non-empty backup archive is available to verify.")
    try:
        verification = execute_restore_verification(backup)
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Restore verification failed: {_redact_error(str(error))}") from error
    return {"status": verification["status"], "verification": _jsonable(verification)}
