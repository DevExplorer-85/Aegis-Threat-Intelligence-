from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app import lab14_api as lab14
from app.auth import SESSIONS


class Cursor:
    def __init__(self, rows):
        self.rows = list(rows)

    def sort(self, key, direction=None):
        if isinstance(key, list):
            field, direction = key[0]
        else:
            field = key
        self.rows.sort(key=lambda row: row.get(field) or datetime.min.replace(tzinfo=timezone.utc), reverse=direction == -1)
        return self

    def limit(self, amount):
        self.rows = self.rows[:amount]
        return self

    def __iter__(self):
        return iter(self.rows)


class Collection:
    def __init__(self, rows=None, count=0):
        self.rows = list(rows or [])
        self.count = count

    def create_index(self, *_args, **_kwargs):
        return None

    def insert_one(self, document):
        self.rows.append(dict(document))
        return type("InsertResult", (), {"inserted_id": len(self.rows)})()

    def find(self, query=None):
        query = query or {}
        rows = [row for row in self.rows if _matches(row, query)]
        return Cursor(rows)

    def find_one(self, query=None, sort=None):
        rows = list(self.find(query))
        if sort:
            field, direction = sort[0]
            rows.sort(key=lambda row: row.get(field) or datetime.min.replace(tzinfo=timezone.utc), reverse=direction == -1)
        return dict(rows[0]) if rows else None

    def count_documents(self, query=None):
        if query:
            return sum(1 for row in self.rows if _matches(row, query))
        return self.count if not self.rows else len(self.rows)

    def update_one(self, query, update, upsert=False):
        found = next((row for row in self.rows if _matches(row, query)), None)
        if found:
            found.update(update.get("$set", {}))
        elif upsert:
            row = dict(update.get("$setOnInsert", {}))
            row.update(update.get("$set", {}))
            row.update(query)
            self.rows.append(row)

    def find_one_and_update(self, query, update, return_document=None):
        found = next((row for row in self.rows if _matches(row, query)), None)
        if not found:
            return None
        found.update(update.get("$set", {}))
        return dict(found)


def _matches(row, query):
    for key, value in query.items():
        actual = row.get(key)
        if isinstance(value, dict) and "$gte" in value:
            if actual is None or actual < value["$gte"]:
                return False
        elif actual != value:
            return False
    return True


class Database:
    def __init__(self, initial=None):
        self.collections = dict(initial or {})

    def __getitem__(self, name):
        return self.collections.setdefault(name, Collection())

    def list_collection_names(self):
        return [name for name, collection in self.collections.items() if name not in {lab14.BACKUPS, lab14.VERIFICATIONS} and (collection.rows or collection.count)]


class VerifyDatabase:
    def list_collection_names(self):
        return ["indicators"]

    def __getitem__(self, _name):
        return Collection(count=2)


class VerifyClient:
    dropped = []

    def __init__(self, _uri, **_kwargs):
        self.admin = type("Admin", (), {"command": lambda _self, _name: {"ok": 1}})()

    def __getitem__(self, _name):
        return VerifyDatabase()

    def drop_database(self, name):
        self.dropped.append(name)

    def close(self):
        pass


@pytest.fixture(autouse=True)
def fake_database(monkeypatch):
    db = Database({"indicators": Collection(count=2)})
    monkeypatch.setattr(lab14, "db", db)
    monkeypatch.setattr(lab14, "source_client", object())
    yield db


def make_client():
    app = FastAPI()
    app.include_router(lab14.router)
    return TestClient(app)


def test_cache_hit_ratio_and_replication_lag_calculations():
    assert lab14.cache_hit_ratio({"pages requested from the cache": 100, "pages read into cache": 12}) == 88.0
    assert lab14.cache_hit_ratio({"pages requested from the cache": 0, "pages read into cache": 0}) is None
    now = datetime.now(timezone.utc)
    status = {"members": [
        {"name": "primary:27017", "stateStr": "PRIMARY", "optimeDate": now},
        {"name": "secondary:27017", "stateStr": "SECONDARY", "optimeDate": now - timedelta(seconds=12)},
    ]}
    assert lab14.replication_lags(status) == [{"member": "secondary:27017", "lag_seconds": 12.0}]


def test_threshold_detection_only_creates_real_measurement_alerts():
    sample = {
        "cache_hit_ratio_percent": 79.9,
        "replication_lag_by_member": [{"member": "secondary:27017", "lag_seconds": 10.1}],
    }
    alerts = lab14._metric_alert_candidates(sample)
    assert [alert["metric"] for alert in alerts] == ["cache_hit_ratio_percent", "replication_lag_seconds"]
    assert lab14._metric_alert_candidates({"cache_hit_ratio_percent": None, "replication_lag_by_member": []}) == []


def test_monitoring_endpoint_returns_saved_samples_and_rejects_unsupported_window(fake_database):
    token = "test-monitor-admin"
    SESSIONS[token] = {"role": "admin", "permissions": ["monitoring_admin"]}
    now = datetime.now(timezone.utc)
    fake_database[lab14.METRICS].insert_one({"sampled_at": now, "connections": 4, "cache_hit_ratio_percent": 91.5})
    client = make_client()
    response = client.get("/api/ops/metrics/monitoring?minutes=30", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["samples"][0]["connections"] == 4
    assert client.get("/api/ops/metrics/monitoring?minutes=45", headers={"Authorization": f"Bearer {token}"}).status_code == 422
    assert client.get("/api/ops/metrics/monitoring?minutes=30").status_code == 401


def test_moderator_acknowledges_open_alert_and_permissions_are_enforced(fake_database):
    token = "test-threat-hunter"
    SESSIONS[token] = {"role": "threat_hunter", "name": "Moderator", "permissions": ["moderate_alerts"]}
    fake_database[lab14.ALERTS].insert_one({
        "alert_id": "alert-1", "metric": "cache_hit_ratio_percent", "actual_value": 70,
        "threshold": 80, "member": "cluster", "severity": "WARNING", "status": "open",
        "created_at": datetime.now(timezone.utc),
    })
    client = make_client()
    response = client.post("/api/moderation/alerts/ack", json={"alert_id": "alert-1"}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["alert"]["status"] == "acknowledged"
    assert response.json()["alert"]["acknowledged_by"] == "Moderator"
    analyst_token = "test-analyst"
    SESSIONS[analyst_token] = {"role": "soc_analyst", "permissions": []}
    assert client.get("/api/moderation/alerts", headers={"Authorization": f"Bearer {analyst_token}"}).status_code == 403
    assert client.get("/api/services/lab14", headers={"Authorization": f"Bearer {analyst_token}"}).status_code == 403


def test_backup_execution_records_actual_file_size_and_checksum(monkeypatch, tmp_path, fake_database):
    monkeypatch.setenv("LAB14_BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("LAB14_MONGODUMP_PATH", "/tools/mongodump")
    monkeypatch.setenv("MONGO_URI", "mongodb://source:27017")
    monkeypatch.setenv("DATABASE_NAME", "cti_test")

    def fake_run(command, timeout):
        assert timeout >= 30
        archive = next(Path(arg.split("=", 1)[1]) for arg in command if arg.startswith("--archive="))
        archive.write_bytes(b"actual-backup-archive")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(lab14, "_run_tool", fake_run)
    result = lab14.execute_backup("manual:test")
    record = fake_database[lab14.BACKUPS].rows[0]
    assert result["size_bytes"] == len(b"actual-backup-archive")
    assert result["size_mb"] == 0.0  # Tiny fixture rounds to 0.000 MB.
    assert record["size_bytes"] == len(b"actual-backup-archive")
    assert record["sha256"] == hashlib.sha256(b"actual-backup-archive").hexdigest()
    assert Path(record["path"]).stat().st_mode & 0o777 == 0o600


def test_restore_verification_uses_isolated_namespace_and_cleans_only_scratch(monkeypatch, tmp_path, fake_database):
    archive = tmp_path / "backup.archive.gz"
    archive.write_bytes(b"verified archive")
    monkeypatch.setenv("LAB14_BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("LAB14_MONGORESTORE_PATH", "/tools/mongorestore")
    monkeypatch.setenv("MONGO_URI", "mongodb://source:27017")
    monkeypatch.setenv("LAB14_RESTORE_VERIFY_URI", "mongodb://verify:27017")
    monkeypatch.setenv("DATABASE_NAME", "cti_test")
    monkeypatch.setattr(lab14, "MongoClient", VerifyClient)
    VerifyClient.dropped.clear()
    captured = {}

    def fake_run(command, timeout):
        assert timeout >= 30
        captured["command"] = command
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(lab14, "_run_tool", fake_run)
    backup = {
        "backup_id": "backup-1", "name": archive.name, "path": str(archive),
        "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "collection_counts": {"indicators": 2},
    }
    result = lab14.execute_restore_verification(backup)
    assert result["status"] == "verified"
    assert result["collections_verified"] == 1
    assert result["documents_verified"] == 2
    assert any(arg.startswith("--nsTo=lab14_verify_") for arg in captured["command"])
    assert "--drop" not in captured["command"]
    assert VerifyClient.dropped and VerifyClient.dropped[0].startswith("lab14_verify_")
    assert fake_database[lab14.VERIFICATIONS].rows[0]["status"] == "verified"


def test_restore_verification_refuses_source_deployment(monkeypatch, tmp_path):
    archive = tmp_path / "backup.archive.gz"
    archive.write_bytes(b"some bytes")
    monkeypatch.setenv("LAB14_MONGORESTORE_PATH", "/tools/mongorestore")
    monkeypatch.setenv("MONGO_URI", "mongodb://same:27017")
    monkeypatch.setenv("LAB14_RESTORE_VERIFY_URI", "mongodb://same:27017")
    with pytest.raises(RuntimeError, match="separate MongoDB deployment"):
        lab14.execute_restore_verification({"path": str(archive), "name": archive.name})


def test_rpo_and_rto_are_reported_as_measured_or_unknown(monkeypatch, tmp_path, fake_database):
    backup_file = tmp_path / "real.archive.gz"
    backup_file.write_bytes(b"backup")
    now = datetime.now(timezone.utc)
    fake_database[lab14.BACKUPS].insert_one({"backup_id": "b1", "name": backup_file.name, "path": str(backup_file), "size_bytes": 6, "created_at": now - timedelta(minutes=2), "duration_seconds": 4, "status": "completed"})
    fake_database[lab14.VERIFICATIONS].insert_one({"status": "verified", "created_at": now - timedelta(minutes=1), "duration_seconds": 90, "collections_verified": 3, "documents_verified": 14})
    monkeypatch.setenv("LAB14_BACKUP_DIR", str(tmp_path))
    state = lab14._current_state()
    assert state["rpo"]["current_seconds"] >= 119
    assert state["rpo"]["within_target"] is True
    assert state["rto"]["last_verified_seconds"] == 90
    assert state["rto"]["within_target"] is True


def test_backup_without_configuration_never_creates_a_success_record(monkeypatch, fake_database):
    monkeypatch.delenv("LAB14_BACKUP_DIR", raising=False)
    with pytest.raises(RuntimeError, match="LAB14_BACKUP_DIR"):
        lab14.execute_backup()
    assert fake_database[lab14.BACKUPS].rows == []


def test_successful_tool_without_archive_is_recorded_as_failed(monkeypatch, tmp_path, fake_database):
    monkeypatch.setenv("LAB14_BACKUP_DIR", str(tmp_path))
    monkeypatch.setenv("LAB14_MONGODUMP_PATH", "/tools/mongodump")
    monkeypatch.setattr(lab14, "_run_tool", lambda command, timeout: subprocess.CompletedProcess(command, 0, "", ""))
    with pytest.raises(RuntimeError, match="without creating"):
        lab14.execute_backup()
    rows = fake_database[lab14.BACKUPS].rows
    assert len(rows) == 1 and rows[0]["status"] == "failed"
    assert lab14._latest_backup() is None


def test_alert_webhook_requires_configured_token_and_is_visible_to_moderators(monkeypatch, fake_database):
    token = "test-webhook-token"
    monkeypatch.setenv("LAB14_ALERT_WEBHOOK_TOKEN", token)
    admin_token = "test-webhook-admin"
    SESSIONS[admin_token] = {"role": "admin", "name": "Admin", "permissions": ["moderate_alerts"]}
    client = make_client()
    payload = {"metric": "replication_lag_seconds", "actual_value": 11.2, "threshold": 10, "member": "mongo2:27017", "severity": "WARNING"}
    assert client.post("/api/webhooks/lab14/alerts", json=payload).status_code == 401
    response = client.post("/api/webhooks/lab14/alerts", json=payload, headers={"X-Lab14-Webhook-Token": token})
    assert response.status_code == 202
    visible = client.get("/api/moderation/alerts", headers={"Authorization": f"Bearer {admin_token}"})
    assert visible.status_code == 200
    assert visible.json()["alerts"][0]["source"] == "webhook"
    assert visible.json()["alerts"][0]["actual_value"] == 11.2


def test_frontend_exposes_operations_tables_buttons_and_chart_containers():
    root = Path(__file__).resolve().parents[2]
    html = (root / "frontend" / "lab14.html").read_text(encoding="utf-8")
    script = (root / "frontend" / "lab14.js").read_text(encoding="utf-8")
    assert 'id="metricsTable"' in html and 'id="alertsTable"' in html and 'id="backupsTable"' in html
    assert 'id="backupNowButton"' in html and 'id="verifyRestoreButton"' in html
    assert all(f'id="{chart}"' in html for chart in ("cacheChart", "replicationChart", "operationsChart", "connectionsChart", "backupChart"))
    assert "/api/ops/lab14/backup" in script and "/api/ops/lab14/verify" in script
    assert "/api/moderation/alerts/ack" in script


def test_workspace_alias_routes_and_admin_service_api(fake_database, monkeypatch):
    from app.main import app

    token = "test-workspace-admin"
    SESSIONS[token] = {"role": "admin", "name": "Admin", "permissions": ["monitoring_admin"]}
    monkeypatch.setattr(lab14, "_current_state", lambda: {"metrics": None, "alerts": [], "backup_history": [], "rpo": {}, "rto": {}})
    client = TestClient(app)
    for path in ("/extras/lab14", "/admin/ops?tab=backups", "/admin/ops?tab=monitoring", "/moderation?tab=alerts"):
        response = client.get(path)
        assert response.status_code == 200
        assert "Chapter 14" in response.text
    assert client.get("/api/services/lab14").status_code == 401
    response = client.get("/api/services/lab14", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
