from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import lab17_api as lab17
from app.auth import SESSIONS


class Cursor:
    def __init__(self, rows): self.rows = list(rows)
    def sort(self, key, direction=-1): self.rows.sort(key=lambda x: x.get(key) or datetime.min.replace(tzinfo=timezone.utc), reverse=direction == -1); return self
    def limit(self, number): self.rows = self.rows[:number]; return self
    def __iter__(self): return iter(self.rows)


class Collection:
    def __init__(self, rows=None): self.rows = [dict(x) for x in (rows or [])]
    def create_index(self, *args, **kwargs): return "idx"
    def find(self, query=None, projection=None):
        query = query or {}
        return Cursor([dict(row) for row in self.rows if all(row.get(k) == v for k, v in query.items())])
    def find_one(self, query, projection=None):
        return next((dict(row) for row in self.rows if all(row.get(k) == v for k, v in query.items())), None)
    def insert_one(self, row): self.rows.append(dict(row)); return type("Result", (), {"inserted_id": len(self.rows)})()
    def replace_one(self, query, row, upsert=False):
        current = next((item for item in self.rows if all(item.get(k) == v for k, v in query.items())), None)
        if current is not None: current.clear(); current.update(row)
        elif upsert: self.rows.append(dict(row))
    def count_documents(self, query): return sum(all(row.get(k) == v for k, v in query.items()) for row in self.rows)
    def distinct(self, field): return list({row.get(field) for row in self.rows if row.get(field) is not None})
    def delete_many(self, query):
        before = len(self.rows); self.rows = [row for row in self.rows if not all(row.get(k) == v for k, v in query.items())]
        return type("Result", (), {"deleted_count": before - len(self.rows)})()


class Database:
    def __init__(self): self.collections = {}
    def __getitem__(self, name): return self.collections.setdefault(name, Collection())
    def command(self, *args, **kwargs): raise RuntimeError("Atlas Search unavailable in unit test")


@pytest.fixture
def app_client(monkeypatch):
    database = Database()
    database["security_reports"].rows = [{"report_id": "r1", "title": "Credential theft report", "content": "The actor used credential phishing to obtain access. The report describes credential theft and persistence."}]
    monkeypatch.setattr(lab17, "db", database)
    monkeypatch.setattr(lab17, "_vector_index_status", lambda: {"available": False, "status": "not_created", "name": "ask_vector_index", "detail": "not Atlas"})
    monkeypatch.setattr(lab17, "_embedding_config", lambda: ("https://test.invalid/embeddings", "test-key", "test-embedding"))
    monkeypatch.setattr(lab17, "_llm_config", lambda: ("https://test.invalid/chat", "", "test-llm"))
    SESSIONS.clear()
    SESSIONS.update({"admin": {"id": "admin-1", "role": "admin", "permissions": ["all"]}, "user-a": {"id": "user-a", "role": "soc_analyst", "permissions": []}, "user-b": {"id": "user-b", "role": "soc_analyst", "permissions": []}})
    app = FastAPI(); app.include_router(lab17.router)
    lab17._job_state = {"status": "idle", "completed": 0, "total": 0, "failures": [], "started_at": None, "finished_at": None}
    with TestClient(app) as client: yield client, database
    SESSIONS.clear()


def headers(token): return {"Authorization": f"Bearer {token}"}


def test_chunking_overlap_and_cosine_dimension_validation():
    chunks = lab17._split_text(" ".join(f"w{i}" for i in range(1900)), target=900, overlap=120)
    assert len(chunks) == 3
    assert len(chunks[0].split()) == 900
    assert lab17._cosine([1, 0], [1, 0]) == pytest.approx(1)
    with pytest.raises(ValueError): lab17._cosine([1], [1, 2])


def test_embedding_batch_parsing_validates_dimensions(monkeypatch):
    monkeypatch.setattr(lab17, "_embedding_config", lambda: ("https://test.invalid/embeddings", "key", "model"))
    monkeypatch.setattr(lab17, "_post_json", lambda *args: {"data": [{"index": 1, "embedding": [0, 1]}, {"index": 0, "embedding": [1, 0]}]})
    assert lab17._embed_many(["first", "second"]) == [[1.0, 0.0], [0.0, 1.0]]
    monkeypatch.setattr(lab17, "_post_json", lambda *args: {"data": [{"embedding": [1]}, {"embedding": [1, 2]}]})
    with pytest.raises(RuntimeError, match="mixed vector dimensions"):
        lab17._embed_many(["first", "second"])


def test_admin_gate_and_index_operation(app_client, monkeypatch):
    client, database = app_client
    assert client.get("/api/ops/ask-index", headers=headers("user-a")).status_code == 403
    monkeypatch.setattr(lab17, "_embed_many", lambda texts: [[1.0, 0.0, 0.0] for _ in texts])
    lab17._run_index()
    stored = database[lab17.CHUNKS].rows
    assert stored and all(row["dimensions"] == 3 and row["embedding_model"] == "test-embedding" for row in stored)
    status = client.get("/api/ops/ask-index", headers=headers("admin")).json()
    assert status["indexed_chunks"] == len(stored)
    assert status["reports_indexed"] == 1


def test_ask_returns_extractively_cited_evidence_and_scoped_history(app_client, monkeypatch):
    client, _ = app_client
    monkeypatch.setattr(lab17, "_embed_many", lambda texts: [[1.0, 0.0, 0.0] for _ in texts])
    lab17._run_index()
    response = client.post("/api/ask", headers=headers("user-a"), json={"question": "How did the actor gain access?"})
    assert response.status_code == 200
    answer = response.json()
    assert answer["mode"] == "extractive"
    assert "without an LLM" in answer["answer"]
    assert answer["sources"][0]["report_title"] == "Credential theft report"
    assert answer["sources"][0]["page_number"] == 1
    assert client.get("/api/ask/history", headers=headers("user-a")).json()["items"][0]["question"] == "How did the actor gain access?"
    assert client.get("/api/ask/history", headers=headers("user-b")).json()["items"] == []
    assert client.delete("/api/ask/history", headers=headers("user-b")).json()["deleted"] == 0
    assert len(client.get("/api/ask/history", headers=headers("user-a")).json()["items"]) == 1


def test_embedding_model_mismatch_is_rejected(app_client, monkeypatch):
    client, database = app_client
    database[lab17.CHUNKS].insert_one({"_id": "old", "embedding": [1, 0], "embedding_model": "other", "dimensions": 2})
    monkeypatch.setattr(lab17, "_embed", lambda text: [1.0, 0.0, 0.0])
    assert client.post("/api/ask", headers=headers("user-a"), json={"question": "test evidence?"}).status_code == 409


def test_history_requires_authentication(app_client):
    client, _ = app_client
    assert client.get("/api/ask/history").status_code == 401
    assert client.delete("/api/ask/history").status_code == 401


def test_duplicate_index_job_is_rejected(app_client):
    client, _ = app_client
    lab17._job_state["status"] = "running"
    response = client.post("/api/ops/ask-index", headers=headers("admin"))
    assert response.status_code == 409


def test_benchmark_reports_measured_exact_and_ivf_and_marks_mongodb_ivf_unsupported(app_client):
    client, database = app_client
    database[lab17.CHUNKS].rows = [
        {"_id": "a", "report_id": "r1", "embedding": [1.0, 0.0], "embedding_model": "test", "dimensions": 2},
        {"_id": "b", "report_id": "r1", "embedding": [0.0, 1.0], "embedding_model": "test", "dimensions": 2},
    ]
    response = client.post("/api/ops/ask-benchmark", headers=headers("admin"))
    assert response.status_code == 200
    methods = {method["name"]: method for method in response.json()["methods"]}
    assert methods["In-memory exact cosine"]["latency_ms"] >= 0
    assert methods["In-memory IVF coarse centroids"]["supported"] is True
    assert methods["MongoDB IVF"]["supported"] is False


def test_llm_answer_uses_citation_context_and_reports_model(app_client, monkeypatch):
    monkeypatch.setattr(lab17, "_llm_config", lambda: ("https://test.invalid/chat", "key", "test-chat"))
    monkeypatch.setattr(lab17, "_post_json", lambda endpoint, body, key: {"choices": [{"message": {"content": "The report documents phishing [1]."}}]})
    answer, mode, model = lab17._generate("How did access occur?", [{"report_title": "Report A", "page_number": 4, "text": "Phishing granted access.", "relevance_score": 0.9}])
    assert (mode, model) == ("llm", "test-chat")
    assert "[1]" in answer
