import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_services_lab13_endpoint():
    response = client.get("/api/services/lab13")
    assert response.status_code == 200
    data = response.json()
    assert "replica_set" in data
    assert "last_failover" in data
    assert "monitoring" in data
    assert "kubernetes" in data
    assert "atlas" in data
    assert data["replica_set"]["connected"] is True
    assert data["atlas"]["terraform_ready"] is True

def test_deployment_metrics_endpoint():
    response = client.get("/api/ops/metrics/deployment?minutes=15")
    assert response.status_code == 200
    data = response.json()
    assert data["minutes"] == 15
    assert "operations_by_type" in data
    assert len(data["operations_by_type"]) > 0
    assert "connections" in data
    assert "cache_usage_mib" in data

def test_failover_requires_confirmation():
    response = client.post("/api/services/lab13/failover", json={})
    assert response.status_code == 400
    assert "confirmation is required" in response.json()["detail"].lower()

def test_failover_success_with_confirmation():
    response = client.post("/api/services/lab13/failover", json={"confirm": True})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "record" in data
    assert data["record"]["failed_reads"] == 0

def test_lab13_frontend_routes():
    res1 = client.get("/extras/lab13")
    assert res1.status_code == 200
    assert "Chapter 13: Containers & Cloud Operations" in res1.text

    res2 = client.get("/admin/ops?tab=deployment")
    assert res2.status_code == 200
    assert "Chapter 13: Containers & Cloud Operations" in res2.text
