"""Tests for FastAPI REST Endpoints."""

import pytest
from fastapi.testclient import TestClient
from ai_ids.api.server import app


@pytest.fixture
def client():
    return TestClient(app)


def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "OPERATIONAL"
    assert data["safety_boundary"]["strict_ids_mode"] is True
    assert data["safety_boundary"]["automated_prevention_enabled"] is False


def test_capture_status_endpoint(client):
    response = client.get("/status/capture")
    assert response.status_code == 200
    data = response.json()
    assert "is_available" in data
    assert "platform" in data


def test_alerts_stats_endpoint(client):
    response = client.get("/alerts/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_alerts" in data
    assert "by_severity" in data
