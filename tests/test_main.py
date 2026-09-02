from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_root():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "message": "AI Security Findings Triage API",
        "status": "running",
    }

def test_create_finding():
    finding = {
        "id": "API-001",
        "title": "SQL Injection",
        "description": "User input reaches a SQL query.",
        "source": "Burp Suite",
    }

    response = client.post("/findings", json=finding)

    assert response.status_code == 201

    data = response.json()

    assert data["id"] == "API-001"
    assert data["title"] == "SQL Injection"
    assert data["source"] == "Burp Suite"


def test_duplicate_finding_rejected():
    finding = {
        "id": "API-002",
        "title": "SQL Injection",
        "description": "User input reaches a SQL query.",
        "source": "Burp Suite",
    }

    first_response = client.post("/findings", json=finding)
    second_response = client.post("/findings", json=finding)

    assert first_response.status_code == 201
    assert second_response.status_code == 409

def test_get_findings():
    finding = {
        "id": "API-003",
        "title": "Broken Access Control",
        "description": "A user can access another user's resource.",
        "source": "Burp Suite",
    }

    client.post("/findings", json=finding)

    response = client.get("/findings")

    assert response.status_code == 200

    data = response.json()

    assert any(item["id"] == "API-003" for item in data)

def test_get_finding():
    finding = {
        "id": "API-004",
        "title": "Security Misconfiguration",
        "description": "Debug information is exposed.",
        "source": "Burp Suite",
    }

    client.post("/findings", json=finding)

    response = client.get("/findings/API-004")

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == "API-004"
    assert data["title"] == "Security Misconfiguration"


def test_get_missing_finding():
    response = client.get("/findings/DOES-NOT-EXIST")

    assert response.status_code == 404
    assert response.json()["detail"] == (
        "Finding with id 'DOES-NOT-EXIST' not found"
    )

def test_get_finding_report():
    finding = {
        "id": "API-005",
        "title": "SQL Injection",
        "description": "User input reaches a SQL query.",
        "source": "Burp Suite",
        "impact": 5,
        "exploitability": 5,
        "exposure": 4,
        "privilege_requirement": 1,
        "asset_criticality": 4,
        "active_exploitation": 4,
        "evidence_strength": 5,
        "reproducibility": 4,
        "detection_reliability": 4,
        "context_consistency": 4,
    }

    client.post("/findings", json=finding)

    response = client.get("/findings/API-005/report")

    assert response.status_code == 200

    data = response.json()

    assert data["finding"]["id"] == "API-005"
    assert data["finding"]["title"] == "SQL Injection"
    assert data["ai_analysis"]["status"] in ["success", "fallback"]
    assert data["markdown"]
    assert "SQL Injection" in data["markdown"]

def test_get_missing_finding_report():
    response = client.get("/findings/DOES-NOT-EXIST/report")

    assert response.status_code == 404
    assert response.json()["detail"] == (
        "Finding with id 'DOES-NOT-EXIST' not found"
    )