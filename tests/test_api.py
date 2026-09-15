import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "llm_mode" in data
    assert data["playbooks_loaded"] >= 4


def test_serve_index():
    response = client.get("/")
    assert response.status_code == 200
    assert "AGENTIC SOC COPILOT" in response.text


def test_incident_analyze_and_approval_workflow():
    payload = {
        "incident_id": "INC-TEST-9999",
        "title": "Suspicious Obfuscated PowerShell Downloader",
        "raw_logs": (
            "[2026-09-15T10:00:00Z] Host: FIN-WS-042 | User: CORP\\jdoe | "
            "CommandLine: powershell.exe -w hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0 | "
            "DestinationIp: 198.51.100.23 | Domain: update-service-check.net | "
            "CommandLine: schtasks.exe /create /tn MaliciousTask /tr payload.ps1"
        )
    }

    # 1. Analyze incident
    analyze_resp = client.post("/incidents/analyze", json=payload)
    assert analyze_resp.status_code == 200
    analysis = analyze_resp.json()

    assert analysis["incident_id"] == "INC-TEST-9999"
    assert analysis["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert "extracted_iocs" in analysis
    assert len(analysis["extracted_iocs"]["ips"]) > 0
    assert len(analysis["retrieved_playbooks"]) > 0
    assert len(analysis["response_plan"]) > 0
    assert analysis["approval_status"] == "PENDING"
    assert len(analysis["execution_trace"]) == 4

    approval_token = analysis["approval_token"]
    assert approval_token.startswith("tok-")

    # 2. Check recent incidents
    recent_resp = client.get("/incidents/recent")
    assert recent_resp.status_code == 200
    recent_list = recent_resp.json()
    assert any(item["incident_id"] == "INC-TEST-9999" for item in recent_list)

    # 3. Approve containment
    approve_resp = client.post(f"/incidents/approve/{approval_token}")
    assert approve_resp.status_code == 200
    approval_data = approve_resp.json()
    assert approval_data["status"] == "APPROVED"
    assert approval_data["approval_token"] == approval_token
    assert len(approval_data["executed_actions"]) > 0

    # 4. Re-approving should return ALREADY_APPROVED
    reapprove_resp = client.post(f"/incidents/approve/{approval_token}")
    assert reapprove_resp.status_code == 200
    assert reapprove_resp.json()["status"] == "ALREADY_APPROVED"


def test_approve_invalid_token():
    response = client.post("/incidents/approve/tok-invalid-nonexistent")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()
