import pytest
from app.tools import (
    is_private_ip,
    decode_powershell_base64,
    extract_iocs,
    analyze_events,
    simulate_containment
)


def test_is_private_ip():
    assert is_private_ip("10.0.4.15") is True
    assert is_private_ip("192.168.1.100") is True
    assert is_private_ip("172.16.5.20") is True
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("198.51.100.23") is False
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("invalid-ip") is False


def test_decode_powershell_base64():
    # "Invoke-WebRequest -Uri http://example.com" in UTF-16LE
    # base64: SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAA==
    b64 = "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAA=="
    decoded = decode_powershell_base64(b64)
    assert "Invoke-WebRequest" in decoded
    assert "http://example.com" in decoded


def test_extract_iocs():
    sample_text = (
        "Host: FIN-WS-042 | SourceIp: 10.0.4.15 | DestinationIp: 198.51.100.23 | "
        "Domain: update-service-check.net | SHA256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069 | "
        "CommandLine: powershell.exe -w hidden -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0"
    )
    iocs = extract_iocs(sample_text)

    # Check IPs
    ips = iocs["ips"]
    assert len(ips) == 2
    ip_map = {item["ip"]: item["type"] for item in ips}
    assert ip_map["10.0.4.15"] == "INTERNAL"
    assert ip_map["198.51.100.23"] == "EXTERNAL"

    # Check Domains
    assert "update-service-check.net" in iocs["domains"]

    # Check Hashes
    assert "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069" in iocs["hashes"]

    # Check Commands
    assert len(iocs["suspicious_commands"]) > 0


def test_analyze_events():
    logs = (
        "[Sysmon Event 1] Host: WS-01 | User: CORP\\alice | Image: powershell.exe -enc AAAA -ep bypass\n"
        "[Sysmon Event 3] Host: WS-01 | DestinationIp: 203.0.113.5 | ThreatScore: 92\n"
        "[Sysmon Event 1] Host: WS-01 | Image: schtasks.exe /create /tn test /tr payload.ps1"
    )
    analysis = analyze_events(logs)
    assert analysis["total_events"] == 3
    assert "WS-01" in analysis["detected_hosts"]
    assert "CORP\\alice" in analysis["detected_users"]
    assert analysis["is_high_risk"] is True
    assert len(analysis["high_risk_signals"]) >= 2


def test_simulate_containment():
    actions = [
        "Isolate host FIN-WS-042 from corporate network",
        "Block outbound egress to IP 198.51.100.23 at firewall"
    ]
    result = simulate_containment("test-token-1234", "INC-TEST-001", actions)
    assert result["incident_id"] == "INC-TEST-001"
    assert result["execution_mode"] == "STRICTLY_SIMULATED"
    assert result["action_count"] == 2
    for record in result["executed_actions"]:
        assert record["status"] == "SIMULATED_SUCCESS"
        assert "SIMULATION AUDIT" in record["details"]
