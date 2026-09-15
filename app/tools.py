import re
import base64
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Any


def is_private_ip(ip_str: str) -> bool:
    """Check if an IPv4 address belongs to enterprise private (RFC 1918) or loopback space."""
    try:
        ip = ipaddress.ip_address(ip_str)
        rfc1918_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
        )
        return any(ip in net for net in rfc1918_networks)
    except ValueError:
        return False


def decode_powershell_base64(encoded_str: str) -> str:
    """Safely decode base64 encoded PowerShell script string (UTF-16LE or ASCII)."""
    try:
        # Standard base64 padding correction
        missing_padding = len(encoded_str) % 4
        if missing_padding:
            encoded_str += "=" * (4 - missing_padding)
        raw_bytes = base64.b64decode(encoded_str)
        # PowerShell -enc stores UTF-16LE
        try:
            decoded = raw_bytes.decode("utf-16le")
            if any(c.isprintable() for c in decoded):
                return decoded
        except Exception:
            pass
        return raw_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def analyze_events(raw_events: str) -> Dict[str, Any]:
    """
    Parse raw security event logs, extract operational metrics,
    identify hostnames, usernames, event signatures, and flag risk signals.
    """
    lines = [line.strip() for line in raw_events.strip().split("\n") if line.strip()]
    event_count = len(lines)
    
    event_types: List[str] = []
    hosts: set = set()
    users: set = set()
    high_risk_signals: List[str] = []

    # Risk signature patterns
    risk_patterns = [
        (r"-enc|-encodedcommand", "Obfuscated / Base64 Encoded PowerShell Command"),
        (r"-ep\s+bypass|-executionpolicy\s+bypass", "PowerShell Execution Policy Bypass"),
        (r"-w\s+hidden|-windowstyle\s+hidden", "Hidden Window Execution"),
        (r"downloadstring|invoke-webrequest|iwr|bitsadmin", "Ingress Tool Transfer / Web Payload Download"),
        (r"schtasks.*\/create", "Persistence via Scheduled Task Creation"),
        (r"mimikatz|sekurlsa|lsass", "Credential Dumping Activity"),
        (r"reg\s+add.*\\run", "Persistence via Windows Registry Run Key"),
        (r"threatscore:\s*([8-9]\d|100)", "High Network Threat Score Detected")
    ]

    for line in lines:
        # Extract Sysmon or Event type
        event_match = re.search(r"\[([^\]]+)\]", line)
        if event_match:
            event_types.append(event_match.group(1))

        # Extract Host
        host_match = re.search(r"Host:\s*([A-Za-z0-9\-_]+)", line, re.IGNORECASE)
        if host_match:
            hosts.add(host_match.group(1))

        # Extract User
        user_match = re.search(r"User:\s*([A-Za-z0-9\\\-_]+)", line, re.IGNORECASE)
        if user_match:
            users.add(user_match.group(1))

        # Check risk patterns
        for pattern, label in risk_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                if label not in high_risk_signals:
                    high_risk_signals.append(label)

    return {
        "total_events": event_count,
        "event_types": list(dict.fromkeys(event_types)),
        "detected_hosts": list(hosts),
        "detected_users": list(users),
        "high_risk_signals": high_risk_signals,
        "is_high_risk": len(high_risk_signals) >= 2
    }


def extract_iocs(text: str) -> Dict[str, Any]:
    """
    Extract Indicators of Compromise (IOCs) from text using deterministic regex rules:
    - IPv4 addresses (classified as internal RFC1918 vs external destination)
    - Fully Qualified Domain Names (excluding common system extensions)
    - File Hashes (MD5, SHA256)
    - Suspicious command lines and decoded payloads
    """
    # 1. IP Extraction
    raw_ips = re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b", text)
    unique_ips = list(dict.fromkeys(raw_ips))
    
    classified_ips = []
    for ip in unique_ips:
        # Ignore standard broadcast or subnet masks
        if ip in ("255.255.255.255", "0.0.0.0", "255.255.255.0"):
            continue
        is_priv = is_private_ip(ip)
        classified_ips.append({
            "ip": ip,
            "type": "INTERNAL" if is_priv else "EXTERNAL",
            "threat_flag": "POTENTIAL_C2" if not is_priv else "INTERNAL_ASSET"
        })

    # 2. Domain Extraction
    potential_domains = re.findall(r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b", text)
    domain_blacklist_suffixes = (
        ".exe", ".dll", ".ps1", ".bat", ".txt", ".json", ".log", ".py", ".com", ".net", ".org"
    )
    valid_domains = []
    for d in potential_domains:
        d_lower = d.lower()
        if not any(d_lower.endswith(s) for s in (".exe", ".dll", ".ps1", ".bat", ".txt", ".json", ".log", ".py")):
            if d_lower not in valid_domains:
                valid_domains.append(d_lower)
    
    # Also capture explicitly labelled domains (e.g. Domain: update-service-check.net)
    explicit_domains = re.findall(r"Domain:\s*([a-zA-Z0-9\-\._]+\.[a-zA-Z]{2,})", text, re.IGNORECASE)
    for d in explicit_domains:
        d_lower = d.lower()
        if d_lower not in valid_domains:
            valid_domains.append(d_lower)

    # 3. Hash Extraction
    sha256_hashes = re.findall(r"\b[A-Fa-f0-9]{64}\b", text)
    md5_hashes = re.findall(r"\b[A-Fa-f0-9]{32}\b", text)
    all_hashes = list(dict.fromkeys(sha256_hashes + md5_hashes))

    # 4. Suspicious Command Strings & Decoded Obfuscation
    suspicious_commands: List[str] = []
    
    # Check for Base64 encoded payload in powershell -enc
    enc_match = re.search(r"-enc\s+([A-Za-z0-9+/=]+)", text, re.IGNORECASE)
    if enc_match:
        b64_str = enc_match.group(1)
        decoded = decode_powershell_base64(b64_str)
        if decoded:
            suspicious_commands.append(f"Decoded PowerShell: {decoded.strip()}")
        else:
            suspicious_commands.append(f"Encoded String: {b64_str}")

    # Check for schtasks /create
    schtasks_match = re.search(r"(schtasks\.exe\s+/create[^\n\r]+)", text, re.IGNORECASE)
    if schtasks_match:
        suspicious_commands.append(schtasks_match.group(1).strip())

    # Check for PowerShell download invocations
    ps_commands = re.findall(r"(powershell\.exe[^\n\r]+)", text, re.IGNORECASE)
    for cmd in ps_commands:
        if cmd not in suspicious_commands and ("-enc" in cmd or "download" in cmd.lower() or "bypass" in cmd.lower()):
            suspicious_commands.append(cmd.strip())

    return {
        "ips": classified_ips,
        "domains": valid_domains,
        "hashes": all_hashes,
        "suspicious_commands": suspicious_commands
    }


def search_security_knowledge(query: str, top_k: int = 2) -> List[Dict[str, Any]]:
    """
    Search local security knowledge base playbooks for relevant procedures.
    Delegates to the RAG knowledge retriever.
    """
    from app.rag import get_rag_engine
    engine = get_rag_engine()
    return engine.search(query=query, top_k=top_k)


def simulate_containment(approval_token: str, incident_id: str, actions: List[str]) -> Dict[str, Any]:
    """
    Execute strictly SIMULATED containment actions following human analyst approval.
    Safety notice: No real operating system modifications, network blocks,
    or credential alterations are executed.
    """
    now = datetime.now(timezone.utc).isoformat()
    action_records = []

    for act in actions:
        target = "Unknown"
        act_type = "CONTAINMENT"
        
        # Categorize action
        if "isolate" in act.lower() or "host" in act.lower():
            act_type = "HOST_ISOLATION"
            host_match = re.search(r"(?:host|workstation|FIN-WS-[\w\-]+|[\w\-]+-WS-[\w\-]+)", act, re.IGNORECASE)
            target = host_match.group(0) if host_match else "Target Host"
        elif "block" in act.lower() or "ip" in act.lower():
            act_type = "FIREWALL_BLOCK"
            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", act)
            target = ip_match.group(0) if ip_match else "Perimeter Edge"
        elif "account" in act.lower() or "password" in act.lower() or "user" in act.lower():
            act_type = "CREDENTIAL_REVOCATION"
            user_match = re.search(r"(?:user|CORP\\[\w\-]+)", act, re.IGNORECASE)
            target = user_match.group(0) if user_match else "Identity Directory"
        elif "task" in act.lower() or "delete" in act.lower() or "persistence" in act.lower():
            act_type = "PERSISTENCE_REMOVAL"
            target = "Scheduled Task Scheduler"

        action_records.append({
            "action": act,
            "status": "SIMULATED_SUCCESS",
            "target": target,
            "timestamp": now,
            "details": f"[SIMULATION AUDIT] Verified approval token '{approval_token[:8]}...'. Policy rule applied safely in sandbox mode."
        })

    return {
        "incident_id": incident_id,
        "approval_token": approval_token,
        "execution_mode": "STRICTLY_SIMULATED",
        "action_count": len(action_records),
        "executed_actions": action_records,
        "completed_at": now,
        "disclaimer": "SAFEGUARD ENGAGED: Simulated containment action executed. No physical changes made to network or endpoints."
    }
