import os
import json
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()


def is_openai_available() -> bool:
    """Check if a valid, non-placeholder OpenAI API key is configured."""
    return bool(OPENAI_API_KEY and not OPENAI_API_KEY.startswith("your_") and len(OPENAI_API_KEY) > 10)


def get_llm_mode() -> str:
    """Return the active LLM execution mode."""
    return "OPENAI_LIVE" if is_openai_available() else "DETERMINISTIC_FALLBACK"


class DeterministicSecurityEngine:
    """
    High-fidelity, deterministic cybersecurity reasoning engine used when
    an OpenAI API key is not provided or when running offline/in interview demo mode.
    """

    @staticmethod
    def generate_triage(title: str, raw_logs: str, event_metrics: Dict[str, Any]) -> Dict[str, str]:
        logs_lower = raw_logs.lower()
        title_lower = title.lower()

        # Assess Severity
        if ("-enc" in logs_lower or "encodedcommand" in logs_lower) and ("schtasks" in logs_lower or "run" in logs_lower):
            severity = "CRITICAL"
            category = "Execution & Persistence (MITRE T1059.001 / T1053)"
            rationale = (
                "Critical threat detected: Host exhibits in-memory obfuscated PowerShell execution "
                "coupled with an unauthorized outbound network connection and automated scheduled task persistence. "
                "Immediate containment required to prevent lateral propagation."
            )
        elif "powershell" in logs_lower and ("downloadstring" in logs_lower or "invoke-webrequest" in logs_lower):
            severity = "HIGH"
            category = "Defense Evasion & Ingress Tool Transfer (MITRE T1105)"
            rationale = (
                "High severity: Detected unauthorized script block attempting remote payload download "
                "bypassing execution policies."
            )
        elif "failed" in logs_lower or "login" in logs_lower or "4625" in logs_lower:
            severity = "MEDIUM"
            category = "Credential Access / Brute Force (MITRE T1110)"
            rationale = (
                "Medium severity: Anomalous authentication pattern detected. Multiple failed logon attempts "
                "observed targeting domain account."
            )
        else:
            severity = "LOW"
            category = "Discovery / Policy Anomaly (MITRE T1087)"
            rationale = (
                "Low severity: Non-destructive administrative event or informational telemetry requiring "
                "standard verification."
            )

        return {
            "severity": severity,
            "attack_category": category,
            "triage_summary": rationale
        }

    @staticmethod
    def generate_investigation(
        title: str,
        raw_logs: str,
        iocs: Dict[str, Any],
        playbooks: List[Dict[str, Any]]
    ) -> str:
        findings = []
        findings.append(f"### Threat Investigation Narrative for: {title}")
        
        # Correlate IOCs
        ext_ips = [item["ip"] for item in iocs.get("ips", []) if item.get("type") == "EXTERNAL"]
        int_ips = [item["ip"] for item in iocs.get("ips", []) if item.get("type") == "INTERNAL"]
        domains = iocs.get("domains", [])
        hashes = iocs.get("hashes", [])
        suspicious_cmds = iocs.get("suspicious_commands", [])

        if int_ips:
            findings.append(f"- **Compromised Internal Endpoint(s)**: {', '.join(int_ips)}")
        if ext_ips:
            findings.append(f"- **External Command & Control (C2) Infrastructure**: Identified untrusted external IP `{', '.join(ext_ips)}` over non-standard port.")
        if domains:
            findings.append(f"- **Suspicious Domain Resolution**: Contacted `{', '.join(domains)}` during execution chain.")
        if hashes:
            findings.append(f"- **Extracted Binary / Payload Hashes**: `{', '.join(hashes)}`")

        if suspicious_cmds:
            findings.append("- **Suspicious Command Invocations**:")
            for cmd in suspicious_cmds:
                findings.append(f"  * `{cmd}`")

        # Grounding from playbooks
        if playbooks:
            top_pb = playbooks[0]
            findings.append(f"- **Playbook Grounding**: Correlated with `{top_pb.get('title')}` (Score: {top_pb.get('score')}). Matches behavioral indicators for living-off-the-land malware staging.")

        findings.append(
            "- **Analyst Conclusion**: The timeline indicates initial execution via an interactive explorer session, "
            "triggering an obfuscated PowerShell dropper, egress staging, and persistence installation. "
            "Host isolation and perimeter firewall block are urgently advised."
        )

        return "\n".join(findings)

    @staticmethod
    def generate_response_plan(
        severity: str,
        iocs: Dict[str, Any],
        playbooks: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        ext_ips = [item["ip"] for item in iocs.get("ips", []) if item.get("type") == "EXTERNAL"]
        int_ips = [item["ip"] for item in iocs.get("ips", []) if item.get("type") == "INTERNAL"]

        # Formulate actionable response recommendations
        plan_steps = [
            "1. [Immediate Containment] Isolate the affected workstation from the corporate network via EDR agent.",
            f"2. [Perimeter Defense] Block outbound egress to external destination IP(s): {', '.join(ext_ips) if ext_ips else 'Identified C2 IPs'} at perimeter firewalls.",
            "3. [Process Termination] Terminate all active powershell.exe and spawned child processes on the endpoint.",
            "4. [Persistence Removal] Delete rogue scheduled tasks and inspect registry Run/RunOnce keys.",
            "5. [Identity Remediation] Force session revocation and password reset for associated user accounts in Active Directory.",
            "6. [Forensic Collection] Collect memory dump and MFT triage image for root cause analysis."
        ]

        # Discrete simulated containment actions requiring human confirmation
        simulated_actions = [
            f"Isolate host network connectivity (EDR Host Isolation) for internal asset {int_ips[0] if int_ips else 'FIN-WS-042'}",
            f"Deploy perimeter firewall egress drop rule for C2 IP {ext_ips[0] if ext_ips else '198.51.100.23'}",
            "Revoke Active Directory Kerberos tickets and disable user account CORP\\jdoe",
            "Delete persistence scheduled task 'SystemUpdateChecker'"
        ]

        return {
            "response_plan": plan_steps,
            "simulated_actions": simulated_actions
        }


def call_llm_triage(title: str, raw_logs: str, event_metrics: Dict[str, Any]) -> Dict[str, str]:
    """Execute triage analysis via OpenAI or fallback engine."""
    if is_openai_available():
        try:
            from langchain_openai import ChatOpenAI
            from langchain_core.prompts import PromptTemplate
            from langchain_core.output_parsers import JsonOutputParser

            llm = ChatOpenAI(model=OPENAI_MODEL, temperature=0.1, openai_api_key=OPENAI_API_KEY)
            prompt = PromptTemplate(
                template="""You are an expert Security Operations Center (SOC) Triage Agent.
Analyze the following security incident and return JSON with keys:
- "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
- "attack_category": Short MITRE ATT&CK tactic/technique name
- "triage_summary": Clear technical justification for this severity rating

Incident Title: {title}
Raw Logs:
{raw_logs}

Return ONLY valid JSON matching this schema.""",
                input_variables=["title", "raw_logs"]
            )
            chain = prompt | llm | JsonOutputParser()
            result = chain.invoke({"title": title, "raw_logs": raw_logs[:2500]})
            return {
                "severity": result.get("severity", "HIGH"),
                "attack_category": result.get("attack_category", "Execution (T1059)"),
                "triage_summary": result.get("triage_summary", "Analyzed via OpenAI.")
            }
        except Exception as e:
            print(f"[LLM Triage Fallback] OpenAI call failed ({e}). Falling back to deterministic engine.")

    return DeterministicSecurityEngine.generate_triage(title, raw_logs, event_metrics)


def call_llm_investigation(
    title: str,
    raw_logs: str,
    iocs: Dict[str, Any],
    playbooks: List[Dict[str, Any]]
) -> str:
    """Execute deep investigation synthesis via OpenAI or fallback engine."""
    if is_openai_available():
        try:
            from langchain_openai import ChatOpenAI
            from langchain_core.prompts import PromptTemplate

            llm = ChatOpenAI(model=OPENAI_MODEL, temperature=0.1, openai_api_key=OPENAI_API_KEY)
            pb_context = "\n".join([f"- {p.get('title')}: {p.get('content_snippet')[:200]}" for p in playbooks])
            prompt = PromptTemplate(
                template="""You are an expert SOC Investigation Agent.
Correlate the security incident logs, extracted IOCs, and retrieved playbooks into a concise, technical investigation findings report.

Incident Title: {title}
Extracted IOCs: {iocs}
Retrieved Playbooks:
{pb_context}
Logs:
{raw_logs}

Format your output in clean Markdown with sections: Threat Narrative, Correlated IOCs, Behavioral Analysis, and Conclusion.""",
                input_variables=["title", "iocs", "pb_context", "raw_logs"]
            )
            chain = prompt | llm
            res = chain.invoke({
                "title": title,
                "iocs": json.dumps(iocs),
                "pb_context": pb_context,
                "raw_logs": raw_logs[:2500]
            })
            return res.content
        except Exception as e:
            print(f"[LLM Investigation Fallback] OpenAI call failed ({e}). Falling back.")

    return DeterministicSecurityEngine.generate_investigation(title, raw_logs, iocs, playbooks)


def call_llm_response_plan(
    severity: str,
    iocs: Dict[str, Any],
    playbooks: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Execute response plan generation via OpenAI or fallback engine."""
    if is_openai_available():
        try:
            from langchain_openai import ChatOpenAI
            from langchain_core.prompts import PromptTemplate
            from langchain_core.output_parsers import JsonOutputParser

            llm = ChatOpenAI(model=OPENAI_MODEL, temperature=0.1, openai_api_key=OPENAI_API_KEY)
            prompt = PromptTemplate(
                template="""You are a SOC Response Agent.
Based on severity: {severity} and IOCs: {iocs}, formulate a recommended incident response plan.
Return ONLY a JSON object with:
- "response_plan": List of ordered actionable response steps (strings).
- "simulated_actions": List of specific candidate containment actions requiring human confirmation (e.g. "Isolate host X", "Block IP Y").""",
                input_variables=["severity", "iocs"]
            )
            chain = prompt | llm | JsonOutputParser()
            result = chain.invoke({"severity": severity, "iocs": json.dumps(iocs)})
            if "response_plan" in result and "simulated_actions" in result:
                return result
        except Exception as e:
            print(f"[LLM Response Fallback] OpenAI call failed ({e}). Falling back.")

    return DeterministicSecurityEngine.generate_response_plan(severity, iocs, playbooks)
