import uuid
from datetime import datetime, timezone
from typing import TypedDict, List, Dict, Any, Optional

from langgraph.graph import StateGraph, START, END

from app.tools import (
    analyze_events,
    extract_iocs,
    search_security_knowledge
)
from app.llm import (
    call_llm_triage,
    call_llm_investigation,
    call_llm_response_plan
)


class AgentState(TypedDict):
    incident_id: str
    title: str
    raw_logs: str
    event_metrics: Dict[str, Any]
    severity: str
    attack_category: str
    triage_summary: str
    retrieved_playbooks: List[Dict[str, Any]]
    extracted_iocs: Dict[str, Any]
    investigation_findings: str
    response_plan: List[str]
    simulated_actions: List[str]
    approval_token: str
    approval_status: str
    execution_trace: List[Dict[str, str]]


def _get_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


def triage_node(state: AgentState) -> Dict[str, Any]:
    """
    Triage Agent:
    - Runs analyze_events tool to inspect telemetry
    - Identifies severity (LOW, MEDIUM, HIGH, CRITICAL)
    - Determines basic attack category / MITRE tactic
    - Provides analytical justification
    """
    raw_logs = state.get("raw_logs", "")
    title = state.get("title", "")
    
    # 1. Tool Call: analyze_events
    event_metrics = analyze_events(raw_logs)

    # 2. LLM reasoning (or deterministic fallback)
    triage_result = call_llm_triage(title, raw_logs, event_metrics)

    trace_entry = {
        "agent": "Triage Agent",
        "status": "COMPLETED",
        "timestamp": _get_timestamp(),
        "details": (
            f"Evaluated {event_metrics.get('total_events', 0)} events. "
            f"Assigned severity {triage_result['severity']} under category '{triage_result['attack_category']}'."
        )
    }

    return {
        "event_metrics": event_metrics,
        "severity": triage_result["severity"],
        "attack_category": triage_result["attack_category"],
        "triage_summary": triage_result["triage_summary"],
        "execution_trace": state.get("execution_trace", []) + [trace_entry]
    }


def rag_node(state: AgentState) -> Dict[str, Any]:
    """
    Knowledge / RAG Agent:
    - Formulates contextual query from triage assessment
    - Invokes search_security_knowledge tool over local playbooks
    - Selects relevant response playbooks for grounding
    """
    title = state.get("title", "")
    category = state.get("attack_category", "")
    triage_summary = state.get("triage_summary", "")

    query = f"{title} {category} {triage_summary}"
    
    # Tool Call: search_security_knowledge
    playbooks = search_security_knowledge(query, top_k=2)

    matched_titles = [f"{p.get('title')} (score: {p.get('score')})" for p in playbooks]
    trace_entry = {
        "agent": "Knowledge / RAG Agent",
        "status": "COMPLETED",
        "timestamp": _get_timestamp(),
        "details": f"Retrieved {len(playbooks)} relevant playbooks: {', '.join(matched_titles)}."
    }

    return {
        "retrieved_playbooks": playbooks,
        "execution_trace": state.get("execution_trace", []) + [trace_entry]
    }


def investigation_node(state: AgentState) -> Dict[str, Any]:
    """
    Investigation Agent:
    - Runs extract_iocs tool to parse IPs, domains, hashes, and commands
    - Correlates evidence against retrieved playbooks
    - Produces synthesized threat narrative and technical findings
    """
    raw_logs = state.get("raw_logs", "")
    title = state.get("title", "")
    playbooks = state.get("retrieved_playbooks", [])

    # 1. Tool Call: extract_iocs
    iocs = extract_iocs(raw_logs)

    # 2. Synthesize investigation report
    investigation_findings = call_llm_investigation(title, raw_logs, iocs, playbooks)

    ip_count = len(iocs.get("ips", []))
    domain_count = len(iocs.get("domains", []))
    hash_count = len(iocs.get("hashes", []))

    trace_entry = {
        "agent": "Investigation Agent",
        "status": "COMPLETED",
        "timestamp": _get_timestamp(),
        "details": (
            f"Extracted {ip_count} IPs, {domain_count} domains, {hash_count} hashes. "
            "Synthesized cross-telemetry behavioral investigation report."
        )
    }

    return {
        "extracted_iocs": iocs,
        "investigation_findings": investigation_findings,
        "execution_trace": state.get("execution_trace", []) + [trace_entry]
    }


def response_node(state: AgentState) -> Dict[str, Any]:
    """
    Response Agent:
    - Generates actionable response recommendations
    - Prepares discrete simulated containment actions
    - Enforces Human-in-the-Loop approval gate by generating a secure approval token
    """
    severity = state.get("severity", "HIGH")
    iocs = state.get("extracted_iocs", {})
    playbooks = state.get("retrieved_playbooks", [])

    # LLM or deterministic response formulation
    response_data = call_llm_response_plan(severity, iocs, playbooks)

    approval_token = f"tok-{uuid.uuid4().hex[:12]}"
    
    trace_entry = {
        "agent": "Response Agent",
        "status": "AWAITING_APPROVAL",
        "timestamp": _get_timestamp(),
        "details": (
            f"Formulated {len(response_data.get('response_plan', []))} response steps. "
            f"Generated approval token '{approval_token}'. Human approval required before simulated containment."
        )
    }

    return {
        "response_plan": response_data.get("response_plan", []),
        "simulated_actions": response_data.get("simulated_actions", []),
        "approval_token": approval_token,
        "approval_status": "PENDING",
        "execution_trace": state.get("execution_trace", []) + [trace_entry]
    }


def build_soc_graph():
    """Construct and compile the LangGraph workflow."""
    workflow = StateGraph(AgentState)

    # Register agent nodes
    workflow.add_node("triage", triage_node)
    workflow.add_node("rag", rag_node)
    workflow.add_node("investigation", investigation_node)
    workflow.add_node("response", response_node)

    # Establish sequential flow
    workflow.add_edge(START, "triage")
    workflow.add_edge("triage", "rag")
    workflow.add_edge("rag", "investigation")
    workflow.add_edge("investigation", "response")
    workflow.add_edge("response", END)

    return workflow.compile()


# Compiled singleton graph
soc_agent_graph = build_soc_graph()


def run_soc_pipeline(incident_id: str, title: str, raw_logs: str) -> Dict[str, Any]:
    """
    Execute the multi-agent SOC pipeline for a given incident.
    """
    initial_state: AgentState = {
        "incident_id": incident_id,
        "title": title,
        "raw_logs": raw_logs,
        "event_metrics": {},
        "severity": "PENDING",
        "attack_category": "PENDING",
        "triage_summary": "",
        "retrieved_playbooks": [],
        "extracted_iocs": {},
        "investigation_findings": "",
        "response_plan": [],
        "simulated_actions": [],
        "approval_token": "",
        "approval_status": "NOT_STARTED",
        "execution_trace": []
    }

    final_state = soc_agent_graph.invoke(initial_state)
    return final_state
