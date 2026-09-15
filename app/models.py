from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class IncidentAnalyzeRequest(BaseModel):
    incident_id: str = Field(..., description="Unique incident identifier (e.g. INC-2026-8821)")
    title: str = Field(..., description="Short descriptive title of the incident")
    raw_logs: str = Field(..., description="Raw security events, EDR telemetry, or syslog lines")


class IOCExtractionResult(BaseModel):
    ips: List[Dict[str, str]] = Field(default_factory=list, description="List of detected IPs with internal/external type")
    domains: List[str] = Field(default_factory=list, description="Extracted domain names")
    hashes: List[str] = Field(default_factory=list, description="Extracted MD5/SHA256 hashes")
    suspicious_commands: List[str] = Field(default_factory=list, description="Extracted obfuscated or high-risk command strings")


class PlaybookMatch(BaseModel):
    playbook_id: str
    title: str
    category: str
    score: float
    content_snippet: str


class AgentTraceStep(BaseModel):
    agent: str
    status: str
    timestamp: str
    details: str


class IncidentAnalyzeResponse(BaseModel):
    incident_id: str
    title: str
    severity: str
    attack_category: str
    triage_summary: str
    extracted_iocs: Dict[str, Any]
    retrieved_playbooks: List[Dict[str, Any]]
    investigation_findings: str
    response_plan: List[str]
    simulated_actions: List[str]
    approval_token: str
    approval_status: str
    execution_trace: List[AgentTraceStep]
    created_at: str


class ApprovalActionRecord(BaseModel):
    action: str
    status: str
    target: str
    timestamp: str
    details: str


class ApprovalResponse(BaseModel):
    approval_token: str
    incident_id: str
    status: str
    message: str
    executed_actions: List[ApprovalActionRecord]
    approved_at: str


class HealthResponse(BaseModel):
    status: str
    version: str
    llm_mode: str
    database_connected: bool
    playbooks_loaded: int


class RecentIncidentSummary(BaseModel):
    incident_id: str
    title: str
    timestamp: str
    severity: str
    category: str
    summary: str
    approval_status: str
