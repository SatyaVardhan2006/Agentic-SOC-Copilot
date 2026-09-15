import os
from pathlib import Path
from contextlib import asynccontextmanager
from typing import List, Dict, Any

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.models import (
    IncidentAnalyzeRequest,
    IncidentAnalyzeResponse,
    ApprovalResponse,
    HealthResponse,
    RecentIncidentSummary
)
from app.agents import run_soc_pipeline
from app.memory import (
    init_db,
    save_incident,
    get_recent_incidents,
    get_incident_by_token,
    record_approval
)
from app.rag import get_rag_engine
from app.llm import get_llm_mode
from app.tools import simulate_containment

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure DB and RAG vector store are initialized
    init_db()
    rag_engine = get_rag_engine()
    print(f"[STARTUP] Initialized DB and indexed {len(rag_engine.documents)} security playbooks.")
    print(f"[STARTUP] Active LLM mode: {get_llm_mode()}")
    yield


app = FastAPI(
    title="Agentic SOC Copilot API",
    description="Multi-agent GenAI assistant for Security Operations Center incident triage, investigation, and response.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for flexible development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static frontend directory
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/", summary="Serve Web Dashboard")
async def serve_index():
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "Agentic SOC Copilot Backend API is running."}


@app.get("/health", response_model=HealthResponse, summary="System Health & Status")
async def health_check():
    rag_engine = get_rag_engine()
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        llm_mode=get_llm_mode(),
        database_connected=True,
        playbooks_loaded=len(rag_engine.documents)
    )


@app.post("/incidents/analyze", response_model=IncidentAnalyzeResponse, summary="Analyze Security Incident")
async def analyze_incident(req: IncidentAnalyzeRequest):
    try:
        # Execute LangGraph multi-agent pipeline
        result = run_soc_pipeline(
            incident_id=req.incident_id,
            title=req.title,
            raw_logs=req.raw_logs
        )

        # Persist into SQLite memory
        save_incident(result)

        return IncidentAnalyzeResponse(
            incident_id=result["incident_id"],
            title=result["title"],
            severity=result["severity"],
            attack_category=result["attack_category"],
            triage_summary=result["triage_summary"],
            extracted_iocs=result["extracted_iocs"],
            retrieved_playbooks=result["retrieved_playbooks"],
            investigation_findings=result["investigation_findings"],
            response_plan=result["response_plan"],
            simulated_actions=result["simulated_actions"],
            approval_token=result["approval_token"],
            approval_status=result["approval_status"],
            execution_trace=result["execution_trace"],
            created_at=result.get("created_at", "")
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Incident analysis workflow failed: {str(e)}"
        )


@app.get("/incidents/recent", response_model=List[RecentIncidentSummary], summary="List Recent Incidents")
async def list_recent_incidents(limit: int = 10):
    try:
        incidents = get_recent_incidents(limit=limit)
        return [RecentIncidentSummary(**item) for item in incidents]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch recent incidents: {str(e)}"
        )


@app.post("/incidents/approve/{approval_token}", response_model=ApprovalResponse, summary="Approve Simulated Containment")
async def approve_incident_containment(approval_token: str):
    incident = get_incident_by_token(approval_token)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval token '{approval_token}' not found."
        )

    # Check if already approved
    if incident.get("approval_status") == "APPROVED":
        sim_log = incident.get("simulated_containment_log", {})
        return ApprovalResponse(
            approval_token=approval_token,
            incident_id=incident["incident_id"],
            status="ALREADY_APPROVED",
            message="Containment actions were previously approved and simulated.",
            executed_actions=sim_log.get("executed_actions", []),
            approved_at=incident.get("approved_at", "")
        )

    # Execute simulated containment tool
    actions = incident.get("simulated_actions", [])
    containment_result = simulate_containment(
        approval_token=approval_token,
        incident_id=incident["incident_id"],
        actions=actions
    )

    # Persist approval and containment log in SQLite
    updated = record_approval(approval_token, containment_result)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record approval in database."
        )

    return ApprovalResponse(
        approval_token=approval_token,
        incident_id=incident["incident_id"],
        status="APPROVED",
        message="Simulated containment successfully authorized and recorded. Zero live changes executed.",
        executed_actions=containment_result["executed_actions"],
        approved_at=updated["approved_at"]
    )
