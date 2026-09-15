import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import os
import tempfile

def _resolve_default_db_path() -> Path:
    """Return writable DB path: /tmp in Vercel/serverless environments, local data/ otherwise."""
    if os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"):
        return Path(tempfile.gettempdir()) / "incidents.db"
    
    local_path = Path(__file__).resolve().parent.parent / "data" / "incidents.db"
    try:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        test_file = local_path.parent / ".write_test"
        with open(test_file, "w") as f:
            f.write("ok")
        test_file.unlink(missing_ok=True)
        return local_path
    except (OSError, PermissionError):
        return Path(tempfile.gettempdir()) / "incidents.db"


DEFAULT_DB_PATH = _resolve_default_db_path()


def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    target_path = db_path or DEFAULT_DB_PATH
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(target_path))
    except (OSError, PermissionError, sqlite3.OperationalError):
        # Fallback to temp directory if specified target path fails
        temp_path = Path(tempfile.gettempdir()) / "incidents.db"
        temp_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(temp_path))
    conn.row_factory = sqlite3.Row
    # Ensure incidents table exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            summary TEXT NOT NULL,
            raw_logs TEXT NOT NULL,
            iocs_json TEXT,
            playbooks_json TEXT,
            investigation_findings TEXT,
            response_plan_json TEXT,
            simulated_actions_json TEXT,
            approval_token TEXT UNIQUE,
            approval_status TEXT NOT NULL,
            execution_trace_json TEXT,
            created_at TEXT NOT NULL,
            approved_at TEXT,
            simulated_containment_log_json TEXT
        );
    """)
    conn.commit()
    return conn


def init_db(db_path: Optional[Path] = None):
    """Initialize the SQLite database and create incidents table if not exists."""
    conn = get_db_connection(db_path)
    conn.close()


def save_incident(incident: Dict[str, Any], db_path: Optional[Path] = None):
    """Insert or replace an incident record in SQLite."""
    conn = get_db_connection(db_path)
    with conn:
        conn.execute("""
            INSERT OR REPLACE INTO incidents (
                id, title, severity, category, summary, raw_logs,
                iocs_json, playbooks_json, investigation_findings,
                response_plan_json, simulated_actions_json,
                approval_token, approval_status, execution_trace_json,
                created_at, approved_at, simulated_containment_log_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident["incident_id"],
            incident["title"],
            incident["severity"],
            incident["attack_category"],
            incident["triage_summary"],
            incident.get("raw_logs", ""),
            json.dumps(incident.get("extracted_iocs", {})),
            json.dumps(incident.get("retrieved_playbooks", [])),
            incident.get("investigation_findings", ""),
            json.dumps(incident.get("response_plan", [])),
            json.dumps(incident.get("simulated_actions", [])),
            incident.get("approval_token", ""),
            incident.get("approval_status", "PENDING"),
            json.dumps(incident.get("execution_trace", [])),
            incident.get("created_at", datetime.now(timezone.utc).isoformat()),
            incident.get("approved_at"),
            json.dumps(incident.get("simulated_containment_log", {}))
        ))
    conn.close()


def get_recent_incidents(limit: int = 10, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Retrieve recent incidents ordered by creation time descending."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, title, severity, category, summary, approval_status, created_at
        FROM incidents
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    results = [
        {
            "incident_id": row["id"],
            "title": row["title"],
            "timestamp": row["created_at"],
            "severity": row["severity"],
            "category": row["category"],
            "summary": row["summary"],
            "approval_status": row["approval_status"]
        }
        for row in rows
    ]
    conn.close()
    return results


def get_incident_by_id(incident_id: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Fetch complete incident record by ID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return _row_to_dict(row)


def get_incident_by_token(token: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Fetch incident record by approval token."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents WHERE approval_token = ?", (token,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return _row_to_dict(row)


def record_approval(token: str, containment_result: Dict[str, Any], db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Update incident record to mark approval and store simulated containment log."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection(db_path)
    with conn:
        cursor = conn.execute("""
            UPDATE incidents
            SET approval_status = 'APPROVED',
                approved_at = ?,
                simulated_containment_log_json = ?
            WHERE approval_token = ?
        """, (now, json.dumps(containment_result), token))
        
        if cursor.rowcount == 0:
            conn.close()
            return None

    conn.close()
    return get_incident_by_token(token, db_path=db_path)


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "incident_id": row["id"],
        "title": row["title"],
        "severity": row["severity"],
        "attack_category": row["category"],
        "triage_summary": row["summary"],
        "raw_logs": row["raw_logs"],
        "extracted_iocs": json.loads(row["iocs_json"] or "{}"),
        "retrieved_playbooks": json.loads(row["playbooks_json"] or "[]"),
        "investigation_findings": row["investigation_findings"],
        "response_plan": json.loads(row["response_plan_json"] or "[]"),
        "simulated_actions": json.loads(row["simulated_actions_json"] or "[]"),
        "approval_token": row["approval_token"],
        "approval_status": row["approval_status"],
        "execution_trace": json.loads(row["execution_trace_json"] or "[]"),
        "created_at": row["created_at"],
        "approved_at": row["approved_at"],
        "simulated_containment_log": json.loads(row["simulated_containment_log_json"] or "{}")
    }
