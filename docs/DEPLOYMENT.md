# Deployment Guide: Agentic SOC Copilot on Vercel

This document describes the production deployment architecture, configuration, and operational verification of the **Agentic SOC Copilot** on Vercel.

---

## 🌐 Production Details

- **Live Production URL**: [https://agentic-soc-copilot.vercel.app](https://agentic-soc-copilot.vercel.app)
- **Deployment Alias**: `https://agentic-soc-copilot-85bun1n52.vercel.app`
- **Health Check Endpoint**: [https://agentic-soc-copilot.vercel.app/health](https://agentic-soc-copilot.vercel.app/health)
- **Framework / Runtime**: Python 3.12 Serverless Function via `@vercel/python`
- **Vercel Project**: `satyavardhangudla2006-6738s-projects/agentic-soc-copilot`

---

## 🏗️ Architecture & Serverless Configuration

The application is deployed using Vercel's native Python runtime without external Docker dependencies.

### 1. Entrypoint (`api/index.py`)
Vercel identifies `api/index.py` as the serverless function handler. It imports the ASGI `app` instance from `app.main`:
```python
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.main import app
```

### 2. Routing (`vercel.json`)
The `vercel.json` file routes all incoming HTTP traffic (`/(.*)`) to the `api/index.py` ASGI handler, allowing FastAPI's internal router to handle root web pages, static assets, and API routes:
```json
{
  "builds": [
    {
      "src": "api/index.py",
      "use": "@vercel/python"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "api/index.py"
    }
  ]
}
```

### 3. Serverless SQLite Memory (`app/memory.py`)
In Vercel's serverless execution environment, the filesystem outside `/tmp` is read-only. `app/memory.py` automatically detects when running on Vercel (`os.getenv("VERCEL")`) and points the SQLite database to `/tmp/incidents.db`:
- **Local Environment**: Persists to `data/incidents.db`.
- **Vercel Serverless**: Writes to `tempfile.gettempdir() / "incidents.db"`.

> [!NOTE]
> **Serverless SQLite Ephemerality**: Vercel serverless functions are stateless and ephemeral. The `/tmp` directory retains incident history across warm function invocations, but can reset during cold restarts. For permanent enterprise multi-region persistence, a managed SQL database (e.g. Neon, Supabase, or AWS RDS PostgreSQL) can be plugged in by swapping `app/memory.py`.

---

## 🔑 Environment Variables

The project runs in **Deterministic Fallback Mode** by default, meaning it does not require any paid API keys to function out-of-the-box.

To enable live OpenAI reasoning in production:
1. In the Vercel Dashboard, navigate to **Settings** > **Environment Variables**.
2. Add:
   - `OPENAI_API_KEY`: Your OpenAI API Key (`sk-...`)
   - `OPENAI_MODEL`: `gpt-4o-mini` (or preferred model)
3. Redeploy or promote the deployment.

---

## 🧪 Production Verification Commands

All production endpoints can be verified using `curl` or `httpx`:

```bash
# 1. Health check
curl -s https://agentic-soc-copilot.vercel.app/health

# 2. Query recent incidents
curl -s https://agentic-soc-copilot.vercel.app/incidents/recent

# 3. Analyze security incident
curl -X POST https://agentic-soc-copilot.vercel.app/incidents/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "INC-PROD-001",
    "title": "Suspicious Obfuscated PowerShell Execution",
    "raw_logs": "powershell.exe -enc SQBuAHY... DestinationIp: 198.51.100.23"
  }'

# 4. Approve simulated containment
curl -X POST https://agentic-soc-copilot.vercel.app/incidents/approve/<TOKEN>
```

---

## 🔄 How to Redeploy

Whenever new commits are made to the codebase:

```bash
# Deploy to production
vercel deploy --prod
```
