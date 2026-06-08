import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from database.connection import close_pool, fetchrow, execute
from database.migrations import run_migrations
from models.schemas import AuditRequest
from orchestrator.swarm_orchestrator import SwarmOrchestrator

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: run Neon DB migrations
    await run_migrations()
    yield
    # Shutdown: close DB pool
    await close_pool()


app = FastAPI(
    title="SwarmAudit API",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow frontend on Vercel / Netlify + local dev
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Track active sessions for rate-limiting
active_sessions: dict[str, SwarmOrchestrator] = {}


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "service": "swarmaudit", "version": "1.0.0"}


# ── Start a new audit session ─────────────────────────────────────────────────
@app.post("/api/audit/start")
async def start_audit(request: AuditRequest):
    url = request.github_url.strip()
    if "github.com" not in url:
        raise HTTPException(status_code=400, detail="Must be a valid GitHub URL")

    # Simple rate limit: max 5 concurrent active sessions globally (free tier)
    if len(active_sessions) >= 5:
        raise HTTPException(
            status_code=429,
            detail="Too many active scans. Please wait for an existing scan to complete.",
        )

    session_id = str(uuid.uuid4())
    await execute(
        "INSERT INTO audit_sessions (id, github_url, status) VALUES ($1, $2, $3)",
        session_id, url, "pending",
    )
    return {"session_id": session_id, "status": "pending"}


# ── WebSocket: live agent streaming ──────────────────────────────────────────
@app.websocket("/ws/audit/{session_id}")
async def audit_websocket(websocket: WebSocket, session_id: str):
    await websocket.accept()
    orchestrator = SwarmOrchestrator(session_id, websocket)
    active_sessions[session_id] = orchestrator

    try:
        # Client must send {"github_url": "..."} immediately after connecting
        data = await asyncio.wait_for(websocket.receive_json(), timeout=30)
        github_url = data.get("github_url", "").strip()
        if not github_url:
            await websocket.send_json({"error": "github_url is required"})
            return

        # Mark as running
        await execute(
            "UPDATE audit_sessions SET status=$1 WHERE id=$2",
            "running", session_id,
        )

        await orchestrator.run(github_url)

        # Mark as complete
        await execute(
            "UPDATE audit_sessions SET status=$1, completed_at=NOW() WHERE id=$2",
            "completed", session_id,
        )

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        pass
    except Exception:
        try:
            await execute(
                "UPDATE audit_sessions SET status=$1 WHERE id=$2",
                "failed", session_id,
            )
        except Exception:
            pass
    finally:
        active_sessions.pop(session_id, None)


# ── Session status ────────────────────────────────────────────────────────────
@app.get("/api/audit/{session_id}/status")
async def get_status(session_id: str):
    row = await fetchrow(
        "SELECT id, github_url, status, total_vulnerabilities, "
        "critical_count, high_count, medium_count, low_count, "
        "total_risk_usd, repo_name, tech_stack, file_count, "
        "created_at, completed_at "
        "FROM audit_sessions WHERE id=$1",
        session_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    return dict(row)


# ── PDF report download ───────────────────────────────────────────────────────
@app.get("/api/report/{session_id}/download")
async def download_report(session_id: str):
    # Validate session exists
    row = await fetchrow("SELECT id FROM audit_sessions WHERE id=$1", session_id)
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")

    report_path = f"/tmp/reports/{session_id}_report.pdf"
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report not ready yet")

    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename=f"swarmaudit_{session_id[:8]}.pdf",
    )
