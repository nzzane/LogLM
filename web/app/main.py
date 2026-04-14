"""
LogLM Web UI — FastAPI application.

Routes:
  GET  /              → dashboard (realtime status + recent alerts)
  GET  /logs          → log browser with filters
  GET  /alerts        → alert history
  GET  /aliases       → service alias management
  GET  /chat          → LLM chat with memory
  POST /api/chat      → send chat message, get LLM response
  GET  /api/stream    → SSE stream of new events (realtime)
  GET  /api/stats     → summary counts
"""

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import AsyncGenerator

import asyncpg
import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

POSTGRES_DSN = os.environ["POSTGRES_DSN"]
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1:8b-instruct-q4_K_M")

app = FastAPI(title="LogLM")
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

_pool: asyncpg.Pool | None = None
_redis: aioredis.Redis | None = None
_http: httpx.AsyncClient | None = None


@app.on_event("startup")
async def startup():
    global _pool, _redis, _http
    _pool = await asyncpg.create_pool(POSTGRES_DSN, min_size=2, max_size=10)
    _redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    _http = httpx.AsyncClient()


@app.on_event("shutdown")
async def shutdown():
    if _pool:
        await _pool.close()
    if _redis:
        await _redis.aclose()
    if _http:
        await _http.aclose()


# ── SSE realtime stream ───────────────────────────────────────────────────────

async def event_generator() -> AsyncGenerator[str, None]:
    pubsub = _redis.pubsub()
    await pubsub.subscribe("loglm:events")
    try:
        while True:
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if msg and msg["type"] == "message":
                yield f"data: {msg['data']}\n\n"
            else:
                yield ": keepalive\n\n"
            await asyncio.sleep(0.1)
    finally:
        await pubsub.unsubscribe("loglm:events")
        await pubsub.aclose()


@app.get("/api/stream")
async def stream():
    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ── Stats API ─────────────────────────────────────────────────────────────────

@app.get("/api/stats")
async def stats():
    async with _pool.acquire() as conn:
        counts = await conn.fetchrow("""
            SELECT
                COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '1 hour') AS events_1h,
                COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '24 hours') AS events_24h,
                COUNT(*) FILTER (WHERE severity IN ('emerg','alert','crit','err','error')
                                   AND timestamp > NOW() - INTERVAL '24 hours') AS errors_24h
            FROM events
        """)
        alert_counts = await conn.fetchrow("""
            SELECT
                COUNT(*) FILTER (WHERE NOT acknowledged) AS unacked,
                COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '24 hours') AS today
            FROM alerts
        """)
        return {
            "events_1h": counts["events_1h"],
            "events_24h": counts["events_24h"],
            "errors_24h": counts["errors_24h"],
            "alerts_unacked": alert_counts["unacked"],
            "alerts_today": alert_counts["today"],
        }


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    async with _pool.acquire() as conn:
        recent_alerts = await conn.fetch("""
            SELECT id, timestamp, severity, title, description,
                   affected_hosts, acknowledged
            FROM alerts ORDER BY timestamp DESC LIMIT 10
        """)
        service_statuses = await conn.fetch("""
            SELECT s.service_name, s.host, s.status, s.last_event, s.last_message, a.alias
            FROM service_status s
            LEFT JOIN service_aliases a ON a.raw_name = s.host
            ORDER BY s.status DESC, s.service_name
        """)
        recent_events = await conn.fetch("""
            SELECT timestamp, host, source, severity, program, message
            FROM events WHERE verdict = 'keep'
            ORDER BY timestamp DESC LIMIT 50
        """)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "alerts": [dict(r) for r in recent_alerts],
        "services": [dict(r) for r in service_statuses],
        "events": [dict(r) for r in recent_events],
    })


# ── Log Browser ───────────────────────────────────────────────────────────────

@app.get("/logs", response_class=HTMLResponse)
async def logs(
    request: Request,
    host: str = "",
    source: str = "",
    severity: str = "",
    q: str = "",
    hours: int = 1,
    page: int = 1,
):
    limit = 100
    offset = (page - 1) * limit
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    filters = ["timestamp > $1"]
    args: list = [since]
    n = 2

    if host:
        filters.append(f"host ILIKE ${n}")
        args.append(f"%{host}%")
        n += 1
    if source:
        filters.append(f"source = ${n}")
        args.append(source)
        n += 1
    if severity:
        filters.append(f"severity = ${n}")
        args.append(severity)
        n += 1
    if q:
        filters.append(f"message ILIKE ${n}")
        args.append(f"%{q}%")
        n += 1

    where = " AND ".join(filters)
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT timestamp, host, source, severity, program, message FROM events "
            f"WHERE {where} ORDER BY timestamp DESC LIMIT {limit} OFFSET {offset}",
            *args,
        )
        total = await conn.fetchval(f"SELECT COUNT(*) FROM events WHERE {where}", *args)

    return templates.TemplateResponse("logs.html", {
        "request": request,
        "events": [dict(r) for r in rows],
        "host": host, "source": source, "severity": severity,
        "q": q, "hours": hours, "page": page,
        "total": total, "limit": limit,
    })


# ── Alerts ────────────────────────────────────────────────────────────────────

@app.get("/alerts", response_class=HTMLResponse)
async def alert_history(request: Request, page: int = 1):
    limit = 50
    offset = (page - 1) * limit
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT $1 OFFSET $2",
            limit, offset,
        )
        total = await conn.fetchval("SELECT COUNT(*) FROM alerts")
    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "alerts": [dict(r) for r in rows],
        "page": page, "total": total, "limit": limit,
    })


@app.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int):
    async with _pool.acquire() as conn:
        await conn.execute("UPDATE alerts SET acknowledged=TRUE WHERE id=$1", alert_id)
    return JSONResponse({"ok": True})


# ── Aliases ───────────────────────────────────────────────────────────────────

@app.get("/aliases", response_class=HTMLResponse)
async def aliases_page(request: Request):
    async with _pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM service_aliases ORDER BY alias")
    return templates.TemplateResponse("aliases.html", {
        "request": request,
        "aliases": [dict(r) for r in rows],
    })


@app.post("/aliases")
async def add_alias(
    request: Request,
    raw_name: str = Form(...),
    alias: str = Form(...),
    description: str = Form(""),
):
    async with _pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO service_aliases (raw_name, alias, description)
               VALUES ($1, $2, $3)
               ON CONFLICT (raw_name) DO UPDATE SET alias=$2, description=$3, updated_at=NOW()""",
            raw_name.strip(), alias.strip(), description.strip(),
        )
    from fastapi.responses import RedirectResponse
    return RedirectResponse("/aliases", status_code=303)


@app.post("/aliases/{alias_id}/delete")
async def delete_alias(alias_id: int):
    async with _pool.acquire() as conn:
        await conn.execute("DELETE FROM service_aliases WHERE id=$1", alias_id)
    return JSONResponse({"ok": True})


# ═════════════════════════════════════════════════════════════════════════════
#  CHAT WITH MEMORY
# ═════════════════════════════════════════════════════════════════════════════

CHAT_SYSTEM = """You are LogLM, an AI assistant for a home/small-office network monitoring system.
You have access to memory summaries of recent network activity, current SNMP metrics,
recent events, alerts, and the full conversation history.

Your users are network administrators who will ask you questions like:
- "What's changed in the last hour?"
- "Anything look different?"
- "What just happened?"
- "Is the router doing OK?"
- "How many wifi clients are connected?"
- "Summarise today's alerts"
- "Any suspicious activity?"

Answer concisely and specifically. Reference actual hostnames, IPs, timestamps, and numbers.
If you don't have enough data to answer, say so. Do not make up events or metrics.
Format your response in plain text with line breaks for readability."""


async def build_chat_context(pool: asyncpg.Pool, redis_client: aioredis.Redis) -> str:
    """Gather current state for the LLM's context window."""
    sections = []
    now = datetime.now(timezone.utc)

    async with pool.acquire() as conn:
        # Recent memory summaries (last 6 = ~30 min of coverage)
        summaries = await conn.fetch(
            "SELECT timestamp, summary FROM memory_summaries ORDER BY timestamp DESC LIMIT 6"
        )
        if summaries:
            sections.append("=== MEMORY SUMMARIES (most recent first) ===")
            for s in summaries:
                sections.append(f"[{s['timestamp'].strftime('%Y-%m-%d %H:%M')}] {s['summary']}")

        # Recent alerts (last 24h)
        alerts = await conn.fetch("""
            SELECT timestamp, severity, title, description, affected_hosts, acknowledged
            FROM alerts WHERE timestamp > NOW() - INTERVAL '24 hours'
            ORDER BY timestamp DESC LIMIT 10
        """)
        if alerts:
            sections.append("\n=== RECENT ALERTS (24h) ===")
            for a in alerts:
                ack = " [ACK]" if a["acknowledged"] else ""
                hosts = ", ".join(a["affected_hosts"] or [])
                sections.append(
                    f"[{a['timestamp'].strftime('%H:%M')}] {a['severity'].upper()}{ack}: "
                    f"{a['title']} — {a['description'][:100]} (hosts: {hosts})"
                )

        # Recent notable events (last hour, errors/warnings only)
        events = await conn.fetch("""
            SELECT timestamp, host, source, severity, message
            FROM events
            WHERE timestamp > NOW() - INTERVAL '1 hour'
              AND severity IN ('emerg','alert','crit','err','error','warning')
            ORDER BY timestamp DESC LIMIT 25
        """)
        if events:
            sections.append("\n=== NOTABLE EVENTS (last 1h) ===")
            for e in events:
                sections.append(
                    f"[{e['timestamp'].strftime('%H:%M:%S')}] {e['severity'].upper()} "
                    f"{e['host']} ({e['source']}): {e['message'][:150]}"
                )

        # Event statistics
        stats = await conn.fetchrow("""
            SELECT
                COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '1 hour')  AS last_1h,
                COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '24 hours') AS last_24h,
                COUNT(*) FILTER (WHERE severity IN ('err','error','crit','emerg','alert')
                                   AND timestamp > NOW() - INTERVAL '1 hour')  AS errors_1h,
                COUNT(DISTINCT host) FILTER (WHERE timestamp > NOW() - INTERVAL '1 hour') AS hosts_1h
            FROM events
        """)
        sections.append(f"\n=== EVENT STATS ===")
        sections.append(
            f"Last 1h: {stats['last_1h']} events ({stats['errors_1h']} errors) from {stats['hosts_1h']} hosts | "
            f"Last 24h: {stats['last_24h']} events"
        )

        # SNMP metrics
        snmp_latest = await conn.fetch("""
            SELECT DISTINCT ON (host) host, sys_name, avg_cpu, wifi_clients,
                   interfaces_up, interfaces_down, total_in_bps, total_out_bps,
                   total_errors, timestamp
            FROM snmp_metrics
            ORDER BY host, timestamp DESC
        """)
        if snmp_latest:
            sections.append("\n=== CURRENT SNMP METRICS ===")
            for m in snmp_latest:
                parts = [f"{m['sys_name'] or m['host']}:"]
                if m["avg_cpu"] is not None:
                    parts.append(f"CPU={m['avg_cpu']:.1f}%")
                parts.append(f"ifaces={m['interfaces_up']}up/{m['interfaces_down']}down")
                if m["wifi_clients"]:
                    parts.append(f"wifi={m['wifi_clients']}clients")
                if m["total_in_bps"]:
                    parts.append(f"in={m['total_in_bps']:.0f}B/s out={m['total_out_bps']:.0f}B/s")
                if m["total_errors"] and m["total_errors"] > 0:
                    parts.append(f"ERRORS={m['total_errors']:.1f}/s")
                sections.append(" ".join(parts))

        # Service aliases for reference
        aliases = await conn.fetch("SELECT raw_name, alias FROM service_aliases")
        if aliases:
            sections.append("\n=== KNOWN HOSTS ===")
            sections.append(", ".join(f"{a['raw_name']}={a['alias']}" for a in aliases))

    sections.append(f"\n=== CURRENT TIME: {now.strftime('%Y-%m-%d %H:%M:%S')} UTC ===")
    return "\n".join(sections)


class ChatRequest(BaseModel):
    session_id: str | None = None
    message: str


@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request, session_id: str = ""):
    sessions = []
    messages = []
    async with _pool.acquire() as conn:
        sessions = await conn.fetch(
            "SELECT id, title, updated_at FROM chat_sessions ORDER BY updated_at DESC LIMIT 20"
        )
        if session_id:
            messages = await conn.fetch(
                "SELECT role, content, created_at FROM chat_messages "
                "WHERE session_id = $1 ORDER BY created_at",
                uuid.UUID(session_id),
            )
    return templates.TemplateResponse("chat.html", {
        "request": request,
        "sessions": [dict(s) for s in sessions],
        "messages": [dict(m) for m in messages],
        "session_id": session_id,
    })


@app.post("/api/chat")
async def chat_send(req: ChatRequest):
    """Handle a chat message: gather context, call LLM, store conversation."""
    if not req.message.strip():
        raise HTTPException(400, "Empty message")

    async with _pool.acquire() as conn:
        # Get or create session
        if req.session_id:
            sid = uuid.UUID(req.session_id)
        else:
            sid = uuid.uuid4()
            await conn.execute(
                "INSERT INTO chat_sessions (id, title) VALUES ($1, $2)",
                sid, req.message[:60],
            )

        # Store user message
        await conn.execute(
            "INSERT INTO chat_messages (session_id, role, content) VALUES ($1, 'user', $2)",
            sid, req.message,
        )

        # Get conversation history (last 20 messages for context)
        history = await conn.fetch(
            "SELECT role, content FROM chat_messages WHERE session_id = $1 "
            "ORDER BY created_at DESC LIMIT 20",
            sid,
        )
        history = list(reversed(history))

    # Build context
    context = await build_chat_context(_pool, _redis)

    # Build prompt with conversation history
    prompt_parts = [f"SYSTEM CONTEXT:\n{context}\n"]
    prompt_parts.append("CONVERSATION HISTORY:")
    for msg in history[:-1]:  # exclude current message
        role = "User" if msg["role"] == "user" else "LogLM"
        prompt_parts.append(f"{role}: {msg['content']}")
    prompt_parts.append(f"\nUser: {req.message}")
    prompt_parts.append("\nLogLM:")

    full_prompt = "\n".join(prompt_parts)

    # Call Ollama
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": full_prompt,
        "system": CHAT_SYSTEM,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": 1024,
        },
    }

    try:
        resp = await _http.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=120)
        resp.raise_for_status()
        answer = resp.json().get("response", "").strip()
    except Exception as e:
        answer = f"Sorry, I couldn't reach the LLM: {e}"

    if not answer:
        answer = "I don't have enough data to answer that right now. Events may still be collecting."

    # Store assistant response
    async with _pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO chat_messages (session_id, role, content, context_summary) VALUES ($1, 'assistant', $2, $3)",
            sid, answer, context[:500],  # store truncated context for debugging
        )
        await conn.execute(
            "UPDATE chat_sessions SET updated_at = NOW(), title = COALESCE(NULLIF(title, 'New conversation'), $2) WHERE id = $1",
            sid, req.message[:60],
        )

    return JSONResponse({
        "session_id": str(sid),
        "response": answer,
    })


@app.post("/api/chat/sessions")
async def new_chat_session():
    sid = uuid.uuid4()
    async with _pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO chat_sessions (id, title) VALUES ($1, 'New conversation')", sid
        )
    return JSONResponse({"session_id": str(sid)})


@app.get("/api/chat/sessions/{session_id}/messages")
async def get_chat_messages(session_id: str):
    async with _pool.acquire() as conn:
        messages = await conn.fetch(
            "SELECT role, content, created_at FROM chat_messages "
            "WHERE session_id = $1 ORDER BY created_at",
            uuid.UUID(session_id),
        )
    return JSONResponse({
        "messages": [
            {"role": m["role"], "content": m["content"], "created_at": m["created_at"].isoformat()}
            for m in messages
        ]
    })
