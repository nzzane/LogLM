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
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import AsyncGenerator

import asyncpg
import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Form, HTTPException, Query, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.encoders import jsonable_encoder
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app import auth, observability

try:
    import docker as docker_sdk
    from docker.errors import DockerException, NotFound
except ImportError:
    docker_sdk = None
    DockerException = Exception
    NotFound = Exception

POSTGRES_DSN = os.environ["POSTGRES_DSN"]
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
LOKI_URL = os.environ.get("LOKI_URL", "http://loki:3100")
LIBRENMS_URL = os.environ.get("LIBRENMS_URL", "")
LIBRENMS_TOKEN = os.environ.get("LIBRENMS_TOKEN", "")
# Quick mode: small fast model for stats/alerts queries
OLLAMA_MODEL = os.environ.get(
    "OLLAMA_MODEL_DEEP",
    os.environ.get("OLLAMA_MODEL", "llama3.2:3b"),
)
# Investigator mode: larger model for cross-source correlation
OLLAMA_MODEL_DEEP = os.environ.get(
    "OLLAMA_MODEL_DEEP",
    os.environ.get("OLLAMA_MODEL", "llama3.1:8b-instruct-q4_K_M"),
)
OLLAMA_MAX_CONCURRENT = int(os.environ.get("OLLAMA_MAX_CONCURRENT", "2"))
OLLAMA_KEEP_ALIVE = os.environ.get("OLLAMA_KEEP_ALIVE", "30m")
_ollama_sem = asyncio.Semaphore(OLLAMA_MAX_CONCURRENT)

# Timezone + NTP — surfaced on /retention so admins know what the host believes.
APP_TZ = os.environ.get("TZ", "UTC")
NTP_SERVER = os.environ.get("NTP_SERVER", "pool.ntp.org")

app = FastAPI(title="LogLM")
app.middleware("http")(observability.metrics_middleware)
templates = Jinja2Templates(directory="app/templates")


class CachedStaticFiles(StaticFiles):
    """Static files with a 1h Cache-Control header so CSS/JS isn't refetched
    on every nav. Hashed query strings (?v=) bust the cache when a file changes."""

    async def get_response(self, path, scope):
        resp = await super().get_response(path, scope)
        if resp.status_code == 200:
            resp.headers["Cache-Control"] = "public, max-age=3600"
        return resp


app.mount("/static", CachedStaticFiles(directory="app/static"), name="static")

_pool: asyncpg.Pool | None = None
_redis: aioredis.Redis | None = None
_http: httpx.AsyncClient | None = None
_docker = None

LOGLM_SERVICES = [
    "loglm-syslog",
    "loglm-snmp",
    "loglm-processor",
    "loglm-analyzer",
    "loglm-web",
    "loglm-loki",
    "loglm-postgres",
    "loglm-redis",
]


@app.on_event("startup")
async def startup():
    global _pool, _redis, _http
    last_err = None
    for _ in range(30):
        try:
            _pool = await asyncpg.create_pool(POSTGRES_DSN, min_size=2, max_size=10)
            break
        except (OSError, ConnectionRefusedError, asyncpg.PostgresError) as e:
            last_err = e
            await asyncio.sleep(2)
    if _pool is None:
        raise RuntimeError(f"Postgres not reachable after 60s: {last_err}")
    async with _pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS event_feedback (
                id          BIGSERIAL PRIMARY KEY,
                event_id    BIGINT,
                host        TEXT,
                program     TEXT,
                pattern     TEXT NOT NULL,
                verdict     TEXT NOT NULL,
                created_at  TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_feedback_verdict ON event_feedback (verdict);
            CREATE INDEX IF NOT EXISTS idx_feedback_host_program ON event_feedback (host, program);

            CREATE TABLE IF NOT EXISTS snmp_devices (
                id          SERIAL PRIMARY KEY,
                host        TEXT NOT NULL UNIQUE,
                port        INT  NOT NULL DEFAULT 161,
                community   TEXT NOT NULL DEFAULT 'public',
                device_type TEXT NOT NULL DEFAULT 'auto',
                label       TEXT,
                enabled     BOOLEAN NOT NULL DEFAULT TRUE,
                source      TEXT NOT NULL DEFAULT 'manual',
                last_polled TIMESTAMPTZ,
                last_status TEXT,
                last_error  TEXT,
                created_at  TIMESTAMPTZ DEFAULT NOW(),
                updated_at  TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_snmp_devices_enabled ON snmp_devices (enabled);

            CREATE TABLE IF NOT EXISTS host_metadata (
                host        TEXT PRIMARY KEY,
                host_type   TEXT NOT NULL DEFAULT 'auto',
                tags        TEXT[] NOT NULL DEFAULT '{}',
                notes       TEXT,
                pinned      BOOLEAN NOT NULL DEFAULT FALSE,
                created_at  TIMESTAMPTZ DEFAULT NOW(),
                updated_at  TIMESTAMPTZ DEFAULT NOW()
            );
            ALTER TABLE host_metadata ADD COLUMN IF NOT EXISTS host_type TEXT NOT NULL DEFAULT 'auto';
            CREATE INDEX IF NOT EXISTS idx_host_metadata_pinned ON host_metadata (pinned) WHERE pinned;
            CREATE INDEX IF NOT EXISTS idx_host_metadata_tags   ON host_metadata USING GIN (tags);
            CREATE INDEX IF NOT EXISTS idx_host_metadata_type   ON host_metadata (host_type);

            CREATE TABLE IF NOT EXISTS topology_nodes (
                host        TEXT PRIMARY KEY,
                label       TEXT,
                icon        TEXT NOT NULL DEFAULT 'server',
                color       TEXT,
                x           REAL,
                y           REAL,
                pinned      BOOLEAN NOT NULL DEFAULT FALSE,
                notes       TEXT,
                created_at  TIMESTAMPTZ DEFAULT NOW(),
                updated_at  TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS topology_edges (
                id          SERIAL PRIMARY KEY,
                from_host   TEXT NOT NULL,
                to_host     TEXT NOT NULL,
                label       TEXT,
                color       TEXT,
                weight      REAL NOT NULL DEFAULT 1.0,
                auto        BOOLEAN NOT NULL DEFAULT FALSE,
                created_at  TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE (from_host, to_host)
            );
            CREATE INDEX IF NOT EXISTS idx_topology_edges_from ON topology_edges (from_host);
            CREATE INDEX IF NOT EXISTS idx_topology_edges_to   ON topology_edges (to_host);

            CREATE TABLE IF NOT EXISTS retention_policies (
                id              SERIAL PRIMARY KEY,
                name            TEXT NOT NULL UNIQUE,
                table_name      TEXT NOT NULL,
                filter_clause   TEXT,
                retention_days  INT  NOT NULL,
                enabled         BOOLEAN NOT NULL DEFAULT TRUE,
                last_run        TIMESTAMPTZ,
                last_deleted    BIGINT NOT NULL DEFAULT 0,
                created_at      TIMESTAMPTZ DEFAULT NOW(),
                updated_at      TIMESTAMPTZ DEFAULT NOW()
            );

            INSERT INTO retention_policies (name, table_name, filter_clause, retention_days) VALUES
                ('events_drop',       'events',           'verdict = ''drop''',                         7),
                ('events_store',      'events',           'verdict = ''store''',                        30),
                ('events_keep',       'events',           'verdict = ''keep''',                         90),
                ('alerts_old',        'alerts',           'acknowledged = TRUE OR severity = ''info''', 365),
                ('snmp_metrics_old',  'snmp_metrics',     NULL,                                          90),
                ('memory_summaries',  'memory_summaries', NULL,                                          365)
            ON CONFLICT (name) DO NOTHING;

            -- Chat tables — safety net for upgrades from a DB that predates them.
            -- A clean deploy already gets these from postgres/init.sql.
            CREATE TABLE IF NOT EXISTS chat_sessions (
                id          UUID PRIMARY KEY,
                title       TEXT NOT NULL DEFAULT 'New conversation',
                created_at  TIMESTAMPTZ DEFAULT NOW(),
                updated_at  TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS chat_messages (
                id              BIGSERIAL PRIMARY KEY,
                session_id      UUID NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
                role            TEXT NOT NULL,
                content         TEXT NOT NULL,
                context_summary TEXT,
                created_at      TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_chat_messages_session
                ON chat_messages (session_id, created_at);
            -- Store which chat mode was used per message (quick/deep)
            ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS mode TEXT DEFAULT 'quick';

            -- Topology tables (may be created by processor; ensure they exist here too)
            CREATE TABLE IF NOT EXISTS host_ip_map (
                ip          TEXT        NOT NULL,
                host        TEXT        NOT NULL,
                confidence  FLOAT       NOT NULL DEFAULT 1.0,
                source      TEXT        NOT NULL DEFAULT 'unknown',
                first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (ip, host)
            );
            CREATE INDEX IF NOT EXISTS idx_host_ip_map_ip   ON host_ip_map (ip);
            CREATE INDEX IF NOT EXISTS idx_host_ip_map_host ON host_ip_map (host);

            CREATE TABLE IF NOT EXISTS topology_learned (
                id           SERIAL PRIMARY KEY,
                src_host     TEXT        NOT NULL,
                dst_host     TEXT        NOT NULL,
                relationship TEXT        NOT NULL,
                evidence     TEXT,
                confidence   FLOAT       NOT NULL DEFAULT 0.5,
                event_count  INT         NOT NULL DEFAULT 1,
                first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (src_host, dst_host, relationship)
            );
            CREATE INDEX IF NOT EXISTS idx_topology_src ON topology_learned (src_host);

            -- Speed up the "last N hours + severity filter" queries that the
            -- dashboard, chat context, and log browser hit on every page load.
            -- (timestamp DESC, severity) lets the planner satisfy both the
            -- range scan and the severity filter from the index alone.
            CREATE INDEX IF NOT EXISTS idx_events_ts_sev
                ON events (timestamp DESC, severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_unacked_ls
                ON alerts (last_seen DESC) WHERE NOT acknowledged;
        """)
    _redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    _http = httpx.AsyncClient(
        limits=httpx.Limits(
            max_connections=OLLAMA_MAX_CONCURRENT,
            max_keepalive_connections=OLLAMA_MAX_CONCURRENT,
            keepalive_expiry=600.0,
        ),
        timeout=httpx.Timeout(300.0, connect=5.0),
    )

    app.state.pool = _pool
    app.state.redis = _redis
    app.state.http = _http

    observability.install(app, OLLAMA_URL, LOKI_URL)
    await auth.bootstrap_admin(_pool)

    global _docker
    if docker_sdk is not None:
        try:
            _docker = docker_sdk.from_env()
            _docker.ping()
        except Exception as e:
            _docker = None
            print(f"[web] docker socket unavailable: {e}")


_AUTH_OPEN_PATHS = {"/login", "/healthz", "/readyz", "/metrics"}


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if path in _AUTH_OPEN_PATHS or path.startswith("/static"):
        return await call_next(request)
    try:
        principal = await auth.current_user(request)
        request.state.user = principal
    except HTTPException:
        if path.startswith("/api/"):
            raise
        return RedirectResponse("/login", status_code=303)
    if request.method in auth.CSRF_METHODS:
        await auth.csrf_guard(request)
    response = await call_next(request)
    return response


@app.on_event("shutdown")
async def shutdown():
    if _pool:
        await _pool.close()
    if _redis:
        await _redis.aclose()
    if _http:
        await _http.aclose()


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    await auth.rate_limit(request, "login", 10, 60)
    ip = auth._client_ip(request)
    ua = request.headers.get("user-agent")
    result = await auth.login_user(_pool, username, password, ip, ua)
    if result is None:
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "Invalid credentials",
        }, status_code=401)
    cookie_val, principal = result
    await auth.audit(_pool, principal, "login", ip=ip)
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(
        auth.SESSION_COOKIE, cookie_val, httponly=True, samesite="lax",
        max_age=int(auth.SESSION_LIFETIME.total_seconds()),
    )
    csrf = auth.issue_csrf_token()
    auth.set_csrf_cookie(resp, csrf)
    return resp


@app.post("/logout")
async def logout_submit(request: Request):
    cookie_val = request.cookies.get(auth.SESSION_COOKIE)
    if cookie_val:
        await auth.logout_session(_pool, cookie_val)
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(auth.SESSION_COOKIE)
    resp.delete_cookie(auth.CSRF_COOKIE)
    return resp


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


@app.get("/api/event-rate")
async def event_rate(hours: int = Query(default=4, le=24)):
    """Per-minute event counts for the last N hours. Used for dashboard sparkline."""
    async with _pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT date_trunc('minute', timestamp) AS minute,
                   COUNT(*) AS cnt,
                   COUNT(*) FILTER (WHERE severity IN ('emerg','alert','crit','err','error')) AS errors
            FROM events
            WHERE timestamp > NOW() - ($1 * INTERVAL '1 hour')
            GROUP BY 1 ORDER BY 1
        """, hours)
    return JSONResponse({
        "points": [
            {"t": r["minute"].isoformat(), "count": r["cnt"], "errors": r["errors"]}
            for r in rows
        ]
    })


@app.get("/api/stream")
async def stream():
    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ── WebSocket live feed with filtering ────────────────────────────────────────

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    """WebSocket live event feed. Client can send JSON filter commands:
      {"filter": {"host": "router", "severity": "err", "search": "ssh"}}
      {"filter": null}  — clear filters
    """
    await websocket.accept()
    filters: dict = {}

    async def _reader():
        nonlocal filters
        try:
            while True:
                msg = await websocket.receive_json()
                if "filter" in msg:
                    filters = msg["filter"] or {}
        except (WebSocketDisconnect, Exception):
            pass

    async def _writer():
        pubsub = _redis.pubsub()
        await pubsub.subscribe("loglm:events")
        try:
            while True:
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg and msg["type"] == "message":
                    try:
                        event = json.loads(msg["data"])
                    except json.JSONDecodeError:
                        continue
                    if _ws_matches(event, filters):
                        await websocket.send_text(msg["data"])
                else:
                    await websocket.send_text('{"keepalive":true}')
                await asyncio.sleep(0.05)
        finally:
            await pubsub.unsubscribe("loglm:events")
            await pubsub.aclose()

    reader_task = asyncio.create_task(_reader())
    try:
        await _writer()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        reader_task.cancel()


def _ws_matches(event: dict, filters: dict) -> bool:
    if not filters:
        return True
    host_f = filters.get("host", "").lower()
    if host_f and host_f not in (event.get("host") or "").lower():
        return False
    sev_f = filters.get("severity", "").lower()
    if sev_f and (event.get("severity") or "").lower() != sev_f:
        return False
    search_f = filters.get("search", "").lower()
    if search_f and search_f not in (event.get("message") or "").lower():
        return False
    program_f = filters.get("program", "").lower()
    if program_f and program_f not in (event.get("program") or "").lower():
        return False
    return True


# ── Stats API ─────────────────────────────────────────────────────────────────

# Cache stats for STATS_TTL seconds so repeated UI polls + chat context reuse
# the same fetch. 500K-row events table scans are expensive; refreshing once
# every 10s is plenty fresh for a dashboard.
_STATS_CACHE: dict = {"ts": 0.0, "data": None}
_STATS_TTL = float(os.environ.get("STATS_CACHE_TTL", "10"))
_stats_lock = asyncio.Lock()


async def _fetch_stats() -> dict:
    """Bounded stats query: uses WHERE timestamp > NOW() - 24h so the planner
    can use the timestamp index instead of scanning the entire events table."""
    async with _pool.acquire() as conn:
        counts = await conn.fetchrow("""
            SELECT
                COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '1 hour') AS events_1h,
                COUNT(*)                                                       AS events_24h,
                COUNT(*) FILTER (WHERE severity IN ('emerg','alert','crit','err','error')) AS errors_24h
            FROM events
            WHERE timestamp > NOW() - INTERVAL '24 hours'
        """)
        alert_counts = await conn.fetchrow("""
            SELECT
                COUNT(*) FILTER (WHERE NOT acknowledged) AS unacked,
                COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '24 hours') AS today
            FROM alerts
        """)
    return {
        "events_1h":     counts["events_1h"],
        "events_24h":    counts["events_24h"],
        "errors_24h":    counts["errors_24h"],
        "alerts_unacked": alert_counts["unacked"],
        "alerts_today":  alert_counts["today"],
    }


async def _cached_stats() -> dict:
    now = asyncio.get_running_loop().time()
    if _STATS_CACHE["data"] is not None and now - _STATS_CACHE["ts"] < _STATS_TTL:
        return _STATS_CACHE["data"]
    async with _stats_lock:
        # Double-check under lock in case another caller populated while we waited.
        now = asyncio.get_running_loop().time()
        if _STATS_CACHE["data"] is not None and now - _STATS_CACHE["ts"] < _STATS_TTL:
            return _STATS_CACHE["data"]
        try:
            data = await _fetch_stats()
            _STATS_CACHE["data"] = data
            _STATS_CACHE["ts"] = now
            return data
        except Exception as e:
            # If the fresh fetch fails, serve stale data so the UI doesn't brick.
            if _STATS_CACHE["data"] is not None:
                return _STATS_CACHE["data"]
            raise


@app.get("/api/stats")
async def stats():
    return await _cached_stats()


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    async with _pool.acquire() as conn:
        recent_alerts = await conn.fetch("""
            SELECT id, timestamp, severity, title, description,
                   affected_hosts, acknowledged, seen_count, last_seen
            FROM alerts ORDER BY COALESCE(last_seen, timestamp) DESC LIMIT 10
        """)
        # Active warnings: unacked alerts in the last 24h, one card per host+title.
        # Used by the "Systems with active warnings" panel.
        warnings = await conn.fetch("""
            SELECT id, severity, title, description, affected_hosts,
                   seen_count, last_seen, recommended_action
            FROM alerts
            WHERE NOT acknowledged
              AND COALESCE(last_seen, timestamp) > NOW() - INTERVAL '24 hours'
            ORDER BY
              CASE severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4
              END,
              COALESCE(last_seen, timestamp) DESC
            LIMIT 12
        """)
        service_statuses = await conn.fetch("""
            SELECT s.service_name, s.host, s.status, s.last_event, s.last_message, a.alias
            FROM service_status s
            LEFT JOIN service_aliases a ON a.raw_name = s.host
            ORDER BY s.status DESC, s.service_name
        """)
        recent_events = await conn.fetch("""
            SELECT id, timestamp, host, source, severity, program, message
            FROM events WHERE verdict = 'keep'
            ORDER BY timestamp DESC LIMIT 50
        """)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "alerts": [dict(r) for r in recent_alerts],
        "warnings": [dict(r) for r in warnings],
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
            f"SELECT id, timestamp, host, source, severity, program, message FROM events "
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
            "SELECT * FROM alerts ORDER BY COALESCE(last_seen, timestamp) DESC LIMIT $1 OFFSET $2",
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
    # Bust cached stats + chat context so UI counters update immediately.
    _STATS_CACHE["data"] = None
    return JSONResponse({"ok": True})


@app.get("/api/warnings")
async def api_warnings():
    """Dashboard active-warnings feed. Returned as JSON so the dashboard can
    poll and re-render the warnings grid without a full page reload."""
    async with _pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, severity, title, description, affected_hosts,
                   seen_count, last_seen, recommended_action, timestamp
            FROM alerts
            WHERE NOT acknowledged
              AND COALESCE(last_seen, timestamp) > NOW() - INTERVAL '24 hours'
            ORDER BY
              CASE severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4
              END,
              COALESCE(last_seen, timestamp) DESC
            LIMIT 20
        """)
    return JSONResponse(jsonable_encoder([dict(r) for r in rows]))


class AlertIgnoreRequest(BaseModel):
    host: str | None = None       # override; default = all affected_hosts
    program: str | None = None    # optional program scope
    pattern: str | None = None    # optional title/pattern text


@app.post("/api/alerts/{alert_id}/ignore")
async def api_alert_ignore(alert_id: int, req: AlertIgnoreRequest | None = None):
    """Acknowledge the alert AND insert an event_feedback row per affected host
    with verdict='ignore' so future matching events are silently dropped.
    The processor fast-LLM signature cache is invalidated via the pubsub
    channel so the rule takes effect immediately."""
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, title, description, affected_hosts, cooldown_key FROM alerts WHERE id=$1",
            alert_id,
        )
        if not row:
            raise HTTPException(404, "alert not found")

        hosts: list[str] = []
        if req and req.host:
            hosts = [req.host]
        else:
            hosts = list(row["affected_hosts"] or [])
        if not hosts:
            hosts = [""]

        pattern = (req.pattern if req else None) or (row["title"] or "")[:200]
        program = (req.program if req else None) or ""

        for h in hosts:
            await conn.execute(
                """INSERT INTO event_feedback (event_id, host, program, pattern, verdict)
                   VALUES (NULL, $1, $2, $3, 'ignore')""",
                h, program, pattern or "*",
            )

        await conn.execute(
            "UPDATE alerts SET acknowledged=TRUE WHERE id=$1", alert_id,
        )

    cooldown_key = row.get("cooldown_key") or ""
    if cooldown_key:
        try:
            await _redis.sadd("loglm:ignored_alert_keys", cooldown_key)
        except Exception as e:
            print(f"[web] ignored key store failed: {e}")

    try:
        await _redis.publish("loglm:feedback", json.dumps({
            "verdict": "ignore", "alert_id": alert_id,
            "hosts": hosts, "pattern": pattern[:120],
        }))
    except Exception as e:
        print(f"[web] alert-ignore publish failed: {e}")

    _STATS_CACHE["data"] = None
    return JSONResponse({"ok": True, "hosts": hosts, "pattern": pattern})


# ── Natural-language ignore / important rules ─────────────────────────────────

_NL_RULE_SYSTEM = """You are a log monitoring rule parser for a home/SOHO network monitor.
The user will describe, in plain English, what log events they want to IGNORE or mark as IMPORTANT.
Your job is to convert their description into one or more structured rules.

Respond ONLY with valid JSON in this exact schema:
{
  "rules": [
    {
      "verdict": "ignore" | "important",
      "host": "<specific hostname or IP, or empty string for any host>",
      "program": "<specific program/service name, or empty string for any>",
      "pattern": "<substring that would appear in the raw log MESSAGE, or empty string for host-wide>",
      "description": "<one-line human description of what this rule does>"
    }
  ],
  "summary": "<one sentence confirming what rules were created>"
}

Pattern guidance:
- The pattern is matched as a SUBSTRING against raw syslog message text.
- For firewall blocks: use patterns like "UFW BLOCK" or "DROPPED" — NOT alert titles.
- For service noise: use the program name in the program field and leave pattern empty.
- For host-wide suppression: use the host field and leave pattern/program empty.
- Never use alert titles (like "SSH Brute Force") as patterns — use actual log text.
- Firewall outbound blocks from internal devices: pattern="UFW BLOCK", program="kernel"
- For broad categories like "all firewall policy blocks from internal devices",
  create separate rules for common patterns: UFW BLOCK, DROPPED, REJECT.

Examples:
User: "ignore firewall blocks from internal devices"
→ rules: [{verdict:"ignore", host:"", program:"kernel", pattern:"UFW BLOCK", ...},
           {verdict:"ignore", host:"", program:"kernel", pattern:"DROPPED", ...}]

User: "ignore health check noise from nginx"
→ rules: [{verdict:"ignore", host:"", program:"nginx", pattern:"GET /health", ...},
           {verdict:"ignore", host:"", program:"nginx", pattern:"GET /ping", ...}]

User: "flag authentication failures on server1 as important"
→ rules: [{verdict:"important", host:"server1", program:"", pattern:"authentication failure", ...}]
"""


class NLRuleRequest(BaseModel):
    text: str


@app.post("/api/rules/natural")
async def api_natural_rule(req: NLRuleRequest):
    """Parse a plain-English rule description into structured event_feedback rows
    using the LLM, then insert them and notify the processor."""
    if not req.text or len(req.text.strip()) < 5:
        raise HTTPException(400, "rule description too short")

    prompt = f'Create monitoring rules for: "{req.text.strip()}"'
    payload = {
        "model": os.environ.get("OLLAMA_MODEL", "llama3.1:8b-instruct-q4_K_M"),
        "prompt": prompt,
        "system": _NL_RULE_SYSTEM,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1, "num_predict": 400},
    }
    try:
        resp = await _http.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=30)
        resp.raise_for_status()
        body = resp.json()
        text = body.get("response", "").strip()
    except Exception as e:
        raise HTTPException(502, f"LLM unavailable: {e}")

    try:
        start = text.find("{")
        end = text.rfind("}") + 1
        parsed = json.loads(text[start:end]) if start >= 0 else {}
    except Exception:
        raise HTTPException(502, "LLM returned unparseable JSON")

    rules = parsed.get("rules", [])
    if not rules:
        raise HTTPException(422, "LLM could not parse any rules from that description")

    inserted = []
    async with _pool.acquire() as conn:
        for r in rules:
            verdict = r.get("verdict", "ignore")
            if verdict not in ("ignore", "important"):
                continue
            host = (r.get("host") or "")[:100]
            program = (r.get("program") or "")[:100]
            pattern = (r.get("pattern") or "")[:200]
            desc = (r.get("description") or "")[:300]
            if not host and not program and not pattern:
                continue  # skip overly broad empty rule
            row_id = await conn.fetchval(
                """INSERT INTO event_feedback (event_id, host, program, pattern, verdict)
                   VALUES (NULL, $1, $2, $3, $4) RETURNING id""",
                host, program, pattern or "*", verdict,
            )
            inserted.append({"id": row_id, "verdict": verdict, "host": host,
                              "program": program, "pattern": pattern, "description": desc})

    if not inserted:
        raise HTTPException(422, "No valid rules could be created from that description")

    # Notify processor to reload feedback cache immediately.
    try:
        await _redis.publish("loglm:feedback", json.dumps({
            "verdict": "natural_rule", "count": len(inserted),
        }))
    except Exception:
        pass

    return JSONResponse({
        "ok": True,
        "inserted": len(inserted),
        "rules": inserted,
        "summary": parsed.get("summary", f"Created {len(inserted)} rule(s)."),
    })


@app.get("/api/rules")
async def api_rules_list():
    """Return all event_feedback rows for the rules management UI."""
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, host, program, pattern, verdict, created_at "
            "FROM event_feedback ORDER BY created_at DESC LIMIT 200"
        )
    return JSONResponse(jsonable_encoder([dict(r) for r in rows]))


@app.delete("/api/rules/{rule_id}")
async def api_rule_delete(rule_id: int):
    async with _pool.acquire() as conn:
        r = await conn.execute("DELETE FROM event_feedback WHERE id=$1", rule_id)
    if r == "DELETE 0":
        raise HTTPException(404, "rule not found")
    try:
        await _redis.publish("loglm:feedback", json.dumps({"verdict": "rule_deleted", "id": rule_id}))
    except Exception:
        pass
    return JSONResponse({"ok": True})


# ── Topology knowledge API ────────────────────────────────────────────────────

@app.get("/api/topology/learned")
async def api_topology_learned():
    """Return all learned device relationships (ARP, syslog correlation, firewall)."""
    async with _pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT src_host, dst_host, relationship, evidence, confidence,
                   event_count, first_seen, last_seen
            FROM topology_learned
            WHERE confidence >= 0.3
            ORDER BY confidence DESC, event_count DESC
            LIMIT 500
        """)
    return JSONResponse(jsonable_encoder([dict(r) for r in rows]))


@app.get("/api/topology/ip-map")
async def api_topology_ip_map(host: str = ""):
    """Return IP↔hostname mappings, optionally filtered by host."""
    async with _pool.acquire() as conn:
        if host:
            rows = await conn.fetch(
                "SELECT ip, host, source, confidence, last_seen "
                "FROM host_ip_map WHERE host = $1 ORDER BY confidence DESC",
                host,
            )
        else:
            rows = await conn.fetch(
                "SELECT ip, host, source, confidence, last_seen "
                "FROM host_ip_map ORDER BY confidence DESC, last_seen DESC LIMIT 1000"
            )
    return JSONResponse(jsonable_encoder([dict(r) for r in rows]))


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


# ── SNMP metrics / graphs ─────────────────────────────────────────────────────

@app.get("/api/metrics/hosts")
async def api_metrics_hosts():
    async with _pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT host,
                   COALESCE(MAX(sys_name), host) AS sys_name,
                   MAX(timestamp) AS last_seen
            FROM snmp_metrics
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY host
            ORDER BY sys_name
        """)
    return JSONResponse(jsonable_encoder([dict(r) for r in rows]))


@app.get("/api/metrics/{host}")
async def api_metrics_series(host: str, hours: int = Query(6, ge=1, le=168)):
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT timestamp, sys_name, avg_cpu, wifi_clients,
                   interfaces_up, interfaces_down, total_in_bps,
                   total_out_bps, total_errors
            FROM snmp_metrics
            WHERE host = $1 AND timestamp > NOW() - ($2 * INTERVAL '1 hour')
            ORDER BY timestamp ASC
            """,
            host, hours,
        )
    return JSONResponse({
        "host": host,
        "hours": hours,
        "points": [
            {
                "t": r["timestamp"].isoformat(),
                "cpu": r["avg_cpu"],
                "wifi": r["wifi_clients"],
                "if_up": r["interfaces_up"],
                "if_down": r["interfaces_down"],
                "in_bps": r["total_in_bps"],
                "out_bps": r["total_out_bps"],
                "errors": r["total_errors"],
            }
            for r in rows
        ],
    })


@app.get("/metrics", response_class=HTMLResponse)
async def metrics_page(request: Request):
    async with _pool.acquire() as conn:
        hosts = await conn.fetch("""
            SELECT host,
                   COALESCE(MAX(sys_name), host) AS sys_name,
                   MAX(timestamp) AS last_seen
            FROM snmp_metrics
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY host
            ORDER BY sys_name
        """)
    return templates.TemplateResponse("metrics.html", {
        "request": request,
        "hosts": [dict(r) for r in hosts],
    })


# ── Feedback (AI training) ────────────────────────────────────────────────────

class FeedbackRequest(BaseModel):
    event_id: int | None = None
    pattern: str | None = None
    host: str | None = None
    program: str | None = None
    verdict: str  # "important" | "ignore"


@app.post("/api/feedback")
async def api_feedback(req: FeedbackRequest):
    if req.verdict not in ("important", "ignore"):
        raise HTTPException(400, "verdict must be 'important' or 'ignore'")
    async with _pool.acquire() as conn:
        row = None
        if req.event_id:
            row = await conn.fetchrow(
                "SELECT host, program, message FROM events WHERE id=$1", req.event_id,
            )
        host = (row["host"] if row else req.host) or ""
        program = (row["program"] if row else req.program) or ""
        pattern = (req.pattern or (row["message"][:200] if row else "") or "").strip()
        if not pattern and not (host or program):
            raise HTTPException(400, "feedback needs pattern, host, or program")
        await conn.execute(
            """INSERT INTO event_feedback (event_id, host, program, pattern, verdict)
               VALUES ($1,$2,$3,$4,$5)""",
            req.event_id, host, program, pattern or "*", req.verdict,
        )
    # Tell the processor to wipe the fast-LLM signature cache + reload the
    # static feedback rules immediately so the very next matching event is
    # classified against this new feedback.
    try:
        await _redis.publish("loglm:feedback", json.dumps({
            "verdict": req.verdict, "host": host,
            "program": program, "pattern": pattern[:120],
        }))
    except Exception as e:
        print(f"[web] feedback publish failed: {e}")
    return JSONResponse({"ok": True})


@app.get("/api/feedback")
async def api_feedback_list():
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, event_id, host, program, pattern, verdict, created_at "
            "FROM event_feedback ORDER BY created_at DESC LIMIT 200"
        )
    return JSONResponse(jsonable_encoder([dict(r) for r in rows]))


@app.post("/api/feedback/{fb_id}/delete")
async def api_feedback_delete(fb_id: int):
    async with _pool.acquire() as conn:
        await conn.execute("DELETE FROM event_feedback WHERE id=$1", fb_id)
    return JSONResponse({"ok": True})


# ── Firewall flows + anomaly detections ─────────────────────────────────────

@app.get("/api/flows")
async def api_flows(
    hours: int = Query(1, ge=1, le=168),
    concerning: bool = Query(False),
    blocked: bool = Query(False),
    src_ip: str = Query(""),
    limit: int = Query(200, ge=1, le=2000),
):
    """Recent firewall flows. Filterable by time window, concerning flag,
    blocked flag, and source IP for RCA queries."""
    where = ["timestamp > NOW() - INTERVAL '1 hour' * $1"]
    params: list = [hours]
    if concerning:
        where.append("concerning = TRUE")
    if blocked:
        where.append("blocked = TRUE")
    if src_ip:
        params.append(src_ip)
        where.append(f"src_ip = ${len(params)}::inet")
    params.append(limit)
    sql = f"""
        SELECT id, timestamp, host, action, blocked, direction,
               src_ip::text AS src_ip, dst_ip::text AS dst_ip,
               src_port, dst_port, proto, in_iface, out_iface,
               port_name, concerning, concerning_reasons
        FROM firewall_flows
        WHERE {' AND '.join(where)}
        ORDER BY timestamp DESC
        LIMIT ${len(params)}
    """
    try:
        async with _pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
    except Exception as e:
        return JSONResponse({"error": str(e), "flows": []}, status_code=200)
    return JSONResponse(jsonable_encoder([dict(r) for r in rows]))


@app.get("/api/flows/top")
async def api_flows_top(hours: int = Query(1, ge=1, le=168)):
    """Dashboard summary: top blocked sources + top targeted ports + direction counts."""
    try:
        async with _pool.acquire() as conn:
            top_src = await conn.fetch(
                """
                SELECT src_ip::text AS src_ip, COUNT(*) AS hits,
                       COUNT(DISTINCT dst_port) AS ports,
                       COUNT(DISTINCT dst_ip)  AS targets
                FROM firewall_flows
                WHERE timestamp > NOW() - INTERVAL '1 hour' * $1 AND blocked
                GROUP BY src_ip ORDER BY hits DESC LIMIT 10
                """, hours,
            )
            top_ports = await conn.fetch(
                """
                SELECT dst_port, port_name, COUNT(*) AS hits,
                       COUNT(DISTINCT src_ip) AS sources
                FROM firewall_flows
                WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
                  AND blocked AND dst_port IS NOT NULL
                GROUP BY dst_port, port_name ORDER BY hits DESC LIMIT 10
                """, hours,
            )
            directions = await conn.fetch(
                """
                SELECT direction, blocked, COUNT(*) AS n
                FROM firewall_flows
                WHERE timestamp > NOW() - INTERVAL '1 hour' * $1
                GROUP BY direction, blocked
                """, hours,
            )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=200)
    return JSONResponse(jsonable_encoder({
        "top_sources": [dict(r) for r in top_src],
        "top_ports":   [dict(r) for r in top_ports],
        "directions":  [dict(r) for r in directions],
    }))


@app.get("/api/anomalies")
async def api_anomalies(
    hours: int = Query(24, ge=1, le=720),
    kind: str = Query(""),
    unacked: bool = Query(False),
    limit: int = Query(200, ge=1, le=2000),
):
    where = ["timestamp > NOW() - INTERVAL '1 hour' * $1"]
    params: list = [hours]
    if kind:
        params.append(kind)
        where.append(f"kind = ${len(params)}")
    if unacked:
        where.append("acknowledged = FALSE")
    params.append(limit)
    sql = f"""
        SELECT id, timestamp, kind, host, program, signature, severity, title,
               description, sample, baseline, observed, acknowledged
        FROM anomaly_detections
        WHERE {' AND '.join(where)}
        ORDER BY timestamp DESC LIMIT ${len(params)}
    """
    try:
        async with _pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)
    except Exception as e:
        return JSONResponse({"error": str(e), "anomalies": []}, status_code=200)
    return JSONResponse(jsonable_encoder([dict(r) for r in rows]))


@app.post("/api/anomalies/{anom_id}/acknowledge")
async def api_anomaly_ack(anom_id: int):
    try:
        async with _pool.acquire() as conn:
            await conn.execute(
                "UPDATE anomaly_detections SET acknowledged = TRUE WHERE id = $1",
                anom_id,
            )
    except Exception as e:
        raise HTTPException(500, str(e))
    return JSONResponse({"ok": True})


@app.get("/api/signatures/new")
async def api_signatures_new(hours: int = Query(24, ge=1, le=168), limit: int = Query(50, ge=1, le=500)):
    """First-seen log shapes in the last N hours — useful for 'what changed today?'"""
    try:
        async with _pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT host, program, severity, signature, sample_message,
                       first_seen, last_seen, total_count
                FROM event_signatures
                WHERE first_seen > NOW() - INTERVAL '1 hour' * $1
                ORDER BY first_seen DESC LIMIT $2
                """, hours, limit,
            )
    except Exception as e:
        return JSONResponse({"error": str(e), "signatures": []}, status_code=200)
    return JSONResponse(jsonable_encoder([dict(r) for r in rows]))


# ── Server / container logs ───────────────────────────────────────────────────

def _container_status(name: str) -> dict:
    if _docker is None:
        return {"name": name, "status": "unavailable", "state": "?"}
    try:
        c = _docker.containers.get(name)
        return {
            "name": name,
            "status": c.status,
            "state": c.attrs.get("State", {}).get("Status", "?"),
            "started_at": c.attrs.get("State", {}).get("StartedAt", ""),
            "image": (c.image.tags[0] if c.image.tags else c.image.short_id),
        }
    except NotFound:
        return {"name": name, "status": "missing", "state": "missing"}
    except DockerException as e:
        return {"name": name, "status": "error", "state": str(e)[:80]}


@app.get("/api/services")
async def api_services():
    return JSONResponse({
        "docker_available": _docker is not None,
        "services": [_container_status(n) for n in LOGLM_SERVICES],
    })


def _tail_logs_sync(name: str, tail: int) -> str:
    c = _docker.containers.get(name)
    data = c.logs(tail=tail, stdout=True, stderr=True, timestamps=False)
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


# Strip per-occurrence noise so identical errors collapse to one signature.
_LOG_NORMALIZE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"  # rfc3339
    r"|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?"                      # plain dt
    r"|\d{2}:\d{2}:\d{2}(?:\.\d+)?"                                            # time only
    r"|0x[0-9a-fA-F]+"                                                          # hex addr
    r"|\b[0-9a-f]{12,}\b"                                                       # ids/hashes
    r"|\b\d+\b"                                                                  # numbers
)


def _normalize_log_line(line: str) -> str:
    return _LOG_NORMALIZE.sub("#", line).strip()


def _group_log_lines(text: str) -> list[dict]:
    """Collapse identical-after-normalization lines. Order preserved by first sighting."""
    groups: list[dict] = []
    sig_idx: dict[str, int] = {}
    for raw in text.splitlines():
        if not raw.strip():
            continue
        sig = _normalize_log_line(raw)
        if not sig:
            continue
        idx = sig_idx.get(sig)
        if idx is not None:
            g = groups[idx]
            g["count"] += 1
            g["last"] = raw
        else:
            sig_idx[sig] = len(groups)
            groups.append({"sample": raw, "last": raw, "count": 1})
    return groups


@app.get("/api/services/{name}/logs")
async def api_service_logs(name: str, tail: int = Query(200, ge=1, le=5000)):
    if name not in LOGLM_SERVICES:
        raise HTTPException(404, "Unknown service")
    if _docker is None:
        raise HTTPException(503, "Docker socket unavailable")
    try:
        text = await asyncio.to_thread(_tail_logs_sync, name, tail)
        groups = _group_log_lines(text)
        return JSONResponse({
            "name": name,
            "tail": tail,
            "logs": text,
            "groups": groups,
            "raw_lines": sum(g["count"] for g in groups),
            "unique_lines": len(groups),
        })
    except NotFound:
        raise HTTPException(404, f"Container {name} not found")
    except DockerException as e:
        raise HTTPException(500, f"Docker error: {e}")


def _stream_logs_iter(name: str):
    c = _docker.containers.get(name)
    return c.logs(stream=True, follow=True, tail=100, stdout=True, stderr=True)


@app.get("/api/services/{name}/stream")
async def api_service_stream(name: str):
    if name not in LOGLM_SERVICES:
        raise HTTPException(404, "Unknown service")
    if _docker is None:
        raise HTTPException(503, "Docker socket unavailable")

    async def gen():
        loop = asyncio.get_running_loop()
        try:
            stream = await loop.run_in_executor(None, _stream_logs_iter, name)
        except NotFound:
            yield f"event: error\ndata: container {name} not found\n\n"
            return
        except DockerException as e:
            yield f"event: error\ndata: docker error: {e}\n\n"
            return

        def next_chunk():
            try:
                return next(stream)
            except StopIteration:
                return None

        try:
            while True:
                chunk = await loop.run_in_executor(None, next_chunk)
                if chunk is None:
                    break
                text = chunk.decode("utf-8", errors="replace") if isinstance(chunk, bytes) else str(chunk)
                for line in text.splitlines():
                    if line:
                        yield f"data: {json.dumps(line)}\n\n"
        finally:
            try:
                stream.close()
            except Exception:
                pass

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/services", response_class=HTMLResponse)
async def services_page(request: Request):
    return templates.TemplateResponse("services.html", {
        "request": request,
        "services": LOGLM_SERVICES,
        "docker_available": _docker is not None,
    })


# ═════════════════════════════════════════════════════════════════════════════
#  SNMP DEVICES + LIBRENMS
# ═════════════════════════════════════════════════════════════════════════════

DEVICE_TYPES = ["auto", "router", "switch", "ap", "firewall", "server"]


async def _snmp_quick_test(host: str, port: int, community: str) -> tuple[bool, str]:
    """Lazy-import pysnmp so the web container doesn't pay startup cost unless
    a user actually clicks Test. Returns (ok, message)."""
    try:
        try:
            from pysnmp.hlapi.v3arch.asyncio import (
                get_cmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity,
            )
        except ImportError:
            from pysnmp.hlapi.asyncio import (
                getCmd as get_cmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity,
            )
        OID_DESCR = "1.3.6.1.2.1.1.1.0"
        OID_NAME  = "1.3.6.1.2.1.1.5.0"
        ei, es, _ix, vbs = await get_cmd(
            SnmpEngine(),
            CommunityData(community),
            await UdpTransportTarget.create((host, int(port)), timeout=4, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(OID_DESCR)),
            ObjectType(ObjectIdentity(OID_NAME)),
        )
        if ei:
            return False, f"transport error: {ei}"
        if es:
            return False, f"snmp error: {es}"
        descr = ""
        name = host
        for oid, val in vbs:
            if str(oid) == OID_DESCR: descr = str(val)
            if str(oid) == OID_NAME:  name = str(val)
        if not descr:
            return False, "no response (timeout, wrong community, or device unreachable)"
        return True, f"{name}: {descr[:160]}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


class DevicePayload(BaseModel):
    host: str
    port: int = 161
    community: str = "public"
    device_type: str = "auto"
    label: str | None = None
    enabled: bool = True


def _validate_device(p: DevicePayload):
    if not p.host.strip():
        raise HTTPException(400, "host is required")
    if p.device_type not in DEVICE_TYPES:
        raise HTTPException(400, f"device_type must be one of {DEVICE_TYPES}")
    if not (1 <= p.port <= 65535):
        raise HTTPException(400, "port must be 1..65535")


@app.get("/api/devices")
async def api_devices_list():
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, host, port, community, device_type, label, enabled, source, "
            "last_polled, last_status, last_error, created_at, updated_at "
            "FROM snmp_devices ORDER BY host"
        )
    return JSONResponse(jsonable_encoder({"devices": [dict(r) for r in rows]}))


@app.post("/api/devices")
async def api_devices_create(p: DevicePayload):
    _validate_device(p)
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO snmp_devices (host, port, community, device_type, label, enabled, source)
                   VALUES ($1, $2, $3, $4, $5, $6, 'manual')
                   RETURNING id""",
                p.host.strip(), p.port, p.community.strip() or "public",
                p.device_type, (p.label or "").strip() or None, p.enabled,
            )
    except asyncpg.UniqueViolationError:
        raise HTTPException(409, f"device {p.host} already exists")
    return {"id": row["id"]}


@app.put("/api/devices/{device_id}")
async def api_devices_update(device_id: int, p: DevicePayload):
    _validate_device(p)
    async with _pool.acquire() as conn:
        result = await conn.execute(
            """UPDATE snmp_devices
                  SET host=$1, port=$2, community=$3, device_type=$4,
                      label=$5, enabled=$6, updated_at=NOW()
                WHERE id=$7""",
            p.host.strip(), p.port, p.community.strip() or "public",
            p.device_type, (p.label or "").strip() or None, p.enabled, device_id,
        )
    if result.endswith(" 0"):
        raise HTTPException(404, "device not found")
    return {"ok": True}


@app.delete("/api/devices/{device_id}")
async def api_devices_delete(device_id: int):
    async with _pool.acquire() as conn:
        result = await conn.execute("DELETE FROM snmp_devices WHERE id=$1", device_id)
    if result.endswith(" 0"):
        raise HTTPException(404, "device not found")
    return {"ok": True}


@app.post("/api/devices/test")
async def api_devices_test(p: DevicePayload):
    _validate_device(p)
    ok, msg = await _snmp_quick_test(p.host.strip(), p.port, p.community or "public")
    return {"ok": ok, "message": msg}


@app.post("/api/devices/{device_id}/test")
async def api_devices_test_existing(device_id: int):
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT host, port, community FROM snmp_devices WHERE id=$1", device_id)
    if not row:
        raise HTTPException(404, "device not found")
    ok, msg = await _snmp_quick_test(row["host"], row["port"], row["community"])
    async with _pool.acquire() as conn:
        await conn.execute(
            "UPDATE snmp_devices SET last_polled=NOW(), last_status=$1, last_error=$2 WHERE id=$3",
            "ok" if ok else "error", None if ok else msg, device_id,
        )
    return {"ok": ok, "message": msg}


# ── LibreNMS integration ──────────────────────────────────────────────────────

def _libre_settings(override_url: str | None = None,
                     override_token: str | None = None) -> tuple[str, str]:
    url = (override_url or LIBRENMS_URL).rstrip("/")
    token = override_token or LIBRENMS_TOKEN
    return url, token


@app.get("/api/librenms/status")
async def api_librenms_status():
    url, token = _libre_settings()
    return {"configured": bool(url and token), "url": url}


class LibrePayload(BaseModel):
    url: str | None = None
    token: str | None = None


@app.post("/api/librenms/test")
async def api_librenms_test(p: LibrePayload):
    url, token = _libre_settings(p.url, p.token)
    if not url or not token:
        raise HTTPException(400, "LibreNMS URL and token required")
    try:
        r = await _http.get(
            f"{url}/api/v0/devices",
            headers={"X-Auth-Token": token},
            timeout=10,
        )
        if r.status_code != 200:
            return {"ok": False, "message": f"HTTP {r.status_code}: {r.text[:160]}"}
        data = r.json()
        count = len(data.get("devices", []))
        return {"ok": True, "message": f"reachable — {count} devices in inventory"}
    except Exception as e:
        return {"ok": False, "message": f"{type(e).__name__}: {e}"}


def _map_librenms_type(t: str) -> str:
    t = (t or "").lower()
    if t in ("network", "router"): return "router"
    if t == "firewall": return "firewall"
    if t in ("server", "linux", "unix", "windows"): return "server"
    if t in ("wireless", "ap"):  return "ap"
    if t == "switch": return "switch"
    return "auto"


@app.post("/api/librenms/sync")
async def api_librenms_sync(p: LibrePayload):
    """Pull devices from LibreNMS and upsert into snmp_devices."""
    url, token = _libre_settings(p.url, p.token)
    if not url or not token:
        raise HTTPException(400, "LibreNMS URL and token required")
    try:
        r = await _http.get(
            f"{url}/api/v0/devices",
            headers={"X-Auth-Token": token},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        raise HTTPException(502, f"LibreNMS fetch failed: {e}")

    devices = data.get("devices", [])
    inserted = updated = 0
    async with _pool.acquire() as conn:
        for d in devices:
            host = d.get("hostname") or d.get("ip")
            if not host:
                continue
            community = d.get("community") or "public"
            label = d.get("sysName") or d.get("display") or d.get("hostname")
            device_type = _map_librenms_type(d.get("type") or d.get("os") or "")
            port = int(d.get("port") or 161)
            existing = await conn.fetchrow(
                "SELECT id, source FROM snmp_devices WHERE host=$1", host)
            if existing:
                # Don't clobber a manually-added device's settings; just refresh label.
                if existing["source"] == "manual":
                    await conn.execute(
                        "UPDATE snmp_devices SET label=COALESCE(label, $1), updated_at=NOW() WHERE id=$2",
                        label, existing["id"],
                    )
                else:
                    await conn.execute(
                        """UPDATE snmp_devices
                              SET port=$1, community=$2, device_type=$3, label=$4,
                                  source='librenms', updated_at=NOW()
                            WHERE id=$5""",
                        port, community, device_type, label, existing["id"],
                    )
                updated += 1
            else:
                await conn.execute(
                    """INSERT INTO snmp_devices (host, port, community, device_type,
                                                  label, enabled, source)
                       VALUES ($1, $2, $3, $4, $5, TRUE, 'librenms')""",
                    host, port, community, device_type, label,
                )
                inserted += 1
    return {"ok": True, "inserted": inserted, "updated": updated, "total": len(devices)}


@app.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request):
    return templates.TemplateResponse("devices.html", {
        "request": request,
        "device_types": DEVICE_TYPES,
        "librenms_configured": bool(LIBRENMS_URL and LIBRENMS_TOKEN),
        "librenms_url": LIBRENMS_URL,
    })


# ═════════════════════════════════════════════════════════════════════════════
#  HOSTS — per-host page, custom tags, notes
# ═════════════════════════════════════════════════════════════════════════════

# Hostnames in URLs may contain dots/colons; we accept anything but block
# obviously dangerous characters.
_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-]+$")


def _safe_host(host: str) -> str:
    host = (host or "").strip()
    if not host or len(host) > 255 or not _HOST_RE.match(host):
        raise HTTPException(400, "invalid host")
    return host


HOST_TYPES = ["auto", "router", "firewall", "switch", "ap", "server", "nas", "nginx", "container", "other"]


class HostMetadataPayload(BaseModel):
    tags: list[str] | None = None
    notes: str | None = None
    pinned: bool | None = None
    host_type: str | None = None


async def _get_host_metadata(conn: asyncpg.Connection, host: str) -> dict:
    row = await conn.fetchrow(
        "SELECT host, host_type, tags, notes, pinned, created_at, updated_at "
        "FROM host_metadata WHERE host = $1",
        host,
    )
    if row:
        return dict(row)
    return {"host": host, "host_type": "auto", "tags": [], "notes": None, "pinned": False}


@app.get("/api/hosts")
async def api_hosts_list():
    """Union of every host we know about: events, snmp_devices, host_metadata.
    Returns recent activity so the UI can sort by last-seen."""
    async with _pool.acquire() as conn:
        rows = await conn.fetch("""
            WITH known AS (
                SELECT host FROM host_metadata
                UNION
                SELECT host FROM snmp_devices
                UNION
                SELECT DISTINCT host FROM events
                WHERE timestamp > NOW() - INTERVAL '24 hours'
            )
            SELECT
                k.host,
                hm.tags,
                hm.pinned,
                hm.notes,
                COALESCE(a.alias, NULL) AS alias,
                d.device_type,
                d.label AS device_label,
                d.last_status,
                (SELECT MAX(timestamp) FROM events e WHERE e.host = k.host) AS last_event,
                (SELECT COUNT(*) FROM events e
                  WHERE e.host = k.host
                    AND e.severity IN ('emerg','alert','crit','err','error','warning')
                    AND e.timestamp > NOW() - INTERVAL '24 hours') AS warn_24h
            FROM known k
            LEFT JOIN host_metadata    hm ON hm.host = k.host
            LEFT JOIN service_aliases  a  ON a.raw_name = k.host
            LEFT JOIN snmp_devices     d  ON d.host = k.host
            ORDER BY hm.pinned DESC NULLS LAST, last_event DESC NULLS LAST
        """)
    return JSONResponse(jsonable_encoder([dict(r) for r in rows]))


@app.get("/api/hosts/tags")
async def api_hosts_tag_index():
    """All distinct tags currently in use, with count, for the tag sidebar."""
    async with _pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT tag, COUNT(*) AS hosts
            FROM host_metadata, UNNEST(tags) AS tag
            GROUP BY tag
            ORDER BY tag
        """)
    return JSONResponse(jsonable_encoder([dict(r) for r in rows]))


@app.get("/api/host/{host}/summary")
async def api_host_summary(host: str):
    host = _safe_host(host)
    async with _pool.acquire() as conn:
        meta = await _get_host_metadata(conn, host)
        device = await conn.fetchrow(
            "SELECT id, host, port, community, device_type, label, enabled, "
            "       source, last_polled, last_status, last_error "
            "FROM snmp_devices WHERE host = $1",
            host,
        )
        alias = await conn.fetchval("SELECT alias FROM service_aliases WHERE raw_name=$1", host)
        recent_events = await conn.fetch(
            "SELECT id, timestamp, source, severity, program, message, verdict "
            "FROM events WHERE host = $1 "
            "ORDER BY timestamp DESC LIMIT 100",
            host,
        )
        active_alerts = await conn.fetch(
            "SELECT id, timestamp, last_seen, severity, title, description, seen_count, acknowledged "
            "FROM alerts WHERE $1 = ANY(affected_hosts) "
            "  AND COALESCE(last_seen, timestamp) > NOW() - INTERVAL '7 days' "
            "ORDER BY last_seen DESC NULLS LAST, timestamp DESC LIMIT 25",
            host,
        )
        stats = await conn.fetchrow("""
            SELECT
                COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '1 hour')  AS events_1h,
                COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '24 hours') AS events_24h,
                COUNT(*) FILTER (WHERE severity IN ('emerg','alert','crit','err','error')
                                   AND timestamp > NOW() - INTERVAL '24 hours') AS errors_24h,
                MAX(timestamp) AS last_event
            FROM events WHERE host = $1
        """, host)
        snmp_latest = await conn.fetchrow("""
            SELECT timestamp, sys_name, avg_cpu, wifi_clients,
                   interfaces_up, interfaces_down, total_in_bps, total_out_bps,
                   total_errors, raw_data
            FROM snmp_metrics WHERE host = $1
            ORDER BY timestamp DESC LIMIT 1
        """, host)

    snmp_dict = None
    if snmp_latest:
        snmp_dict = dict(snmp_latest)
        # Promote sfp_sensors + interface details out of raw_data for easy rendering
        raw = snmp_dict.pop("raw_data", None)
        if raw:
            if isinstance(raw, str):
                import json as _json
                try:
                    raw = _json.loads(raw)
                except Exception:
                    raw = {}
            snmp_dict["sfp_sensors"] = raw.get("sfp_sensors", [])
            snmp_dict["interfaces"]  = raw.get("interfaces", {})

    return JSONResponse(jsonable_encoder({
        "host": host,
        "alias": alias,
        "metadata": meta,
        "device": dict(device) if device else None,
        "stats": dict(stats) if stats else {},
        "snmp_latest": snmp_dict,
        "events": [dict(r) for r in recent_events],
        "alerts": [dict(r) for r in active_alerts],
    }))


@app.put("/api/host/{host}/metadata")
async def api_host_metadata_update(host: str, p: HostMetadataPayload):
    host = _safe_host(host)
    # Normalize tags: strip, lowercase, dedupe.
    tags = None
    if p.tags is not None:
        tags = sorted({t.strip().lower() for t in p.tags if t and t.strip()})
    async with _pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT 1 FROM host_metadata WHERE host=$1", host)
        host_type = p.host_type if p.host_type in HOST_TYPES else None
        if existing is None:
            await conn.execute(
                """INSERT INTO host_metadata (host, host_type, tags, notes, pinned)
                   VALUES ($1, $2, $3, $4, $5)""",
                host,
                host_type or "auto",
                tags or [],
                p.notes,
                bool(p.pinned),
            )
        else:
            sets = []
            args: list = []
            n = 1
            if host_type is not None:
                sets.append(f"host_type = ${n}"); args.append(host_type); n += 1
            if tags is not None:
                sets.append(f"tags = ${n}"); args.append(tags); n += 1
            if p.notes is not None:
                sets.append(f"notes = ${n}"); args.append(p.notes); n += 1
            if p.pinned is not None:
                sets.append(f"pinned = ${n}"); args.append(bool(p.pinned)); n += 1
            if sets:
                sets.append("updated_at = NOW()")
                args.append(host)
                await conn.execute(
                    f"UPDATE host_metadata SET {', '.join(sets)} WHERE host = ${n}",
                    *args,
                )
        meta = await _get_host_metadata(conn, host)
    return JSONResponse(jsonable_encoder(meta))


@app.get("/host/{host}", response_class=HTMLResponse)
async def host_page(request: Request, host: str):
    host = _safe_host(host)
    return templates.TemplateResponse("host.html", {
        "request": request,
        "host": host,
        "host_types": HOST_TYPES,
    })


# ═════════════════════════════════════════════════════════════════════════════
#  TOPOLOGY — node/edge graph with auto-discovery + customisable layout
# ═════════════════════════════════════════════════════════════════════════════

TOPOLOGY_ICONS = ["server", "router", "switch", "ap", "firewall", "cloud", "device"]


def _icon_for_device_type(device_type: str | None) -> str:
    dt = (device_type or "").lower()
    if dt in TOPOLOGY_ICONS:
        return dt
    return "server"


class TopologyNodePayload(BaseModel):
    host: str
    label: str | None = None
    icon: str | None = None
    color: str | None = None
    x: float | None = None
    y: float | None = None
    pinned: bool | None = None
    notes: str | None = None


class TopologyEdgePayload(BaseModel):
    from_host: str
    to_host: str
    label: str | None = None
    color: str | None = None
    weight: float | None = None


@app.get("/api/topology")
async def api_topology():
    """Return the saved topology + auto-promote any known hosts that don't yet
    have a node row. Auto-rows are virtual until the user moves them.

    Dedupes by host across topology_nodes/snmp_devices/host_metadata so the
    vis-network DataSet never sees a duplicate id (which would error the page)."""
    async with _pool.acquire() as conn:
        nodes = await conn.fetch(
            "SELECT host, label, icon, color, x, y, pinned, notes FROM topology_nodes"
        )
        edges = await conn.fetch(
            "SELECT id, from_host, to_host, label, color, weight, auto FROM topology_edges"
        )
        # Known hosts from other tables. Use separate fetches so we can dedupe
        # in Python and not worry about UNION column-compat edge cases.
        snmp_hosts = await conn.fetch(
            "SELECT host, device_type, COALESCE(label, host) AS label FROM snmp_devices"
        )
        meta_hosts = await conn.fetch("SELECT host FROM host_metadata")

    # 1) Start with the real topology_nodes rows, keyed by host.
    by_host: dict[str, dict] = {}
    for r in nodes:
        d = dict(r)
        if not d.get("host"):
            continue
        d["auto"] = False
        by_host[d["host"]] = d

    # 2) Auto-promote snmp_devices that don't yet have a topology_node row.
    for r in snmp_hosts:
        h = r["host"]
        if not h or h in by_host:
            continue
        by_host[h] = {
            "host":   h,
            "label":  r["label"] or h,
            "icon":   _icon_for_device_type(r.get("device_type")),
            "color":  None,
            "x":      None,
            "y":      None,
            "pinned": False,
            "notes":  None,
            "auto":   True,
        }

    # 3) Auto-promote host_metadata rows that neither of the above covers.
    for r in meta_hosts:
        h = r["host"]
        if not h or h in by_host:
            continue
        by_host[h] = {
            "host":   h,
            "label":  h,
            "icon":   "server",
            "color":  None,
            "x":      None,
            "y":      None,
            "pinned": False,
            "notes":  None,
            "auto":   True,
        }

    # 4) Filter edges so we never emit one whose endpoints don't exist as nodes
    # (that would also break the vis-network DataSet).
    edges_out = []
    for r in edges:
        d = dict(r)
        if d.get("from_host") in by_host and d.get("to_host") in by_host:
            edges_out.append(d)

    return JSONResponse(jsonable_encoder({
        "nodes": list(by_host.values()),
        "edges": edges_out,
    }))


@app.put("/api/topology/node")
async def api_topology_node_upsert(p: TopologyNodePayload):
    host = _safe_host(p.host)
    icon = (p.icon or "server").lower()
    if icon not in TOPOLOGY_ICONS:
        icon = "server"
    async with _pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO topology_nodes (host, label, icon, color, x, y, pinned, notes)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               ON CONFLICT (host) DO UPDATE
                 SET label  = COALESCE(EXCLUDED.label,  topology_nodes.label),
                     icon   = EXCLUDED.icon,
                     color  = COALESCE(EXCLUDED.color,  topology_nodes.color),
                     x      = COALESCE(EXCLUDED.x,      topology_nodes.x),
                     y      = COALESCE(EXCLUDED.y,      topology_nodes.y),
                     pinned = COALESCE(EXCLUDED.pinned, topology_nodes.pinned),
                     notes  = COALESCE(EXCLUDED.notes,  topology_nodes.notes),
                     updated_at = NOW()""",
            host, p.label, icon, p.color, p.x, p.y,
            bool(p.pinned) if p.pinned is not None else False,
            p.notes,
        )
    return {"ok": True}


@app.delete("/api/topology/node/{host}")
async def api_topology_node_delete(host: str):
    host = _safe_host(host)
    async with _pool.acquire() as conn:
        await conn.execute("DELETE FROM topology_nodes WHERE host = $1", host)
        await conn.execute(
            "DELETE FROM topology_edges WHERE from_host = $1 OR to_host = $1", host)
    return {"ok": True}


@app.post("/api/topology/edge")
async def api_topology_edge_create(p: TopologyEdgePayload):
    a = _safe_host(p.from_host)
    b = _safe_host(p.to_host)
    if a == b:
        raise HTTPException(400, "edge cannot loop on itself")
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO topology_edges (from_host, to_host, label, color, weight, auto)
                   VALUES ($1, $2, $3, $4, $5, FALSE)
                   RETURNING id""",
                a, b, p.label, p.color, p.weight or 1.0,
            )
    except asyncpg.UniqueViolationError:
        raise HTTPException(409, "edge already exists")
    return {"id": row["id"]}


@app.delete("/api/topology/edge/{edge_id}")
async def api_topology_edge_delete(edge_id: int):
    async with _pool.acquire() as conn:
        await conn.execute("DELETE FROM topology_edges WHERE id = $1", edge_id)
    return {"ok": True}


@app.get("/topology", response_class=HTMLResponse)
async def topology_page(request: Request):
    return templates.TemplateResponse("topology.html", {
        "request": request,
        "icons": TOPOLOGY_ICONS,
    })


# ═════════════════════════════════════════════════════════════════════════════
#  RETENTION POLICIES
# ═════════════════════════════════════════════════════════════════════════════

RETENTION_TABLES_ALLOWED = {
    "events":             "timestamp",
    "alerts":             "timestamp",
    "snmp_metrics":       "timestamp",
    "memory_summaries":   "timestamp",
    "firewall_flows":     "timestamp",
    "anomaly_detections": "timestamp",
}

# Filter clauses are admin-editable but get inlined into a DELETE — they
# cannot be parameterized because asyncpg won't templatise an arbitrary WHERE
# fragment. Validate against a tight allowlist + denylist before use.
_FILTER_FORBIDDEN = re.compile(
    r"(?i)(;|--|/\*|\*/|\b("
    r"drop|delete|insert|update|create|alter|grant|revoke|truncate|"
    r"copy|merge|exec|execute|union|attach|detach|do|call|notify|listen|"
    r"into|returning|with"
    r")\b)"
)
_FILTER_ALLOWED_CHARS = re.compile(r"^[A-Za-z0-9_\s'\"=<>!,()\.\-\+]+$")


def _validate_filter_clause(clause: str | None) -> None:
    """Raises HTTPException if the clause is unsafe."""
    if not clause:
        return
    if len(clause) > 500:
        raise HTTPException(400, "filter clause too long (max 500 chars)")
    if _FILTER_FORBIDDEN.search(clause):
        raise HTTPException(400, "filter clause contains forbidden keyword")
    if not _FILTER_ALLOWED_CHARS.match(clause):
        raise HTTPException(400, "filter clause has invalid characters")
    if clause.count("(") != clause.count(")"):
        raise HTTPException(400, "filter clause has unbalanced parens")
    if clause.count("'") % 2 != 0:
        raise HTTPException(400, "filter clause has unbalanced quotes")


class RetentionPayload(BaseModel):
    name: str | None = None
    table_name: str | None = None
    filter_clause: str | None = None
    retention_days: int | None = None
    enabled: bool | None = None


@app.get("/api/retention")
async def api_retention_list():
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, name, table_name, filter_clause, retention_days, enabled, "
            "       last_run, last_deleted, updated_at "
            "FROM retention_policies ORDER BY name"
        )
    return JSONResponse(jsonable_encoder([dict(r) for r in rows]))


@app.post("/api/retention")
async def api_retention_create(p: RetentionPayload):
    if not p.name or not p.table_name or p.retention_days is None:
        raise HTTPException(400, "name, table_name and retention_days are required")
    if p.table_name not in RETENTION_TABLES_ALLOWED:
        raise HTTPException(400, f"table must be one of {sorted(RETENTION_TABLES_ALLOWED)}")
    if p.retention_days < 1:
        raise HTTPException(400, "retention_days must be >= 1")
    _validate_filter_clause(p.filter_clause)
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO retention_policies
                       (name, table_name, filter_clause, retention_days, enabled)
                   VALUES ($1, $2, $3, $4, COALESCE($5, TRUE))
                   RETURNING id""",
                p.name.strip(), p.table_name, p.filter_clause, p.retention_days, p.enabled,
            )
    except asyncpg.UniqueViolationError:
        raise HTTPException(409, f"policy {p.name} already exists")
    return {"id": row["id"]}


@app.put("/api/retention/{policy_id}")
async def api_retention_update(policy_id: int, p: RetentionPayload):
    if p.table_name is not None and p.table_name not in RETENTION_TABLES_ALLOWED:
        raise HTTPException(400, f"table must be one of {sorted(RETENTION_TABLES_ALLOWED)}")
    if p.retention_days is not None and p.retention_days < 1:
        raise HTTPException(400, "retention_days must be >= 1")
    if p.filter_clause is not None:
        _validate_filter_clause(p.filter_clause)
    sets = []
    args: list = []
    n = 1
    for col, val in (
        ("name",          p.name),
        ("table_name",    p.table_name),
        ("filter_clause", p.filter_clause),
        ("retention_days", p.retention_days),
        ("enabled",       p.enabled),
    ):
        if val is not None:
            sets.append(f"{col} = ${n}")
            args.append(val)
            n += 1
    if not sets:
        return {"ok": True}
    sets.append("updated_at = NOW()")
    args.append(policy_id)
    async with _pool.acquire() as conn:
        result = await conn.execute(
            f"UPDATE retention_policies SET {', '.join(sets)} WHERE id = ${n}",
            *args,
        )
    if result.endswith(" 0"):
        raise HTTPException(404, "policy not found")
    return {"ok": True}


@app.delete("/api/retention/{policy_id}")
async def api_retention_delete(policy_id: int):
    async with _pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM retention_policies WHERE id = $1", policy_id)
    if result.endswith(" 0"):
        raise HTTPException(404, "policy not found")
    return {"ok": True}


@app.post("/api/retention/{policy_id}/run")
async def api_retention_run_now(policy_id: int):
    """Apply one policy immediately. Mirrors processor's _run_policy."""
    async with _pool.acquire() as conn:
        policy = await conn.fetchrow(
            "SELECT id, name, table_name, filter_clause, retention_days "
            "FROM retention_policies WHERE id = $1",
            policy_id,
        )
    if not policy:
        raise HTTPException(404, "policy not found")
    table = policy["table_name"]
    if table not in RETENTION_TABLES_ALLOWED:
        raise HTTPException(400, "policy targets an unsupported table")
    ts_col = RETENTION_TABLES_ALLOWED[table]
    days = int(policy["retention_days"])
    if days <= 0:
        raise HTTPException(400, "retention_days must be > 0")
    extra = (policy["filter_clause"] or "").strip()
    _validate_filter_clause(extra)  # re-check stored clause before executing
    where = f"{ts_col} < NOW() - INTERVAL '{days} days'"
    if extra:
        where += f" AND ({extra})"
    sql = (
        f"WITH victims AS ("
        f"  SELECT ctid FROM {table} WHERE {where} LIMIT 5000"
        f") DELETE FROM {table} WHERE ctid IN (SELECT ctid FROM victims)"
    )
    deleted = 0
    async with _pool.acquire() as conn:
        try:
            while True:
                tag = await conn.execute(sql)
                try:
                    n = int(tag.split()[-1])
                except (ValueError, IndexError):
                    n = 0
                deleted += n
                if n < 5000:
                    break
            await conn.execute(
                "UPDATE retention_policies SET last_run=NOW(), last_deleted=$1, updated_at=NOW() WHERE id=$2",
                deleted, policy_id,
            )
        except Exception as e:
            raise HTTPException(500, f"prune failed: {e}")
    return {"ok": True, "deleted": deleted}


@app.get("/retention", response_class=HTMLResponse)
async def retention_page(request: Request):
    return templates.TemplateResponse("retention.html", {
        "request": request,
        "tables": sorted(RETENTION_TABLES_ALLOWED.keys()),
    })


# ── System info: timezone + NTP ───────────────────────────────────────────────

# Mutable in-process NTP hint. Persisted to /data/ntp.conf on change so it
# survives restarts even though the value lives outside the env file.
import time as _time

NTP_STATE_FILE = os.environ.get("NTP_STATE_FILE", "/data/ntp.conf")
_ntp_runtime = NTP_SERVER

try:
    if os.path.exists(NTP_STATE_FILE):
        with open(NTP_STATE_FILE, "r", encoding="utf-8") as _f:
            _saved = _f.read().strip()
            if _saved:
                _ntp_runtime = _saved
except Exception:
    pass


class NtpPayload(BaseModel):
    server: str


@app.get("/api/system/info")
async def api_system_info():
    now = datetime.now()
    return {
        "tz": APP_TZ,
        "tz_offset_minutes": int(_time.timezone / -60) if not _time.daylight else int(_time.altzone / -60),
        "server_time": now.isoformat(),
        "epoch": int(now.timestamp()),
        "ntp_server": _ntp_runtime,
        "ntp_default": NTP_SERVER,
    }


@app.put("/api/system/ntp")
async def api_system_set_ntp(p: NtpPayload):
    global _ntp_runtime
    server = (p.server or "").strip()
    if not server or len(server) > 253:
        raise HTTPException(400, "invalid NTP server")
    # Loose hostname guard (DNS or IPv4).
    if not re.match(r"^[A-Za-z0-9._\-]+$", server):
        raise HTTPException(400, "invalid characters in NTP server")
    _ntp_runtime = server
    try:
        os.makedirs(os.path.dirname(NTP_STATE_FILE), exist_ok=True)
        with open(NTP_STATE_FILE, "w", encoding="utf-8") as f:
            f.write(server + "\n")
    except Exception as e:
        # Persisting is best-effort — value still applies in-process.
        log_msg = f"[web] could not persist NTP server to {NTP_STATE_FILE}: {e}"
        print(log_msg)
    return {"ok": True, "ntp_server": _ntp_runtime,
            "note": "Container clocks come from the host. Configure your "
                    "host OS to sync against this NTP server."}


# ═════════════════════════════════════════════════════════════════════════════
#  CHAT WITH MEMORY
# ═════════════════════════════════════════════════════════════════════════════

CHAT_SYSTEM_QUICK = """You are LogLM Quick, an AI assistant for a home/small-office network monitor.
You have access to memory summaries, current SNMP metrics, recent notable events, and alerts.

Answer concisely in 2-6 sentences. Focus on current state and anything worth acting on.
Reference actual hostnames, IPs, timestamps, and counts.
If something is fine, say so — don't pad with caveats.
Do not make up events or metrics."""

CHAT_SYSTEM_DEEP = """You are LogLM Investigator, a network forensics assistant.
Your job is to trace what happened across all log sources, SNMP data, and device relationships.

When the user asks about an event, incident, or time window:
1. Build a TIMELINE — list events in chronological order across ALL hosts in the window.
   Include info/notice events — they often fill in the story (reconnects, auth successes, etc.)
2. Identify CAUSAL CHAINS — e.g. router rebooted → downstream devices lost link → DHCP renewals.
   Use the topology data to know which devices are upstream/downstream of each other.
3. LINK IPs to hosts — the context includes a host_ip_map. If a log mentions 10.x.x.x,
   look it up and name the actual device. Show your reasoning: "10.20.10.5 = NAS (from ARP/syslog)".
4. Use SNMP data to corroborate — interface counters dropping, CPU spike, link state changes.
5. State your CONFIDENCE — if it's circumstantial, say so. If you can't link two events, say so.

Format:
TIMELINE (chronological)
→ [HH:MM:SS] host: what happened

CAUSAL CHAIN
→ [event A] caused [event B] because [reason]

CONCLUSION
→ What happened, confidence level, recommended follow-up.

Reference actual hostnames, IPs, timestamps. Do not invent data."""

# Backwards-compat alias used in non-chat code paths (analyzer hints etc)
CHAT_SYSTEM = CHAT_SYSTEM_QUICK


_TIME_WINDOW_RE = re.compile(
    r"(?i)\b(?:last|past)\s+(\d+)\s*(minute|minutes|min|hour|hours|hr|day|days)s?\b"
)
_AT_TIME_RE = re.compile(
    r"(?i)\b(?:at|around|near)\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\b"
)


def _extract_time_window(message: str) -> tuple[str, str] | None:
    """Parse 'last 30 minutes', 'past 2 hours', etc. Returns (start_iso, end_iso)
    in UTC or None if the user didn't specify a window."""
    m = _TIME_WINDOW_RE.search(message)
    if m:
        n = int(m.group(1))
        unit = m.group(2).lower()
        delta_sec = n * {"min": 60, "minute": 60, "minutes": 60,
                         "hr": 3600, "hour": 3600, "hours": 3600,
                         "day": 86400, "days": 86400}.get(unit, 60)
        end = datetime.now(timezone.utc)
        start = end - timedelta(seconds=delta_sec)
        return start.isoformat(), end.isoformat()
    return None


_CHAT_CTX_CACHE: dict = {"ts": 0.0, "key": None, "data": None}
_CHAT_CTX_TTL = float(os.environ.get("CHAT_CTX_TTL", "8"))
_chat_ctx_lock = asyncio.Lock()


async def build_chat_context(pool: asyncpg.Pool, redis_client: aioredis.Redis,
                              user_message: str = "") -> str:
    """Gather current state for the LLM's context window.
    If the user asked about a specific time window ('last hour', 'past 30 min'),
    the events section is narrowed to that window and a broader event sample
    is returned so the LLM can RCA the window.

    Cached for CHAT_CTX_TTL seconds on a key that includes the extracted time
    window — so rapid-fire questions about the same period reuse one fetch,
    but a new "last 3 hours" question still forces a fresh read."""
    time_window = _extract_time_window(user_message) if user_message else None
    cache_key = ("window", time_window) if time_window else ("base",)
    now_mono = asyncio.get_running_loop().time()
    if (_CHAT_CTX_CACHE["data"] is not None
            and _CHAT_CTX_CACHE["key"] == cache_key
            and now_mono - _CHAT_CTX_CACHE["ts"] < _CHAT_CTX_TTL):
        return _CHAT_CTX_CACHE["data"]

    async with _chat_ctx_lock:
        now_mono = asyncio.get_running_loop().time()
        if (_CHAT_CTX_CACHE["data"] is not None
                and _CHAT_CTX_CACHE["key"] == cache_key
                and now_mono - _CHAT_CTX_CACHE["ts"] < _CHAT_CTX_TTL):
            return _CHAT_CTX_CACHE["data"]
        try:
            result = await _build_chat_context_inner(pool, user_message, time_window)
        except Exception as e:
            # If the rebuild fails, fall back to stale cache so chat still works.
            if _CHAT_CTX_CACHE["data"] is not None:
                return _CHAT_CTX_CACHE["data"]
            raise
        _CHAT_CTX_CACHE["data"] = result
        _CHAT_CTX_CACHE["ts"] = now_mono
        _CHAT_CTX_CACHE["key"] = cache_key
        return result


async def _build_chat_context_inner(pool: asyncpg.Pool,
                                     user_message: str,
                                     time_window) -> str:
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

        if time_window:
            start_iso, end_iso = time_window
            events = await conn.fetch(
                """
                SELECT timestamp, host, source, severity, message
                FROM events
                WHERE timestamp BETWEEN $1::timestamptz AND $2::timestamptz
                  AND severity IN ('emerg','alert','crit','err','error','warning','notice')
                ORDER BY timestamp DESC LIMIT 60
                """,
                start_iso, end_iso,
            )
            sections.append(f"\n=== EVENTS IN USER-REQUESTED WINDOW ({start_iso} → {end_iso}) ===")
        else:
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

        if not time_window:
            info_sample = await conn.fetch("""
                SELECT timestamp, host, source, severity, message
                FROM events
                WHERE timestamp > NOW() - INTERVAL '1 hour'
                  AND severity IN ('info', 'notice')
                ORDER BY timestamp DESC LIMIT 15
            """)
            if info_sample:
                sections.append("\n=== RECENT NORMAL ACTIVITY (sample, last 1h) ===")
                for e in info_sample:
                    sections.append(
                        f"[{e['timestamp'].strftime('%H:%M:%S')}] {e['severity'].upper()} "
                        f"{e['host']} ({e['source']}): {e['message'][:150]}"
                    )

        # Concerning firewall flows (last 1h). Top-talker summary for RCA.
        try:
            flows = await conn.fetch("""
                SELECT host, src_ip::text AS src_ip, dst_ip::text AS dst_ip,
                       dst_port, port_name, direction, action, blocked,
                       COUNT(*) AS n
                FROM firewall_flows
                WHERE timestamp > NOW() - INTERVAL '1 hour' AND concerning
                GROUP BY host, src_ip, dst_ip, dst_port, port_name, direction, action, blocked
                ORDER BY n DESC LIMIT 15
            """)
            if flows:
                sections.append("\n=== CONCERNING FIREWALL FLOWS (last 1h) ===")
                for f in flows:
                    sections.append(
                        f"  {f['n']}× {f['direction'] or '?'} {f['src_ip']}→{f['dst_ip']}"
                        f":{f['dst_port'] or '?'}/{f['port_name'] or ''} "
                        f"[{f['action']}{'/BLOCKED' if f['blocked'] else ''}] on {f['host']}"
                    )
            # Top blocked source IPs — catches external scanners.
            top_blocked = await conn.fetch("""
                SELECT src_ip::text AS src, COUNT(*) AS n,
                       COUNT(DISTINCT dst_port) AS ports, COUNT(DISTINCT dst_ip) AS targets
                FROM firewall_flows
                WHERE timestamp > NOW() - INTERVAL '1 hour' AND blocked
                GROUP BY src_ip
                ORDER BY n DESC LIMIT 8
            """)
            if top_blocked:
                sections.append("\n=== TOP BLOCKED SOURCES (1h) ===")
                for r in top_blocked:
                    sections.append(
                        f"  {r['src']}: {r['n']} blocked hits, "
                        f"{r['ports']} unique dst-ports, {r['targets']} targets"
                    )
        except Exception as e:
            # firewall_flows table may not exist yet on first run
            pass

        # Anomalies detected by the learning layer (last 24h, unacked)
        try:
            anomalies = await conn.fetch("""
                SELECT timestamp, kind, host, program, title, description,
                       baseline, observed, severity
                FROM anomaly_detections
                WHERE timestamp > NOW() - INTERVAL '24 hours' AND NOT acknowledged
                ORDER BY timestamp DESC LIMIT 15
            """)
            if anomalies:
                sections.append("\n=== LEARNED ANOMALIES (24h, unacked) ===")
                for a in anomalies:
                    extra = ""
                    if a["baseline"] is not None and a["observed"] is not None:
                        extra = f" (baseline={a['baseline']:.1f} observed={a['observed']:.1f})"
                    sections.append(
                        f"[{a['timestamp'].strftime('%H:%M')}] {a['severity'].upper()} "
                        f"{a['kind']} on {a['host']}: {a['title']}{extra}"
                    )
        except Exception:
            pass

        stats = await conn.fetchrow("""
            SELECT
                COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '1 hour')  AS last_1h,
                COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '24 hours') AS last_24h,
                COUNT(*) FILTER (WHERE severity IN ('err','error','crit','emerg','alert')
                                   AND timestamp > NOW() - INTERVAL '1 hour')  AS errors_1h,
                COUNT(*) FILTER (WHERE severity = 'warning'
                                   AND timestamp > NOW() - INTERVAL '1 hour')  AS warnings_1h,
                COUNT(*) FILTER (WHERE severity IN ('info','notice')
                                   AND timestamp > NOW() - INTERVAL '1 hour')  AS info_1h,
                COUNT(DISTINCT host) FILTER (WHERE timestamp > NOW() - INTERVAL '1 hour') AS hosts_1h
            FROM events
        """)
        sections.append(f"\n=== EVENT STATS ===")
        sections.append(
            f"Last 1h: {stats['last_1h']} events "
            f"({stats['errors_1h']} errors, {stats['warnings_1h']} warnings, "
            f"{stats['info_1h']} info/notice) from {stats['hosts_1h']} hosts | "
            f"Last 24h: {stats['last_24h']} events"
        )

        host_activity = await conn.fetch("""
            SELECT host, COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE severity IN ('err','error','crit','emerg','alert')) AS errors
            FROM events
            WHERE timestamp > NOW() - INTERVAL '1 hour'
            GROUP BY host
            ORDER BY total DESC LIMIT 15
        """)
        if host_activity:
            sections.append("\n=== PER-HOST ACTIVITY (last 1h) ===")
            for h in host_activity:
                err_part = f" ({h['errors']} errors)" if h['errors'] else ""
                sections.append(f"  {h['host']}: {h['total']} events{err_part}")

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


# ── Deep (Investigator) context ────────────────────────────────────────────────

_DEEP_CTX_CACHE: dict = {"ts": 0.0, "key": None, "data": None}
_DEEP_CTX_TTL = 15.0   # slightly longer — queries are expensive
_deep_ctx_lock = asyncio.Lock()


async def build_deep_context(pool: asyncpg.Pool, message: str = "") -> str:
    """Full-spectrum context for the Investigator agent.

    Differences from quick context:
    • All event severities (not just error/warning) — info events fill the story
    • Up to 400 events — timeline needs volume
    • Default window: last 30 minutes (not 1 hour of highlights)
    • Timeline grouped by 1-minute buckets for chronological narrative
    • Full topology section: LLDP neighbours + learned connections + host_ip_map
    • Full SNMP raw data (interfaces, SFP readings)
    • IP resolution: every IP in the context is annotated with its known hostname
    """
    time_window = _extract_time_window(message) if message else None
    # "what just happened" / "what happened" → last 30 min
    if not time_window and re.search(r"\bjust\b|\brecent\b|\bnow\b", message, re.I):
        end   = datetime.now(timezone.utc)
        start = end - timedelta(minutes=30)
        time_window = (start.isoformat(), end.isoformat())

    cache_key = ("deep", time_window or "base")
    now_mono = asyncio.get_running_loop().time()

    if (_DEEP_CTX_CACHE["data"] is not None
            and _DEEP_CTX_CACHE["key"] == cache_key
            and now_mono - _DEEP_CTX_CACHE["ts"] < _DEEP_CTX_TTL):
        return _DEEP_CTX_CACHE["data"]

    async with _deep_ctx_lock:
        now_mono = asyncio.get_running_loop().time()
        if (_DEEP_CTX_CACHE["data"] is not None
                and _DEEP_CTX_CACHE["key"] == cache_key
                and now_mono - _DEEP_CTX_CACHE["ts"] < _DEEP_CTX_TTL):
            return _DEEP_CTX_CACHE["data"]
        result = await _build_deep_context_inner(pool, message, time_window)
        _DEEP_CTX_CACHE["data"] = result
        _DEEP_CTX_CACHE["ts"]   = now_mono
        _DEEP_CTX_CACHE["key"]  = cache_key
        return result


async def _build_deep_context_inner(pool: asyncpg.Pool,
                                     message: str,
                                     time_window) -> str:
    sections: list[str] = []
    now = datetime.now(timezone.utc)

    async with pool.acquire() as conn:
        # ── 1. Build IP → hostname resolution map ─────────────────────────────
        ip_rows = await conn.fetch("""
            SELECT ip, host, source, confidence
            FROM host_ip_map
            ORDER BY confidence DESC, last_seen DESC
        """)
        # Best-confidence mapping: ip → (host, source, confidence)
        ip_to_host: dict[str, tuple[str, str, float]] = {}
        for r in ip_rows:
            if r["ip"] not in ip_to_host or r["confidence"] > ip_to_host[r["ip"]][2]:
                ip_to_host[r["ip"]] = (r["host"], r["source"], float(r["confidence"]))

        def resolve_ip(ip: str) -> str:
            """Return 'hostname (ip)' if known, else just ip."""
            if not ip:
                return ip
            info = ip_to_host.get(ip)
            if info:
                return f"{info[0]} ({ip}, via {info[1]})"
            return ip

        # ── 2. Topology overview ───────────────────────────────────────────────
        topo_rows = await conn.fetch("""
            SELECT src_host, dst_host, relationship, evidence, confidence, event_count
            FROM topology_learned
            WHERE confidence >= 0.5
            ORDER BY confidence DESC, event_count DESC
            LIMIT 60
        """)
        lldp_rows = await conn.fetch("""
            SELECT local_host, local_port, remote_host, remote_port, last_seen
            FROM lldp_neighbours
            ORDER BY last_seen DESC
            LIMIT 40
        """)
        if lldp_rows:
            sections.append("=== PHYSICAL TOPOLOGY (LLDP) ===")
            for r in lldp_rows:
                sections.append(
                    f"  {r['local_host']} port {r['local_port']} ↔ "
                    f"{r['remote_host']} port {r['remote_port']}"
                )
        if topo_rows:
            sections.append("\n=== LEARNED TOPOLOGY (ARP / firewall / syslog correlation) ===")
            for r in topo_rows:
                conf = f"{r['confidence']:.0%}"
                sections.append(
                    f"  [{conf}] {r['src_host']} — {r['relationship']} → {r['dst_host']}"
                    f"  ({r['evidence'] or ''}, seen {r['event_count']}x)"
                )

        # ── 3. IP→hostname reference table ────────────────────────────────────
        if ip_to_host:
            sections.append("\n=== IP ADDRESS DIRECTORY ===")
            # Group by host for readability
            host_ips: dict[str, list[str]] = {}
            for ip, (host, src, conf) in ip_to_host.items():
                host_ips.setdefault(host, []).append(f"{ip}[{src},{conf:.0%}]")
            for host, ips in sorted(host_ips.items()):
                sections.append(f"  {host}: {', '.join(ips)}")

        # ── 4. Full event timeline ─────────────────────────────────────────────
        if time_window:
            start_iso, end_iso = time_window
            events = await conn.fetch("""
                SELECT timestamp, host, source, severity, program, message, structured
                FROM events
                WHERE timestamp BETWEEN $1::timestamptz AND $2::timestamptz
                ORDER BY timestamp ASC
                LIMIT 500
            """, start_iso, end_iso)
            sections.append(
                f"\n=== FULL EVENT TIMELINE ({start_iso[:16]} → {end_iso[:16]} UTC, "
                f"all severities, {len(events)} events) ==="
            )
        else:
            events = await conn.fetch("""
                SELECT timestamp, host, source, severity, program, message, structured
                FROM events
                WHERE timestamp > NOW() - INTERVAL '30 minutes'
                ORDER BY timestamp ASC
                LIMIT 400
            """)
            sections.append(
                f"\n=== FULL EVENT TIMELINE (last 30 min, all severities, {len(events)} events) ==="
            )

        # Group into 1-minute buckets for readability
        import collections
        buckets: dict[str, list] = collections.defaultdict(list)
        for e in events:
            bucket = e["timestamp"].strftime("%H:%M")
            buckets[bucket].append(e)

        for bucket, evs in sorted(buckets.items()):
            sections.append(f"\n  [{bucket}]")
            for e in evs:
                host = e["host"]
                msg  = e["message"][:200]
                # Resolve IPs that appear inline in the message
                # (quick pass — replace known IPs with "hostname (ip)")
                for ip, (hname, _, _conf) in ip_to_host.items():
                    if ip in msg and hname != host:
                        msg = msg.replace(ip, f"{hname}({ip})")
                sections.append(
                    f"    {e['severity'].upper():8} {host} [{e['program'] or e['source']}]: {msg}"
                )

        # ── 5. Active alerts ───────────────────────────────────────────────────
        alerts = await conn.fetch("""
            SELECT timestamp, severity, title, description, affected_hosts,
                   seen_count, acknowledged
            FROM alerts
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            ORDER BY timestamp DESC LIMIT 15
        """)
        if alerts:
            sections.append("\n=== ALERTS (24h) ===")
            for a in alerts:
                ack  = " [ACK]" if a["acknowledged"] else ""
                hosts = ", ".join(a["affected_hosts"] or [])
                cnt  = f" ×{a['seen_count']}" if (a["seen_count"] or 1) > 1 else ""
                sections.append(
                    f"  [{a['timestamp'].strftime('%H:%M')}] {a['severity'].upper()}{ack}{cnt}: "
                    f"{a['title']} — {a['description'][:120]} (hosts: {hosts})"
                )

        # ── 6. SNMP full snapshot ──────────────────────────────────────────────
        snmp_rows = await conn.fetch("""
            SELECT DISTINCT ON (host) host, sys_name, avg_cpu, wifi_clients,
                   interfaces_up, interfaces_down, total_in_bps, total_out_bps,
                   total_errors, raw_data, timestamp
            FROM snmp_metrics
            ORDER BY host, timestamp DESC
        """)
        if snmp_rows:
            sections.append("\n=== SNMP DEVICE STATE ===")
            for m in snmp_rows:
                parts = [f"{m['sys_name'] or m['host']} ({m['host']}):"]
                if m["avg_cpu"] is not None:
                    parts.append(f"CPU={m['avg_cpu']:.1f}%")
                parts.append(f"if={m['interfaces_up']}↑/{m['interfaces_down']}↓")
                if m["total_errors"] and m["total_errors"] > 0:
                    parts.append(f"ERRORS={m['total_errors']:.1f}/s")
                if m["wifi_clients"]:
                    parts.append(f"wifi={m['wifi_clients']}")
                age = int((now - m["timestamp"].replace(tzinfo=timezone.utc)).total_seconds())
                parts.append(f"(polled {age}s ago)")
                sections.append("  " + " ".join(parts))

                # Show per-interface detail for down or erroring interfaces
                raw = m["raw_data"]
                if raw:
                    try:
                        raw_dict = raw if isinstance(raw, dict) else json.loads(raw)
                        ifaces = raw_dict.get("interfaces", {})
                        down_ifs = [v["name"] for v in ifaces.values()
                                    if v.get("oper_status") == "down"
                                    and v.get("name") not in ("lo", "Null0", "Loopback0")]
                        if down_ifs:
                            sections.append(f"    DOWN interfaces: {', '.join(down_ifs)}")
                        sfp = raw_dict.get("sfp_sensors", [])
                        if sfp:
                            sfp_parts = []
                            for s in sfp:
                                if s.get("is_sfp"):
                                    sfp_parts.append(f"{s['name']}={s['value']}{s['unit']}")
                            if sfp_parts:
                                sections.append(f"    SFP: {', '.join(sfp_parts)}")
                    except Exception:
                        pass

        # ── 7. Anomaly detections ──────────────────────────────────────────────
        try:
            anomalies = await conn.fetch("""
                SELECT timestamp, kind, host, program, title, baseline, observed, severity
                FROM anomaly_detections
                WHERE timestamp > NOW() - INTERVAL '24 hours' AND NOT acknowledged
                ORDER BY timestamp DESC LIMIT 20
            """)
            if anomalies:
                sections.append("\n=== LEARNED ANOMALIES (24h) ===")
                for a in anomalies:
                    extra = ""
                    if a["baseline"] is not None and a["observed"] is not None:
                        extra = f" (baseline={a['baseline']:.1f} vs observed={a['observed']:.1f})"
                    sections.append(
                        f"  [{a['timestamp'].strftime('%H:%M')}] {a['severity'].upper()} "
                        f"{a['kind']} on {a['host']}: {a['title']}{extra}"
                    )
        except Exception:
            pass

        # ── 8. Firewall flow summary ───────────────────────────────────────────
        try:
            flows = await conn.fetch("""
                SELECT host, src_ip::text AS src_ip, dst_ip::text AS dst_ip,
                       dst_port, port_name, direction, action, blocked,
                       COUNT(*) AS n
                FROM firewall_flows
                WHERE timestamp > NOW() - INTERVAL '30 minutes'
                GROUP BY host, src_ip, dst_ip, dst_port, port_name, direction, action, blocked
                ORDER BY n DESC LIMIT 30
            """)
            if flows:
                sections.append("\n=== FIREWALL FLOWS (30 min) ===")
                for f in flows:
                    src_r = resolve_ip(f["src_ip"])
                    dst_r = resolve_ip(f["dst_ip"])
                    act = f["action"] + ("/BLOCK" if f["blocked"] else "")
                    sections.append(
                        f"  {f['n']}× {f['direction'] or '?'} {src_r} → {dst_r}"
                        f":{f['dst_port'] or '?'}/{f['port_name'] or ''} [{act}] on {f['host']}"
                    )
        except Exception:
            pass

    sections.append(f"\n=== CURRENT TIME: {now.strftime('%Y-%m-%d %H:%M:%S')} UTC ===")
    return "\n".join(sections)


class ChatRequest(BaseModel):
    session_id: str | None = None
    message: str
    mode: str = "quick"     # "quick" | "deep"


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
                "SELECT role, content, created_at, mode FROM chat_messages "
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

    # Build context and select model/prompt based on mode
    mode = (req.mode or "quick").lower()
    if mode == "deep":
        context = await build_deep_context(_pool, req.message)
        system_prompt = CHAT_SYSTEM_DEEP
        model = OLLAMA_MODEL_DEEP
        num_predict = 2048
        temperature = 0.2
    else:
        mode = "quick"
        context = await build_chat_context(_pool, _redis, req.message)
        system_prompt = CHAT_SYSTEM_QUICK
        model = OLLAMA_MODEL
        num_predict = 800
        temperature = 0.3

    # Build prompt with conversation history
    agent_name = "LogLM Investigator" if mode == "deep" else "LogLM"
    prompt_parts = [f"SYSTEM CONTEXT:\n{context}\n"]
    prompt_parts.append("CONVERSATION HISTORY:")
    for msg in history[:-1]:  # exclude current message
        role = "You" if msg["role"] == "user" else agent_name
        prompt_parts.append(f"{role}: {msg['content']}")
    prompt_parts.append(f"\nUser: {req.message}")
    prompt_parts.append(f"\n{agent_name}:")

    full_prompt = "\n".join(prompt_parts)

    payload = {
        "model": model,
        "prompt": full_prompt,
        "system": system_prompt,
        "stream": False,
        "keep_alive": OLLAMA_KEEP_ALIVE,
        "options": {
            "temperature": temperature,
            "num_predict": num_predict,
        },
    }

    answer = None
    async with _ollama_sem:
        delay = 2.0
        for attempt in range(4):
            try:
                resp = await _http.post(
                    f"{OLLAMA_URL}/api/generate", json=payload, timeout=300)
                if resp.status_code in (429, 502, 503, 504) and attempt < 3:
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                resp.raise_for_status()
                answer = resp.json().get("response", "").strip()
                break
            except (httpx.ReadTimeout, httpx.ConnectTimeout,
                    httpx.RemoteProtocolError, httpx.ConnectError) as e:
                if attempt < 3:
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                answer = f"LLM unreachable after retries: {e}"
                break
            except Exception as e:
                answer = f"Sorry, I couldn't reach the LLM: {e}"
                break

    if not answer:
        answer = "I don't have enough data to answer that right now. Events may still be collecting."

    # Store assistant response
    async with _pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO chat_messages (session_id, role, content, context_summary, mode) "
            "VALUES ($1, 'assistant', $2, $3, $4)",
            sid, answer, context[:500], mode,
        )
        await conn.execute(
            "UPDATE chat_sessions SET updated_at = NOW(), "
            "title = COALESCE(NULLIF(title, 'New conversation'), $2) WHERE id = $1",
            sid, req.message[:60],
        )

    return JSONResponse({
        "session_id": str(sid),
        "response":   answer,
        "mode":       mode,
    })


@app.post("/api/chat/stream")
async def chat_stream(req: ChatRequest):
    """Streaming chat — returns SSE with tokens as they arrive from LLM."""
    if not req.message.strip():
        raise HTTPException(400, "Empty message")

    async with _pool.acquire() as conn:
        if req.session_id:
            sid = uuid.UUID(req.session_id)
        else:
            sid = uuid.uuid4()
            await conn.execute(
                "INSERT INTO chat_sessions (id, title) VALUES ($1, $2)",
                sid, req.message[:60],
            )
        await conn.execute(
            "INSERT INTO chat_messages (session_id, role, content) VALUES ($1, 'user', $2)",
            sid, req.message,
        )
        history = await conn.fetch(
            "SELECT role, content FROM chat_messages WHERE session_id = $1 "
            "ORDER BY created_at DESC LIMIT 20",
            sid,
        )
        history = list(reversed(history))

    stream_mode = (req.mode or "quick").lower()
    if stream_mode == "deep":
        context = await build_deep_context(_pool, req.message)
        system_prompt = CHAT_SYSTEM_DEEP
        stream_model  = OLLAMA_MODEL_DEEP
        num_predict   = 2048
        temperature   = 0.2
    else:
        stream_mode   = "quick"
        context = await build_chat_context(_pool, _redis, req.message)
        system_prompt = CHAT_SYSTEM_QUICK
        stream_model  = OLLAMA_MODEL
        num_predict   = 800
        temperature   = 0.3

    agent_name = "LogLM Investigator" if stream_mode == "deep" else "LogLM"
    prompt_parts = [f"SYSTEM CONTEXT:\n{context}\n"]
    prompt_parts.append("CONVERSATION HISTORY:")
    for msg in history[:-1]:
        role = "You" if msg["role"] == "user" else agent_name
        prompt_parts.append(f"{role}: {msg['content']}")
    prompt_parts.append(f"\nUser: {req.message}")
    prompt_parts.append(f"\n{agent_name}:")

    payload = {
        "model": stream_model,
        "prompt": "\n".join(prompt_parts),
        "system": system_prompt,
        "stream": True,
        "keep_alive": OLLAMA_KEEP_ALIVE,
        "options": {"temperature": temperature, "num_predict": num_predict},
    }

    async def _token_stream():
        full_answer = []
        yield f"data: {json.dumps({'session_id': str(sid), 'type': 'start', 'mode': stream_mode})}\n\n"
        try:
            async with _ollama_sem:
                async with _http.stream("POST", f"{OLLAMA_URL}/api/generate",
                                         json=payload, timeout=300) as resp:
                    async for line in resp.aiter_lines():
                        if not line:
                            continue
                        try:
                            chunk = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        token = chunk.get("response", "")
                        if token:
                            full_answer.append(token)
                            yield f"data: {json.dumps({'type': 'token', 'text': token})}\n\n"
                        if chunk.get("done"):
                            break
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'text': str(e)})}\n\n"

        answer = "".join(full_answer) or "No response from LLM."
        async with _pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO chat_messages (session_id, role, content, context_summary, mode) "
                "VALUES ($1, 'assistant', $2, $3, $4)",
                sid, answer, context[:500], stream_mode,
            )
            await conn.execute(
                "UPDATE chat_sessions SET updated_at = NOW(), "
                "title = COALESCE(NULLIF(title, 'New conversation'), $2) WHERE id = $1",
                sid, req.message[:60],
            )
        yield f"data: {json.dumps({'type': 'done', 'session_id': str(sid), 'mode': stream_mode})}\n\n"

    return StreamingResponse(_token_stream(), media_type="text/event-stream")


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
            "SELECT role, content, created_at, mode FROM chat_messages "
            "WHERE session_id = $1 ORDER BY created_at",
            uuid.UUID(session_id),
        )
    return JSONResponse({
        "messages": [
            {"role": m["role"], "content": m["content"], "created_at": m["created_at"].isoformat()}
            for m in messages
        ]
    })


# ── Config export/import (config-as-code) ─────────────────────────────────────

@app.get("/api/config/export")
async def config_export():
    """Export all user-configurable state as JSON for version control."""
    async with _pool.acquire() as conn:
        aliases = [dict(r) for r in await conn.fetch(
            "SELECT raw_name, alias FROM service_aliases")]
        feedback = [dict(r) for r in await conn.fetch(
            "SELECT host, program, pattern, verdict FROM event_feedback ORDER BY created_at")]
        retention = [dict(r) for r in await conn.fetch(
            "SELECT name, table_name, filter_clause, retention_days, enabled FROM retention_policies")]
        devices = [dict(r) for r in await conn.fetch(
            "SELECT host, port, community, device_type, label, poll_interfaces, poll_cpu, "
            "poll_wireless, enabled FROM snmp_devices")]
        sigma = [dict(r) for r in await conn.fetch(
            "SELECT rule_id, title, enabled, level, status FROM sigma_rules")]
        topo_nodes = [dict(r) for r in await conn.fetch(
            "SELECT host, label, icon, color, x, y, pinned, notes FROM topology_nodes")]
        topo_edges = [dict(r) for r in await conn.fetch(
            "SELECT from_host, to_host, label, color, weight FROM topology_edges WHERE NOT auto")]
    config = {
        "version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "service_aliases": aliases,
        "event_feedback": feedback,
        "retention_policies": retention,
        "snmp_devices": devices,
        "sigma_rules_state": sigma,
        "topology_nodes": topo_nodes,
        "topology_edges": topo_edges,
    }
    return JSONResponse(config)


class ConfigImport(BaseModel):
    config: dict
    merge: bool = True


@app.post("/api/config/import")
async def config_import(req: ConfigImport):
    """Import configuration. merge=True upserts, merge=False replaces."""
    cfg = req.config
    counts = {}
    async with _pool.acquire() as conn:
        if "service_aliases" in cfg:
            for a in cfg["service_aliases"]:
                await conn.execute(
                    "INSERT INTO service_aliases (raw_name, alias) VALUES ($1, $2) "
                    "ON CONFLICT (raw_name) DO UPDATE SET alias = $2",
                    a["raw_name"], a["alias"],
                )
            counts["service_aliases"] = len(cfg["service_aliases"])

        if "event_feedback" in cfg:
            for f in cfg["event_feedback"]:
                await conn.execute(
                    "INSERT INTO event_feedback (host, program, pattern, verdict) "
                    "SELECT $1, $2, $3, $4 WHERE NOT EXISTS "
                    "(SELECT 1 FROM event_feedback WHERE pattern = $3 AND host = $1)",
                    f.get("host"), f.get("program"), f["pattern"], f["verdict"],
                )
            counts["event_feedback"] = len(cfg["event_feedback"])

        if "retention_policies" in cfg:
            for r in cfg["retention_policies"]:
                await conn.execute(
                    "INSERT INTO retention_policies (name, table_name, filter_clause, retention_days, enabled) "
                    "VALUES ($1, $2, $3, $4, $5) ON CONFLICT (name) DO UPDATE SET "
                    "table_name = $2, filter_clause = $3, retention_days = $4, enabled = $5",
                    r["name"], r["table_name"], r.get("filter_clause"),
                    r["retention_days"], r.get("enabled", True),
                )
            counts["retention_policies"] = len(cfg["retention_policies"])

        if "snmp_devices" in cfg:
            for d in cfg["snmp_devices"]:
                await conn.execute(
                    "INSERT INTO snmp_devices (host, port, community, device_type, label, enabled) "
                    "VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (host) DO UPDATE SET "
                    "port = $2, community = $3, device_type = $4, label = $5, enabled = $6",
                    d["host"], d.get("port", 161), d.get("community", "public"),
                    d.get("device_type", "auto"), d.get("label"),
                    d.get("enabled", True),
                )
            counts["snmp_devices"] = len(cfg["snmp_devices"])

        if "topology_nodes" in cfg:
            for n in cfg["topology_nodes"]:
                await conn.execute(
                    "INSERT INTO topology_nodes (host, label, icon, color, x, y, pinned, notes) "
                    "VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (host) DO UPDATE SET "
                    "label=$2, icon=$3, color=$4, x=$5, y=$6, pinned=$7, notes=$8",
                    n["host"], n.get("label"), n.get("icon"), n.get("color"),
                    n.get("x"), n.get("y"), n.get("pinned", False), n.get("notes"),
                )
            counts["topology_nodes"] = len(cfg["topology_nodes"])

    return JSONResponse({"imported": counts})
