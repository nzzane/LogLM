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
from fastapi import FastAPI, Request, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.encoders import jsonable_encoder
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

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
LIBRENMS_URL = os.environ.get("LIBRENMS_URL", "")
LIBRENMS_TOKEN = os.environ.get("LIBRENMS_TOKEN", "")
# Chat uses the deep model for reasoning + correlation. Falls back to legacy OLLAMA_MODEL.
OLLAMA_MODEL = os.environ.get(
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
                tags        TEXT[] NOT NULL DEFAULT '{}',
                notes       TEXT,
                pinned      BOOLEAN NOT NULL DEFAULT FALSE,
                created_at  TIMESTAMPTZ DEFAULT NOW(),
                updated_at  TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_host_metadata_pinned ON host_metadata (pinned) WHERE pinned;
            CREATE INDEX IF NOT EXISTS idx_host_metadata_tags   ON host_metadata USING GIN (tags);

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

    global _docker
    if docker_sdk is not None:
        try:
            _docker = docker_sdk.from_env()
            _docker.ping()
        except Exception as e:
            _docker = None
            print(f"[web] docker socket unavailable: {e}")


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


class HostMetadataPayload(BaseModel):
    tags: list[str] | None = None
    notes: str | None = None
    pinned: bool | None = None


async def _get_host_metadata(conn: asyncpg.Connection, host: str) -> dict:
    row = await conn.fetchrow(
        "SELECT host, tags, notes, pinned, created_at, updated_at "
        "FROM host_metadata WHERE host = $1",
        host,
    )
    if row:
        return dict(row)
    return {"host": host, "tags": [], "notes": None, "pinned": False}


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
                   total_errors
            FROM snmp_metrics WHERE host = $1
            ORDER BY timestamp DESC LIMIT 1
        """, host)

    return JSONResponse(jsonable_encoder({
        "host": host,
        "alias": alias,
        "metadata": meta,
        "device": dict(device) if device else None,
        "stats": dict(stats) if stats else {},
        "snmp_latest": dict(snmp_latest) if snmp_latest else None,
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
        if existing is None:
            await conn.execute(
                """INSERT INTO host_metadata (host, tags, notes, pinned)
                   VALUES ($1, $2, $3, $4)""",
                host,
                tags or [],
                p.notes,
                bool(p.pinned),
            )
        else:
            sets = []
            args: list = []
            n = 1
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
    have a node row. Auto-rows are virtual until the user moves them."""
    async with _pool.acquire() as conn:
        nodes = await conn.fetch(
            "SELECT host, label, icon, color, x, y, pinned, notes FROM topology_nodes"
        )
        edges = await conn.fetch(
            "SELECT id, from_host, to_host, label, color, weight, auto FROM topology_edges"
        )
        # Hosts we know about but that don't yet have a topology_node row.
        known = await conn.fetch("""
            SELECT d.host, d.device_type, COALESCE(d.label, d.host) AS label
            FROM snmp_devices d
            WHERE NOT EXISTS (SELECT 1 FROM topology_nodes n WHERE n.host = d.host)
            UNION
            SELECT host, NULL, host
            FROM host_metadata
            WHERE NOT EXISTS (SELECT 1 FROM topology_nodes n WHERE n.host = host_metadata.host)
        """)

    nodes_out = [dict(r) for r in nodes]
    for r in known:
        d = dict(r)
        nodes_out.append({
            "host":   d["host"],
            "label":  d.get("label") or d["host"],
            "icon":   _icon_for_device_type(d.get("device_type")),
            "color":  None,
            "x":      None,
            "y":      None,
            "pinned": False,
            "notes":  None,
            "auto":   True,
        })

    return JSONResponse(jsonable_encoder({
        "nodes": nodes_out,
        "edges": [dict(r) for r in edges],
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


async def build_chat_context(pool: asyncpg.Pool, redis_client: aioredis.Redis,
                              user_message: str = "") -> str:
    """Gather current state for the LLM's context window.
    If the user asked about a specific time window ('last hour', 'past 30 min'),
    the events section is narrowed to that window and a broader event sample
    is returned so the LLM can RCA the window."""
    sections = []
    now = datetime.now(timezone.utc)
    time_window = _extract_time_window(user_message) if user_message else None

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

        # Recent notable events — narrow to user-specified window if given,
        # otherwise default to last hour.
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

    # Build context (honours time-window phrases in the user's message)
    context = await build_chat_context(_pool, _redis, req.message)

    # Build prompt with conversation history
    prompt_parts = [f"SYSTEM CONTEXT:\n{context}\n"]
    prompt_parts.append("CONVERSATION HISTORY:")
    for msg in history[:-1]:  # exclude current message
        role = "User" if msg["role"] == "user" else "LogLM"
        prompt_parts.append(f"{role}: {msg['content']}")
    prompt_parts.append(f"\nUser: {req.message}")
    prompt_parts.append("\nLogLM:")

    full_prompt = "\n".join(prompt_parts)

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": full_prompt,
        "system": CHAT_SYSTEM,
        "stream": False,
        "keep_alive": OLLAMA_KEEP_ALIVE,
        "options": {
            "temperature": 0.3,
            "num_predict": 1024,
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
