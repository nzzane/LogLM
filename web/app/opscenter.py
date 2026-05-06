"""
OpsCenter — System health aggregation, monitoring silences, and activity feed.

Provides high-level operational status across the entire LogLM stack:
  - Aggregate health score (0-100) derived from alerts, SNMP, anomalies
  - Per-component liveness checks (Redis, Postgres, Loki, Ollama, processor)
  - Monitoring silence management (host/category/severity-scoped pauses)
  - Real-time activity feed (append-only ring, sourced from alerts + HITL + user actions)
  - Role-based access constants (admin / operator / viewer)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

import asyncpg
import httpx

log = logging.getLogger(__name__)

# ── RBAC role constants ───────────────────────────────────────────────────────

ROLE_ADMIN    = "admin"
ROLE_OPERATOR = "operator"
ROLE_VIEWER   = "viewer"

# Roles that can approve HITL actions
HITL_APPROVERS = {ROLE_ADMIN}

# Roles that can submit HITL proposals via LLM chat
HITL_PROPOSERS = {ROLE_ADMIN, ROLE_OPERATOR}

# Roles that can read-only everything
ALL_ROLES = {ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER}

# ── System health ─────────────────────────────────────────────────────────────

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
LOKI_URL   = os.environ.get("LOKI_URL",   "http://loki:3100")


@dataclass
class ComponentHealth:
    name: str
    status: str        # ok | degraded | critical | unknown
    latency_ms: int | None
    detail: str
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class SystemHealth:
    score: int                          # 0-100
    status: str                         # ok | degraded | critical
    components: list[ComponentHealth]
    active_alerts: int
    critical_alerts: int
    active_silences: int
    pending_hitl: int
    events_1h: int
    errors_1h: int
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


async def _check_http(http: httpx.AsyncClient, url: str, name: str,
                      timeout: float = 3.0) -> ComponentHealth:
    t0 = time.monotonic()
    try:
        r = await http.get(url, timeout=timeout)
        ms = int((time.monotonic() - t0) * 1000)
        if r.status_code < 400:
            return ComponentHealth(name=name, status="ok", latency_ms=ms,
                                   detail=f"HTTP {r.status_code}")
        return ComponentHealth(name=name, status="degraded", latency_ms=ms,
                               detail=f"HTTP {r.status_code}")
    except Exception as e:
        ms = int((time.monotonic() - t0) * 1000)
        return ComponentHealth(name=name, status="critical", latency_ms=ms,
                               detail=str(e)[:120])


async def get_system_health(pool: asyncpg.Pool, redis_client,
                             http: httpx.AsyncClient) -> SystemHealth:
    """Aggregate health check across all platform components."""

    # Run component probes concurrently
    probe_tasks = [
        _check_http(http, f"{OLLAMA_URL}/api/tags", "Ollama LLM"),
        _check_http(http, f"{LOKI_URL}/ready", "Loki"),
    ]
    component_results = list(await asyncio.gather(*probe_tasks, return_exceptions=True))
    components: list[ComponentHealth] = []
    for r in component_results:
        if isinstance(r, ComponentHealth):
            components.append(r)
        else:
            components.append(ComponentHealth("unknown", "unknown", None, str(r)))

    # Redis probe
    t0 = time.monotonic()
    try:
        await redis_client.ping()
        components.append(ComponentHealth(
            name="Redis", status="ok",
            latency_ms=int((time.monotonic()-t0)*1000), detail="PONG",
        ))
    except Exception as e:
        components.append(ComponentHealth(
            name="Redis", status="critical",
            latency_ms=int((time.monotonic()-t0)*1000), detail=str(e)[:80],
        ))

    # Postgres probe
    t0 = time.monotonic()
    try:
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        components.append(ComponentHealth(
            name="PostgreSQL", status="ok",
            latency_ms=int((time.monotonic()-t0)*1000), detail="query ok",
        ))
    except Exception as e:
        components.append(ComponentHealth(
            name="PostgreSQL", status="critical",
            latency_ms=int((time.monotonic()-t0)*1000), detail=str(e)[:80],
        ))

    # Redis queue depths for processor / analyzer liveness
    try:
        hi  = await redis_client.xlen("loglm:stream:hi")
        ana = await redis_client.xlen("loglm:stream:analysis")
        proc_status = "ok"
        proc_detail = f"raw:hi={hi} analysis={ana}"
        if ana > 5000:
            proc_status = "degraded"
            proc_detail += " (analysis backlog high)"
        components.append(ComponentHealth(
            name="Processor/Analyzer pipeline",
            status=proc_status, latency_ms=None, detail=proc_detail,
        ))
    except Exception as e:
        components.append(ComponentHealth(
            name="Processor/Analyzer pipeline",
            status="unknown", latency_ms=None, detail=str(e)[:80],
        ))

    # Alert counts and event metrics
    try:
        async with pool.acquire() as conn:
            active_alerts = await conn.fetchval(
                "SELECT COUNT(*) FROM alerts WHERE NOT acknowledged "
                "AND (user_verdict IS NULL OR user_verdict != 'ignored')"
            )
            critical_alerts = await conn.fetchval(
                "SELECT COUNT(*) FROM alerts WHERE NOT acknowledged "
                "AND severity = 'critical' "
                "AND (user_verdict IS NULL OR user_verdict != 'ignored')"
            )
            events_1h = await conn.fetchval(
                "SELECT COUNT(*) FROM events WHERE timestamp > NOW() - INTERVAL '1 hour'"
            )
            errors_1h = await conn.fetchval(
                "SELECT COUNT(*) FROM events "
                "WHERE timestamp > NOW() - INTERVAL '1 hour' "
                "AND severity IN ('emerg','alert','crit','err','error')"
            )
            active_silences = await conn.fetchval(
                "SELECT COUNT(*) FROM monitoring_silences "
                "WHERE expires_at > NOW() AND revoked_at IS NULL"
            )
            pending_hitl = await conn.fetchval(
                "SELECT COUNT(*) FROM pending_actions WHERE status = 'pending'"
            )
    except Exception:
        active_alerts = critical_alerts = events_1h = errors_1h = 0
        active_silences = pending_hitl = 0

    # Compute composite health score
    degraded = sum(1 for c in components if c.status == "degraded")
    critical = sum(1 for c in components if c.status == "critical")
    score = 100
    score -= critical * 20
    score -= degraded * 8
    score -= min(critical_alerts * 5, 30)
    score -= min((active_alerts - critical_alerts) * 2, 20)
    score = max(0, min(100, score))

    if score >= 80:
        overall = "ok"
    elif score >= 50:
        overall = "degraded"
    else:
        overall = "critical"

    return SystemHealth(
        score=score,
        status=overall,
        components=components,
        active_alerts=int(active_alerts),
        critical_alerts=int(critical_alerts),
        active_silences=int(active_silences),
        pending_hitl=int(pending_hitl),
        events_1h=int(events_1h),
        errors_1h=int(errors_1h),
    )


# ── Monitoring silences ───────────────────────────────────────────────────────

async def get_active_silences(pool: asyncpg.Pool) -> list[dict]:
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT id, host, category, severity_filter, reason,
                          created_by, created_at, expires_at, action_id
                   FROM monitoring_silences
                   WHERE expires_at > NOW() AND revoked_at IS NULL
                   ORDER BY created_at DESC"""
            )
        return [dict(r) for r in rows]
    except Exception as e:
        log.debug(f"get_active_silences failed: {e}")
        return []


async def create_silence(
    pool: asyncpg.Pool, redis_client,
    host: str | None, category: str | None, severity_filter: str | None,
    reason: str, created_by: str, duration_minutes: int,
    action_id: str | None = None,
) -> str:
    """
    Create a monitoring silence. Returns the silence UUID.
    Also pushes the silence definition to Redis so the analyzer
    can reject matching events without a DB round-trip.
    """
    expires = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
    async with pool.acquire() as conn:
        sid = await conn.fetchval(
            """INSERT INTO monitoring_silences
                   (host, category, severity_filter, reason, created_by, expires_at, action_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7::uuid)
               RETURNING id""",
            host, category, severity_filter, reason, created_by, expires,
            action_id,
        )

    # Publish to Redis so running analyzer picks it up in < 1s
    try:
        silence_data = {
            "id": str(sid),
            "host": host,
            "category": category,
            "severity_filter": severity_filter,
            "expires_at": expires.isoformat(),
        }
        await redis_client.setex(
            f"loglm:silence:{sid}",
            int(duration_minutes * 60) + 60,
            json.dumps(silence_data),
        )
        await redis_client.publish("loglm:silences_changed", json.dumps({"op": "add", **silence_data}))
    except Exception as e:
        log.warning(f"silence Redis sync failed: {e}")

    log.info(f"Silence created: id={sid} host={host} cat={category} by={created_by} "
             f"duration={duration_minutes}m")
    return str(sid)


async def revoke_silence(pool: asyncpg.Pool, redis_client,
                          silence_id: str, revoked_by: str) -> bool:
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE monitoring_silences SET revoked_at=NOW(), revoked_by=$1 WHERE id=$2::uuid",
            revoked_by, silence_id,
        )
    if result == "UPDATE 0":
        return False
    try:
        await redis_client.delete(f"loglm:silence:{silence_id}")
        await redis_client.publish("loglm:silences_changed",
                                    json.dumps({"op": "remove", "id": silence_id}))
    except Exception:
        pass
    return True


# ── Activity feed ─────────────────────────────────────────────────────────────

async def push_activity(
    pool: asyncpg.Pool, redis_client,
    actor: str, action_type: str, title: str,
    detail: str | None = None,
    severity: str = "info",
    source: str = "system",
    link: str | None = None,
) -> None:
    """
    Append one entry to the real-time activity feed.
    Writes to DB (persistent) and publishes to Redis (real-time SSE).
    """
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO activity_feed
                       (actor, action_type, title, detail, severity, source, link)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)""",
                actor, action_type, title, detail, severity, source, link,
            )
    except Exception as e:
        log.debug(f"activity_feed insert failed: {e}")

    try:
        await redis_client.publish("loglm:activity", json.dumps({
            "actor":       actor,
            "action_type": action_type,
            "title":       title,
            "detail":      detail,
            "severity":    severity,
            "source":      source,
            "link":        link,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        }))
    except Exception:
        pass


async def get_activity_feed(pool: asyncpg.Pool, limit: int = 100,
                             source_filter: str | None = None) -> list[dict]:
    try:
        async with pool.acquire() as conn:
            if source_filter:
                rows = await conn.fetch(
                    "SELECT * FROM activity_feed WHERE source=$1 "
                    "ORDER BY timestamp DESC LIMIT $2",
                    source_filter, limit,
                )
            else:
                rows = await conn.fetch(
                    "SELECT * FROM activity_feed ORDER BY timestamp DESC LIMIT $1",
                    limit,
                )
        return [dict(r) for r in rows]
    except Exception as e:
        log.debug(f"get_activity_feed failed: {e}")
        return []


# ── User management helpers ───────────────────────────────────────────────────

VALID_ROLES = (ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER)


async def list_users(pool: asyncpg.Pool) -> list[dict]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT u.id, u.username, u.display_name, u.email, u.role,
                      u.disabled, u.created_at, u.last_login,
                      (SELECT COUNT(*) FROM user_sessions s
                       WHERE s.user_id = u.id AND NOT s.revoked
                         AND s.expires_at > NOW()) AS active_sessions
               FROM users u
               ORDER BY u.created_at"""
        )
    return [dict(r) for r in rows]


async def get_user_sessions(pool: asyncpg.Pool, user_id: int) -> list[dict]:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT id, ip::TEXT, user_agent, created_at, expires_at, revoked
               FROM user_sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20""",
            user_id,
        )
    return [dict(r) for r in rows]


async def revoke_user_sessions(pool: asyncpg.Pool, user_id: int,
                                except_token_hash: bytes | None = None) -> int:
    async with pool.acquire() as conn:
        if except_token_hash:
            r = await conn.execute(
                "UPDATE user_sessions SET revoked=TRUE "
                "WHERE user_id=$1 AND NOT revoked AND token_hash != $2",
                user_id, except_token_hash,
            )
        else:
            r = await conn.execute(
                "UPDATE user_sessions SET revoked=TRUE "
                "WHERE user_id=$1 AND NOT revoked",
                user_id,
            )
    try:
        return int(r.split()[-1])
    except Exception:
        return 0
