"""
Prometheus metrics + health checks for the web service.

Exposes:
  /healthz  → fast liveness (is the event loop running?)
  /readyz   → deep readiness (DB + Redis + Ollama)
  /metrics  → Prometheus exposition format

Metrics we care about (same registry is reused across services — each
service process exports its own surface):
  loglm_http_requests_total{route, method, status}
  loglm_http_request_seconds{route}                 histogram
  loglm_pool_connections{pool, state}               gauge
  loglm_redis_queue_depth{queue}                    gauge
  loglm_dep_up{dep}                                 gauge (0/1)
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest,
)

log = logging.getLogger(__name__)

# ── Registry ────────────────────────────────────────────────────────────────

http_requests = Counter(
    "loglm_http_requests_total",
    "HTTP requests handled by the LogLM web UI",
    ["route", "method", "status"],
)
http_latency = Histogram(
    "loglm_http_request_seconds",
    "HTTP request latency in seconds",
    ["route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
pool_conns = Gauge(
    "loglm_pool_connections",
    "Postgres pool connection counts",
    ["pool", "state"],
)
queue_depth = Gauge(
    "loglm_redis_queue_depth",
    "Length of a Redis queue (list or stream)",
    ["queue"],
)
dep_up = Gauge(
    "loglm_dep_up",
    "1 if a dependency (postgres, redis, ollama, loki) is reachable, else 0",
    ["dep"],
)
feedback_hits = Counter(
    "loglm_feedback_clicks_total",
    "User ★/✕ feedback clicks",
    ["verdict"],
)


# ── Middleware ──────────────────────────────────────────────────────────────

async def metrics_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    start = time.perf_counter()
    # Collapse path parameters into their template ("/alerts/{id}/ignore")
    # so we don't explode the label cardinality.
    route = request.scope.get("route")
    label = getattr(route, "path", None) or request.url.path
    try:
        response = await call_next(request)
        status = response.status_code
    except Exception:
        http_requests.labels(label, request.method, "500").inc()
        http_latency.labels(label).observe(time.perf_counter() - start)
        raise
    http_requests.labels(label, request.method, str(status)).inc()
    http_latency.labels(label).observe(time.perf_counter() - start)
    return response


# ── Dep probes ──────────────────────────────────────────────────────────────

async def probe_postgres(pool) -> bool:
    try:
        async with pool.acquire() as conn:
            await asyncio.wait_for(conn.fetchval("SELECT 1"), timeout=2)
        return True
    except Exception as e:
        log.debug(f"postgres probe failed: {e}")
        return False


async def probe_redis(redis) -> bool:
    try:
        return await asyncio.wait_for(redis.ping(), timeout=2)
    except Exception as e:
        log.debug(f"redis probe failed: {e}")
        return False


async def probe_ollama(http, url: str) -> bool:
    try:
        r = await http.get(f"{url}/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


async def probe_loki(http, url: str) -> bool:
    try:
        r = await http.get(f"{url}/ready", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


# ── Endpoint handlers ───────────────────────────────────────────────────────

def install(app: FastAPI, ollama_url: str, loki_url: str) -> None:
    """Wire health + metrics routes onto the app. Call once during startup.
    Middleware must be registered BEFORE app starts — use install_middleware()."""

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> Response:
        return Response("ok", media_type="text/plain")

    @app.get("/readyz", include_in_schema=False)
    async def readyz(request: Request) -> Response:
        pool = request.app.state.pool
        redis = request.app.state.redis
        http = request.app.state.http
        results = {
            "postgres": await probe_postgres(pool),
            "redis":    await probe_redis(redis),
            "ollama":   await probe_ollama(http, ollama_url),
            "loki":     await probe_loki(http, loki_url),
        }
        for dep, ok in results.items():
            dep_up.labels(dep).set(1 if ok else 0)
        critical = results["postgres"] and results["redis"]
        if critical:
            return Response(str(results), media_type="text/plain", status_code=200)
        return Response(str(results), media_type="text/plain", status_code=503)

    @app.get("/metrics", include_in_schema=False)
    async def metrics(request: Request) -> Response:
        # Scrape pool + queue state on demand so exporters are always fresh.
        pool = request.app.state.pool
        redis = request.app.state.redis
        if pool is not None:
            try:
                pool_conns.labels("web", "size").set(pool.get_size())
                pool_conns.labels("web", "idle").set(pool.get_idle_size())
            except Exception:
                pass
        if redis is not None:
            for q in ("loglm:stream:hi", "loglm:stream:mid", "loglm:stream:lo", "loglm:stream:analysis"):
                try:
                    queue_depth.labels(q).set(await redis.xlen(q))
                except Exception:
                    pass
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
