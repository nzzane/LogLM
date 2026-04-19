"""
Prometheus metrics + tiny health HTTP server for the processor.

Runs aiohttp on PROCESSOR_METRICS_PORT (default 9101) so a Prometheus
scrape and a Compose healthcheck can both hit it without colliding with
the main worker loop. Kept self-contained so the processor stays a single
process — no sidecars, no second image.
"""

from __future__ import annotations

import logging
import os

from aiohttp import web
from prometheus_client import (
    CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest,
)

log = logging.getLogger(__name__)

PORT = int(os.environ.get("PROCESSOR_METRICS_PORT", "9101"))

# ── Metrics ─────────────────────────────────────────────────────────────────

events_in = Counter(
    "loglm_processor_events_in_total",
    "Raw events pulled from a Redis priority queue",
    ["queue"],
)
events_out = Counter(
    "loglm_processor_events_out_total",
    "Events written to Postgres after parse+filter+dedupe",
    ["verdict"],   # keep | drop | dupe | error
)
events_to_analyzer = Counter(
    "loglm_processor_to_analyzer_total",
    "Events forwarded to the analyzer queue",
)
parse_seconds = Histogram(
    "loglm_processor_parse_seconds",
    "Time spent parsing one event end-to-end",
    buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5),
)
write_seconds = Histogram(
    "loglm_processor_write_seconds",
    "Time spent persisting one event (Postgres + Loki)",
    buckets=(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
)
queue_depth = Gauge(
    "loglm_processor_queue_depth",
    "Length of a Redis raw queue at last poll",
    ["queue"],
)
worker_busy = Gauge(
    "loglm_processor_worker_busy",
    "Number of worker tasks currently inside the per-event chain",
)
backpressure = Gauge(
    "loglm_processor_backpressure",
    "1 if analyzer queue is over the soft/hard threshold, else 0",
    ["level"],   # soft | hard
)
fast_llm_calls = Counter(
    "loglm_processor_fast_llm_calls_total",
    "Calls into the fast (small) LLM categorizer",
    ["result"],   # hit | miss | timeout | error | skipped
)
sigma_hits = Counter(
    "loglm_processor_sigma_hits_total",
    "Sigma rule matches",
    ["severity"],
)
dedup_drops = Counter(
    "loglm_processor_dedup_drops_total",
    "Events suppressed by the burst dedup signature cache",
)
feedback_apply = Counter(
    "loglm_processor_feedback_total",
    "User ★/✕ feedback events consumed from the pubsub channel",
    ["verdict"],
)


# ── HTTP server ─────────────────────────────────────────────────────────────

async def _metrics(_: web.Request) -> web.Response:
    return web.Response(body=generate_latest(), content_type=CONTENT_TYPE_LATEST)


async def _healthz(_: web.Request) -> web.Response:
    return web.Response(text="ok")


_runner: web.AppRunner | None = None


async def start() -> None:
    """Boot the aiohttp metrics server. Idempotent — safe to call twice."""
    global _runner
    if _runner is not None:
        return
    app = web.Application()
    app.router.add_get("/metrics", _metrics)
    app.router.add_get("/healthz", _healthz)
    _runner = web.AppRunner(app, access_log=None)
    await _runner.setup()
    site = web.TCPSite(_runner, "0.0.0.0", PORT)
    await site.start()
    log.info(f"processor metrics listening on :{PORT}")


async def stop() -> None:
    global _runner
    if _runner is not None:
        await _runner.cleanup()
        _runner = None
