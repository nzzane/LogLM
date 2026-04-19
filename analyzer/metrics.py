"""
Prometheus metrics + health for the analyzer service.

The analyzer is the heavy LLM stage, so we split its timings from the
processor's — batch-scan latency is dominated by model tokens/sec, not
queue I/O, and you want to plot them separately.
"""

from __future__ import annotations

import logging
import os

from aiohttp import web
from prometheus_client import (
    CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest,
)

log = logging.getLogger(__name__)

PORT = int(os.environ.get("ANALYZER_METRICS_PORT", "9102"))

batches_total = Counter(
    "loglm_analyzer_batches_total",
    "LLM batches completed",
    ["outcome"],   # ok | empty | error | retry
)
batch_size = Histogram(
    "loglm_analyzer_batch_size",
    "Events per batch",
    buckets=(1, 5, 10, 20, 50, 100, 200, 400, 800),
)
batch_seconds = Histogram(
    "loglm_analyzer_batch_seconds",
    "Wall-clock of one analyzer batch (prompt build → JSON parse)",
    buckets=(0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 15.0, 30.0, 60.0, 120.0),
)
alerts_emitted = Counter(
    "loglm_analyzer_alerts_total",
    "Alerts written after correlation",
    ["severity"],
)
llm_tokens_in = Counter(
    "loglm_analyzer_llm_tokens_in_total",
    "Prompt tokens reported by Ollama",
)
llm_tokens_out = Counter(
    "loglm_analyzer_llm_tokens_out_total",
    "Completion tokens reported by Ollama",
)
llm_errors = Counter(
    "loglm_analyzer_llm_errors_total",
    "Failed LLM calls (any reason)",
    ["kind"],   # timeout | http | parse | inject
)
backlog = Gauge(
    "loglm_analyzer_backlog",
    "Depth of the analyzer input queue at last poll",
)
busy = Gauge(
    "loglm_analyzer_busy",
    "1 while a batch is being processed",
)
memory_summaries = Counter(
    "loglm_analyzer_memory_summaries_total",
    "Memory summaries written for chat recall",
)


async def _metrics(_: web.Request) -> web.Response:
    return web.Response(body=generate_latest(), content_type=CONTENT_TYPE_LATEST)


async def _healthz(_: web.Request) -> web.Response:
    return web.Response(text="ok")


_runner: web.AppRunner | None = None


async def start() -> None:
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
    log.info(f"analyzer metrics listening on :{PORT}")


async def stop() -> None:
    global _runner
    if _runner is not None:
        await _runner.cleanup()
        _runner = None
