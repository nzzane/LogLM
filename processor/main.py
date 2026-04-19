"""
Processor service.
Reads raw events from Redis list loglm:raw,
parses + filters them, then:
  - "keep"  → push to loglm:analysis (LLM queue) + send to Loki
  - "store" → send to Loki only
  - "drop"  → discard

Also polls LibreNMS API for SNMP alerts if configured.
"""

import asyncio
import json
import logging
import os
import re
import signal
import time
from datetime import datetime, timezone

import asyncpg
import httpx
import redis.asyncio as aioredis
import xxhash

from parser import parse
from filter import classify, _rate_limiter, get_feedback_cache
import fast_categorizer
import anomaly
import metrics as proc_metrics
import partitions
import streams
import sigma_engine
import distill
import geoip
from batch_writer import BatchWriter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [processor] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

REDIS_URL = os.environ["REDIS_URL"]
POSTGRES_DSN = os.environ["POSTGRES_DSN"]
LOKI_URL = os.environ.get("LOKI_URL", "http://loki:3100")
LIBRENMS_URL = os.environ.get("LIBRENMS_URL", "")
LIBRENMS_TOKEN = os.environ.get("LIBRENMS_TOKEN", "")
LIBRENMS_POLL_INTERVAL = 60  # seconds

# Pipeline tunables — most useful at scale.
PROCESSOR_WORKERS = int(os.environ.get("PROCESSOR_WORKERS", "4"))
# Pool sizing: each worker can hold a connection for the full
# parse→record→anomaly chain. Plus retention, feedback, baselines, librenms.
# Sized generously — idle conns are cheap; deadlocks are not.
PG_POOL_MIN = int(os.environ.get("PROCESSOR_PG_POOL_MIN", "4"))
PG_POOL_MAX = int(os.environ.get("PROCESSOR_PG_POOL_MAX", "24"))
# Soft ceiling on acquire — if we can't get a connection in this many seconds
# we log + continue rather than hang the worker forever.
PG_ACQUIRE_TIMEOUT = float(os.environ.get("PROCESSOR_PG_ACQUIRE_TIMEOUT", "10"))
# Worker heartbeat + watchdog. Each worker logs every N seconds showing it's
# alive and how many events it processed; the main loop restarts any worker
# that has gone silent for 3× this interval.
WORKER_HEARTBEAT_SEC = int(os.environ.get("PROCESSOR_HEARTBEAT_SEC", "60"))
WORKER_STALL_SEC = int(os.environ.get("PROCESSOR_STALL_SEC", "180"))
# When the analysis (deep LLM) queue grows past this, the processor stops
# pushing low-priority/firewall events into it so the LLM can catch up
# without dropping high-priority security work.
ANALYSIS_BACKPRESSURE_HIGH = int(os.environ.get("ANALYSIS_BACKPRESSURE_HIGH", "1500"))
ANALYSIS_BACKPRESSURE_HARD = int(os.environ.get("ANALYSIS_BACKPRESSURE_HARD", "5000"))
# Per-firewall-flow-signature cooldown before another instance is forwarded
# to the deep LLM. Stops 100s of identical "blocked port 22 from .42" events
# from flooding the analysis queue while still surfacing the first one.
FIREWALL_LLM_COOLDOWN_SEC = int(os.environ.get("FIREWALL_LLM_COOLDOWN_SEC", "60"))

# Priority queue keys — must match rsyslog/syslog_receiver.py.
RAW_QUEUES = ["loglm:raw:hi", "loglm:raw:mid", "loglm:raw:lo"]
# Legacy: drain old single-list queue once at startup so an upgrade doesn't
# leak in-flight events. Removed from steady-state BLPOP.
LEGACY_RAW_QUEUE = "loglm:raw"


async def send_to_loki(client: httpx.AsyncClient, event: dict, verdict: str):
    ts_ns = str(int(datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).timestamp() * 1e9))
    labels = {
        "job": "loglm",
        "host": event["host"],
        "source": event["source"],
        "severity": event["severity"],
        "verdict": verdict,
    }
    payload = {
        "streams": [{
            "stream": labels,
            "values": [[ts_ns, event["message"]]]
        }]
    }
    try:
        resp = await client.post(f"{LOKI_URL}/loki/api/v1/push", json=payload, timeout=5)
        if resp.status_code not in (204, 200):
            log.warning(f"Loki push failed: {resp.status_code} {resp.text[:200]}")
    except Exception as e:
        log.debug(f"Loki push error: {e}")


def _event_hash(event: dict) -> bytes:
    """xxhash128 of (timestamp, host, program, message). Deduplicates events
    that arrive via multiple paths (stream re-delivery, duplicate syslog)."""
    h = xxhash.xxh128()
    h.update(event.get("timestamp", "").encode())
    h.update(event.get("host", "").encode())
    h.update((event.get("program") or "").encode())
    h.update(event.get("message", "").encode())
    return h.digest()


async def record_event_pg(conn, event: dict, verdict: str) -> bool:
    """Insert event with xxhash dedup. Returns True if inserted, False if dup."""
    ev_hash = _event_hash(event)
    result = await conn.execute(
        """
        INSERT INTO events (timestamp, host, source, severity, program, message, structured, verdict, event_hash)
        VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
        ON CONFLICT (event_hash, timestamp) WHERE event_hash IS NOT NULL DO NOTHING
        """,
        datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")),
        event["host"],
        event["source"],
        event["severity"],
        event["program"],
        event["message"],
        json.dumps(event.get("structured", {})),
        verdict,
        ev_hash,
    )
    return result != "INSERT 0 0"


async def poll_librenms(redis_client, http_client: httpx.AsyncClient):
    if not LIBRENMS_URL or not LIBRENMS_TOKEN:
        return
    headers = {"X-Auth-Token": LIBRENMS_TOKEN}
    try:
        resp = await http_client.get(
            f"{LIBRENMS_URL}/api/v0/alerts",
            headers=headers,
            params={"state": 1},
            timeout=10,
        )
        if resp.status_code != 200:
            return
        data = resp.json()
        for alert in data.get("alerts", []):
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "host": alert.get("hostname", "librenms"),
                "source": "librenms",
                "severity": "warning",
                "facility": "daemon",
                "program": "librenms",
                "message": (
                    f"LibreNMS alert: {alert.get('name','?')} "
                    f"on {alert.get('hostname','?')}: {alert.get('notes','')}"
                ),
                "structured": {"type": "librenms_alert", "raw": alert},
            }
            # LibreNMS alerts are always hi-priority — they only fire when a
            # monitored check actually tripped.
            await streams.xadd_event(redis_client, streams.STREAM_HI, json.dumps(event))
    except Exception as e:
        log.warning(f"LibreNMS poll error: {e}")


async def _resolve_verdict(event: dict) -> str:
    """
    Two-stage classification. Every event is sorted by static rules AND the
    fast LLM (when enabled). The fast LLM tags each event with a category and
    can upgrade a verdict (drop→store→keep), but security/user-feedback rules
    can never be downgraded by the LLM.

    Pipeline:
      raw event
        → static classify (user feedback > ALWAYS_KEEP/DROP > severity > rate-limit)
        → fast LLM (categorize + refine)  [signature-cached so cost stays bounded]
        → final verdict + fast_category attached
        → if "keep": forwarded to deep LLM via loglm:analysis
    """
    static_verdict = classify(event)

    if not fast_categorizer.enabled():
        return static_verdict

    refined = await fast_categorizer.categorize(event)
    if refined is None:
        return static_verdict   # LLM unavailable → stick with static

    llm_verdict = refined["verdict"]
    cat = refined.get("category", "other")
    structured = event.setdefault("structured", {})
    structured["fast_category"] = cat
    structured["fast_verdict"]  = llm_verdict
    structured["static_verdict"] = static_verdict

    # Merge: most aggressive verdict wins (keep > store > drop).
    # Static rules can never be downgraded — security wins ties.
    if static_verdict == "keep" or llm_verdict == "keep":
        return "keep"
    if static_verdict == "store" or llm_verdict == "store":
        return "store"
    return "drop"


# Per-(src,dst,port,action) cooldown so 100s of identical firewall events
# don't all hit the LLM. Process-local (one cache per worker is fine — Redis
# isn't a great fit for a hot-path 1000-tps lookup).
_firewall_llm_cache: dict[str, float] = {}
_firewall_llm_last_prune = 0.0


def _firewall_llm_recently_seen(event: dict) -> bool:
    """Return True if this firewall flow's signature was already forwarded to
    the LLM analysis queue within FIREWALL_LLM_COOLDOWN_SEC. Storage for
    firewall_flows table is unaffected — only the LLM forwarding is throttled."""
    global _firewall_llm_last_prune
    s = event.get("structured") or {}
    if s.get("type") != "firewall_event":
        return False
    sig = (
        f"{s.get('src_ip','')}|{s.get('dst_ip','')}|{s.get('dst_port','')}"
        f"|{s.get('action','')}|{event.get('host','')}"
    )
    now = asyncio.get_running_loop().time()
    last = _firewall_llm_cache.get(sig)
    if last is not None and now - last < FIREWALL_LLM_COOLDOWN_SEC:
        return True
    _firewall_llm_cache[sig] = now
    if now - _firewall_llm_last_prune > FIREWALL_LLM_COOLDOWN_SEC:
        cutoff = now - FIREWALL_LLM_COOLDOWN_SEC
        for k in list(_firewall_llm_cache.keys()):
            if _firewall_llm_cache[k] < cutoff:
                del _firewall_llm_cache[k]
        _firewall_llm_last_prune = now
    return False


# ── Host type cache (refreshed every 60s from Postgres) ───────────────────────
_host_type_cache: dict[str, str] = {}   # host → host_type
_host_type_last_refresh = 0.0


async def _refresh_host_type_cache(pool: asyncpg.Pool) -> None:
    global _host_type_last_refresh
    now = asyncio.get_running_loop().time()
    if now - _host_type_last_refresh < 60.0:
        return
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT host, host_type FROM host_metadata WHERE host_type != 'auto'")
        _host_type_cache.update({r["host"]: r["host_type"] for r in rows})
        _host_type_last_refresh = now
    except Exception as e:
        log.debug(f"host_type cache refresh failed: {e}")


_NGINX_PROGRAMS = re.compile(r"\b(nginx|caddy|traefik|haproxy|apache|httpd)\b", re.IGNORECASE)
_NGINX_SOURCES = {"nginx", "caddy", "traefik", "haproxy", "apache"}
_SNMP_SOURCES = {"snmp_monitor", "snmp_trap"}
_SNMP_STRUCT_TYPES = {"snmp_alert", "snmp_trap", "snmp_poll"}
_SNMP_HOST_TYPES = {"router", "ap", "switch", "firewall"}
_NGINX_HOST_TYPES = {"nginx"}


def _pick_analysis_stream(event: dict) -> str:
    """Route an event to the most specific analysis stream based on source,
    structured type, and host type. Falls back to STREAM_ANALYSIS (syslog)."""
    source = (event.get("source") or "").lower()
    program = (event.get("program") or "").lower()
    structured = event.get("structured") or {}
    struct_type = (structured.get("type") or "").lower()
    host_type = _host_type_cache.get(event.get("host", ""), "auto")

    # SNMP stream: SNMP monitor events, trap handlers, or SNMP-class hosts
    if source in _SNMP_SOURCES or struct_type in _SNMP_STRUCT_TYPES:
        return streams.STREAM_ANALYSIS_SNMP
    if host_type in _SNMP_HOST_TYPES:
        return streams.STREAM_ANALYSIS_SNMP

    # Nginx stream: web proxy events or nginx-class hosts
    if source in _NGINX_SOURCES or host_type in _NGINX_HOST_TYPES:
        return streams.STREAM_ANALYSIS_NGINX
    if _NGINX_PROGRAMS.search(program):
        return streams.STREAM_ANALYSIS_NGINX

    return streams.STREAM_ANALYSIS


_analysis_qlen = 0
_analysis_qlen_last_check = 0.0


async def _analysis_qlen_cached(redis_client) -> int:
    """XLEN on every event would burn a lot of Redis round-trips. Refresh once
    per second and let workers share the result."""
    global _analysis_qlen, _analysis_qlen_last_check
    now = asyncio.get_running_loop().time()
    if now - _analysis_qlen_last_check > 1.0:
        try:
            _analysis_qlen = await redis_client.xlen(streams.STREAM_ANALYSIS)
        except Exception:
            pass
        _analysis_qlen_last_check = now
    return _analysis_qlen


async def _drain_legacy_queue(redis_client) -> int:
    """One-shot drain of the pre-priority single queue. Pushes everything into
    the mid priority list so a rolling upgrade doesn't strand events."""
    moved = 0
    try:
        while True:
            item = await redis_client.lpop(LEGACY_RAW_QUEUE)
            if item is None:
                break
            await redis_client.rpush("loglm:raw:mid", item)
            moved += 1
    except Exception as e:
        log.debug(f"legacy queue drain failed: {e}")
    if moved:
        log.info(f"drained {moved} events from legacy {LEGACY_RAW_QUEUE} → loglm:raw:mid")
    return moved


# ── Worker health tracking ────────────────────────────────────────────────────
# Each worker ticks _worker_last_seen[i] on every loop iteration. The watchdog
# (monitor_workers_loop) restarts any worker whose tick is older than
# WORKER_STALL_SEC. Also holds per-worker processed counters for heartbeat.
_worker_last_seen: dict[int, float] = {}
_worker_processed: dict[int, int] = {}


async def _handle_one_event(
    worker_id: int,
    queue_name: str,
    raw_bytes: str,
    pool: asyncpg.Pool,
    redis_client,
    http_client: httpx.AsyncClient,
) -> None:
    """Process exactly one event. Owns ONE pg connection for its entire
    lifetime — record → firewall_flow → anomaly track → anomaly insert —
    so a worker can never acquire three overlapping conns and deadlock the
    pool. Any exception is caught and logged; the worker keeps going."""
    t0 = time.perf_counter()
    try:
        raw = json.loads(raw_bytes)
    except json.JSONDecodeError:
        proc_metrics.events_out.labels("error").inc()
        return
    try:
        event = parse(raw)
    except Exception as e:
        log.debug(f"[w{worker_id}] parse failed: {e}")
        proc_metrics.events_out.labels("error").inc()
        return
    geoip.enrich_event(event)
    try:
        verdict = await _resolve_verdict(event)
    except Exception as e:
        log.debug(f"[w{worker_id}] classify failed: {e}")
        verdict = "drop"

    proc_metrics.parse_seconds.observe(time.perf_counter() - t0)

    structured = event.get("structured") or {}
    if structured.get("fast_verdict"):
        try:
            sig = fast_categorizer._signature(event)
            await distill.record(
                pool, sig, event.get("host", ""),
                event.get("program") or "",
                structured["fast_verdict"],
                structured.get("fast_category", "other"),
            )
        except Exception:
            pass

    if verdict == "drop":
        proc_metrics.events_out.labels("drop").inc()
        return

    try:
        await send_to_loki(http_client, event, verdict)
    except Exception as e:
        log.debug(f"[w{worker_id}] loki push failed: {e}")

    t_write = time.perf_counter()
    try:
        async with pool.acquire() as conn:
            try:
                inserted = await record_event_pg(conn, event, verdict)
                if not inserted:
                    proc_metrics.dedup_drops.inc()
            except Exception as e:
                log.warning(f"[w{worker_id}] events insert failed: {e}")
            try:
                await anomaly.insert_firewall_flow(conn, event)
            except Exception as e:
                log.debug(f"[w{worker_id}] firewall_flow insert failed: {e}")
            try:
                anomalies = await anomaly.track(conn, event)
            except Exception as e:
                log.debug(f"[w{worker_id}] anomaly track failed: {e}")
                anomalies = []
            for a in anomalies:
                try:
                    await anomaly.insert_anomaly(conn, a)
                except Exception as e:
                    log.debug(f"[w{worker_id}] anomaly insert failed: {e}")
            # ── Topology: map syslog sender IP → reported hostname ─────────────
            # source_ip is the UDP packet source captured by the syslog receiver.
            # It's the ground-truth IP for this hostname — highest confidence.
            src_ip = raw.get("source_ip", "")
            ev_host = event.get("host", "")
            if src_ip and src_ip not in ("unknown", "") and ev_host:
                try:
                    await _upsert_host_ip(conn, src_ip, ev_host,
                                          "syslog_source", 1.0)
                except Exception:
                    pass
    except asyncio.TimeoutError:
        log.warning(f"[w{worker_id}] pg pool acquire timed out — skipping DB write")
        proc_metrics.events_out.labels("error").inc()
    except Exception as e:
        log.warning(f"[w{worker_id}] pg pool/conn error: {e}")
        proc_metrics.events_out.labels("error").inc()
    else:
        proc_metrics.write_seconds.observe(time.perf_counter() - t_write)
        proc_metrics.events_out.labels("keep" if verdict == "keep" else "store").inc()

    # Sigma rule matching — runs on every non-dropped event.
    try:
        sigma_hits = sigma_engine.match_event(event)
        for rule in sigma_hits:
            proc_metrics.sigma_hits.labels(rule.level).inc()
            await sigma_engine.record_hit(pool, rule, event)
            if rule.level in ("critical", "high"):
                sigma_event = {
                    "timestamp": event["timestamp"],
                    "host": event.get("host", ""),
                    "source": "sigma",
                    "severity": rule.level,
                    "facility": "daemon",
                    "program": event.get("program", ""),
                    "message": f"Sigma [{rule.level}] {rule.title}: {event.get('message', '')[:300]}",
                    "structured": {
                        "type": "sigma_hit",
                        "rule_id": rule.rule_id,
                        "rule_title": rule.title,
                        "tags": rule.tags,
                    },
                }
                await streams.xadd_event(redis_client, streams.STREAM_ANALYSIS, json.dumps(sigma_event))
    except Exception as e:
        log.debug(f"[w{worker_id}] sigma matching failed: {e}")

    # Push each detected anomaly to the deep LLM queue (always, regardless
    # of backpressure — these are the signals we MUST surface).
    try:
        for a in (anomalies if 'anomalies' in locals() else []):
            anom_event = {
                "timestamp": event["timestamp"],
                "host": a["host"],
                "source": "anomaly",
                "severity": a.get("severity", "warning"),
                "facility": "daemon",
                "program": a.get("program", ""),
                "message": f"{a['title']}: {a.get('description', '')}",
                "structured": {
                    "type": a["kind"],
                    "baseline": a.get("baseline"),
                    "observed": a.get("observed"),
                    "signature": a.get("signature"),
                },
            }
            await streams.xadd_event(redis_client, streams.STREAM_ANALYSIS, json.dumps(anom_event))
    except Exception as e:
        log.debug(f"[w{worker_id}] anomaly queue push failed: {e}")

    # Decide whether to forward the raw event to the deep LLM analysis queue.
    s = event.get("structured") or {}
    is_firewall = s.get("type") == "firewall_event"
    is_concerning_flow = is_firewall and bool(s.get("concerning"))
    is_high_severity = (event.get("severity") or "").lower() in (
        "emerg", "alert", "crit", "err", "error"
    )

    forward = False
    if verdict == "keep":
        forward = True
    if is_concerning_flow:
        forward = True

    # Firewall LLM throttle: even concerning flows get rate-limited per
    # signature so the analysis queue doesn't fill with the same flow.
    if is_firewall and forward and _firewall_llm_recently_seen(event):
        forward = False

    # Backpressure: when the LLM is behind, only high-priority events get
    # through. Firewall + everything else gets dropped from analysis (still
    # stored in events table).
    if forward:
        qlen = await _analysis_qlen_cached(redis_client)
        if qlen >= ANALYSIS_BACKPRESSURE_HARD and not is_high_severity:
            forward = False
        elif qlen >= ANALYSIS_BACKPRESSURE_HIGH and is_firewall:
            forward = False

    if forward:
        try:
            stream = _pick_analysis_stream(event)
            await streams.xadd_event(redis_client, stream, json.dumps(event))
            proc_metrics.events_to_analyzer.inc()
        except Exception as e:
            log.warning(f"[w{worker_id}] could not enqueue for analysis: {e}")


async def process_loop(worker_id: int, redis_client, pool: asyncpg.Pool, http_client: httpx.AsyncClient):
    """Drain priority streams via XREADGROUP. Each entry is ACKed after
    successful processing. Unacked entries get re-claimed by the watchdog's
    claim_stale sweep and eventually DLQ'd after MAX_DELIVERIES."""
    consumer = f"w{worker_id}"
    log.info(f"Processor worker {worker_id} started (stream consumer={consumer})")
    redis_backoff = 1.0
    last_heartbeat = asyncio.get_running_loop().time()
    last_claim = asyncio.get_running_loop().time()

    while True:
        _worker_last_seen[worker_id] = asyncio.get_running_loop().time()
        now = asyncio.get_running_loop().time()

        # Periodically reclaim stale entries from other crashed workers.
        entries: list[tuple[str, str, str]] = []
        if now - last_claim > 30:
            try:
                entries = await streams.claim_stale(
                    redis_client, streams.GROUP_PROCESSORS, consumer,
                    streams.RAW_STREAMS,
                )
            except Exception as e:
                log.debug(f"[w{worker_id}] claim_stale failed: {e}")
            last_claim = now

        # Read new entries from streams.
        if not entries:
            try:
                entries = await streams.xread_group(
                    redis_client, streams.GROUP_PROCESSORS, consumer,
                    streams.RAW_STREAMS, count=1, block_ms=1000,
                )
                redis_backoff = 1.0
            except (aioredis.ConnectionError, aioredis.TimeoutError, OSError) as e:
                log.warning(f"[w{worker_id}] xreadgroup failed: {e}; retry in {redis_backoff:.1f}s")
                await asyncio.sleep(redis_backoff)
                redis_backoff = min(redis_backoff * 2, 30.0)
                continue

        if not entries:
            if now - last_heartbeat > WORKER_HEARTBEAT_SEC:
                log.info(f"[w{worker_id}] heartbeat: processed={_worker_processed.get(worker_id, 0)} (idle)")
                last_heartbeat = now
            continue

        for stream_name, entry_id, raw_bytes in entries:
            proc_metrics.events_in.labels(stream_name).inc()
            proc_metrics.worker_busy.inc()
            try:
                await _handle_one_event(worker_id, stream_name, raw_bytes, pool, redis_client, http_client)
                await streams.xack(redis_client, stream_name, streams.GROUP_PROCESSORS, entry_id)
            except Exception as e:
                log.warning(f"[w{worker_id}] event handler crashed (entry {entry_id}): {e}")
            finally:
                proc_metrics.worker_busy.dec()

            _worker_processed[worker_id] = _worker_processed.get(worker_id, 0) + 1

        now = asyncio.get_running_loop().time()
        if now - last_heartbeat > WORKER_HEARTBEAT_SEC:
            log.info(
                f"[w{worker_id}] heartbeat: processed={_worker_processed.get(worker_id, 0)} "
                f"lastStream={entries[-1][0] if entries else '?'}"
            )
            last_heartbeat = now


async def librenms_loop(redis_client, http_client: httpx.AsyncClient):
    while True:
        await poll_librenms(redis_client, http_client)
        await asyncio.sleep(LIBRENMS_POLL_INTERVAL)


async def cleanup_loop():
    while True:
        await asyncio.sleep(1800)
        _rate_limiter.cleanup()


async def anomaly_baseline_loop(pool: asyncpg.Pool, redis_client):
    """Periodically fold completed 1h windows into each signature's learned
    baseline (EMA). Also checks for silent hosts and rolls host activity."""
    while True:
        await asyncio.sleep(300)
        try:
            updated = await anomaly.roll_baselines(pool)
            host_updated = await anomaly.roll_host_activity(pool)
            if updated or host_updated:
                log.info(f"anomaly baselines rolled: {updated} sigs, {host_updated} hosts")
        except Exception as e:
            log.debug(f"baseline roll failed: {e}")
        try:
            silence = await anomaly.check_silence(pool)
            for a in silence:
                async with pool.acquire() as conn:
                    await anomaly.insert_anomaly(conn, a)
                anom_event = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "host": a["host"],
                    "source": "anomaly",
                    "severity": a.get("severity", "high"),
                    "facility": "daemon",
                    "program": "anomaly",
                    "message": f"{a['title']}: {a.get('description', '')}",
                    "structured": {"type": a["kind"]},
                }
                await streams.xadd_event(redis_client, streams.STREAM_ANALYSIS, json.dumps(anom_event))
        except Exception as e:
            log.debug(f"silence check failed: {e}")


async def partition_loop(pool: asyncpg.Pool):
    """Hourly: create upcoming partitions + drop expired ones."""
    await asyncio.sleep(10)
    while True:
        try:
            await partitions.ensure_partitions(pool)
            await partitions.drop_expired(pool)
        except Exception as e:
            log.warning(f"partition maintenance failed: {e}")
        await asyncio.sleep(3600)


# ── Retention enforcement ─────────────────────────────────────────────────────

# Tables we are willing to prune. Locked down to prevent injection via
# retention_policies.table_name (which is admin-editable via the web UI).
RETENTION_TABLES: dict[str, str] = {
    "events":             "timestamp",
    "alerts":             "timestamp",
    "snmp_metrics":       "timestamp",
    "memory_summaries":   "timestamp",
    "firewall_flows":     "timestamp",
    "anomaly_detections": "timestamp",
}
# Partitioned tables use DROP PARTITION (handled by partition_loop) instead
# of row-by-row DELETE, so skip them in the classic retention loop.
_PARTITIONED_TABLES = {"events", "firewall_flows", "snmp_metrics"}

RETENTION_INTERVAL_SECONDS = int(os.environ.get("RETENTION_INTERVAL_SECONDS", "3600"))
RETENTION_CHUNK = int(os.environ.get("RETENTION_CHUNK", "5000"))

# Defense-in-depth: web/main.py validates filter_clause before insert, but the
# DB row could have been edited by hand or by an older buggy build. Re-validate
# here so the processor never executes an unsafe DELETE.
_FILTER_FORBIDDEN = re.compile(
    r"(?i)(;|--|/\*|\*/|\b("
    r"drop|delete|insert|update|create|alter|grant|revoke|truncate|"
    r"copy|merge|exec|execute|union|attach|detach|do|call|notify|listen|"
    r"into|returning|with"
    r")\b)"
)
_FILTER_ALLOWED_CHARS = re.compile(r"^[A-Za-z0-9_\s'\"=<>!,()\.\-\+]+$")


def _filter_clause_safe(clause: str) -> bool:
    if not clause:
        return True
    if len(clause) > 500:
        return False
    if _FILTER_FORBIDDEN.search(clause):
        return False
    if not _FILTER_ALLOWED_CHARS.match(clause):
        return False
    if clause.count("(") != clause.count(")"):
        return False
    if clause.count("'") % 2 != 0:
        return False
    return True


async def _run_policy(pool: asyncpg.Pool, policy: dict) -> int:
    """Apply one retention policy. Returns rows deleted.
    Uses a chunked DELETE so a months-old backlog doesn't lock the table."""
    table = policy["table_name"]
    if table not in RETENTION_TABLES:
        log.warning(f"retention policy {policy['name']} targets unknown table {table}")
        return 0
    if table in _PARTITIONED_TABLES:
        return 0  # handled by partition_loop via DROP PARTITION
    ts_col = RETENTION_TABLES[table]
    days = int(policy["retention_days"])
    if days <= 0:
        return 0
    extra = (policy.get("filter_clause") or "").strip()
    if extra and not _filter_clause_safe(extra):
        log.warning(f"retention {policy['name']}: refusing unsafe filter_clause")
        return 0
    where = f"{ts_col} < NOW() - INTERVAL '{days} days'"
    if extra:
        where += f" AND ({extra})"

    sql = (
        f"WITH victims AS ("
        f"  SELECT ctid FROM {table} WHERE {where} LIMIT {RETENTION_CHUNK}"
        f") DELETE FROM {table} WHERE ctid IN (SELECT ctid FROM victims)"
    )

    total = 0
    while True:
        async with pool.acquire() as conn:
            try:
                tag = await conn.execute(sql)
            except Exception as e:
                log.warning(f"retention {policy['name']} failed: {e}")
                return total
        # tag like "DELETE 1234"
        try:
            n = int(tag.split()[-1])
        except (ValueError, IndexError):
            n = 0
        total += n
        if n < RETENTION_CHUNK:
            break
        await asyncio.sleep(0)  # yield between chunks
    return total


async def retention_loop(pool: asyncpg.Pool):
    log.info(f"Retention loop started, interval={RETENTION_INTERVAL_SECONDS}s")
    # First run after a short delay so other init has finished.
    await asyncio.sleep(60)
    while True:
        try:
            async with pool.acquire() as conn:
                policies = await conn.fetch(
                    "SELECT id, name, table_name, filter_clause, retention_days "
                    "FROM retention_policies WHERE enabled = TRUE"
                )
            for row in policies:
                policy = dict(row)
                deleted = await _run_policy(pool, policy)
                async with pool.acquire() as conn:
                    await conn.execute(
                        "UPDATE retention_policies "
                        "SET last_run = NOW(), last_deleted = $1, updated_at = NOW() "
                        "WHERE id = $2",
                        deleted, policy["id"],
                    )
                if deleted:
                    log.info(f"retention {policy['name']}: deleted {deleted} rows from {policy['table_name']}")
        except Exception as e:
            log.warning(f"retention loop iteration failed: {e}")
        await asyncio.sleep(RETENTION_INTERVAL_SECONDS)


_last_feedback_count = -1


async def _refresh_feedback(pool: asyncpg.Pool, force_clear: bool = False) -> None:
    """Reload event_feedback into the static cache + fast LLM examples.
    If the row count changed (new user feedback), also wipe the fast LLM
    signature cache so previously-classified events get re-evaluated against
    the new rules instead of returning a stale verdict."""
    global _last_feedback_count
    cache = get_feedback_cache()
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT pattern, host, program, verdict, created_at "
                "FROM event_feedback ORDER BY created_at DESC LIMIT 200"
            )
        dict_rows = [dict(r) for r in rows]
        cache.replace(dict_rows)
        fast_categorizer.set_feedback_examples(dict_rows)
        if force_clear or len(dict_rows) != _last_feedback_count:
            fast_categorizer.clear_sig_cache()
        _last_feedback_count = len(dict_rows)
    except Exception as e:
        log.debug(f"feedback refresh failed: {e}")


async def feedback_refresh_loop(pool: asyncpg.Pool):
    """Periodic safety-net refresh every 30s. The pubsub listener handles
    interactive user feedback within ~1s; this loop catches missed events
    (e.g. processor was restarting when feedback was published).
    Also refreshes the host_type routing cache."""
    while True:
        await _refresh_feedback(pool)
        await _refresh_host_type_cache(pool)
        await asyncio.sleep(30)


_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_RFC1918 = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.)"
)


async def _upsert_host_ip(conn: asyncpg.Connection,
                           ip: str, host: str,
                           source: str, confidence: float) -> None:
    """Record or refresh an IP → hostname mapping in host_ip_map."""
    await conn.execute("""
        INSERT INTO host_ip_map (ip, host, source, confidence, first_seen, last_seen)
        VALUES ($1, $2, $3, $4, NOW(), NOW())
        ON CONFLICT (ip, host) DO UPDATE
        SET last_seen  = NOW(),
            confidence = GREATEST(host_ip_map.confidence, EXCLUDED.confidence),
            source     = CASE WHEN EXCLUDED.confidence >= host_ip_map.confidence
                              THEN EXCLUDED.source ELSE host_ip_map.source END
    """, ip, host, source, confidence)


async def _upsert_topology(conn: asyncpg.Connection,
                            src_host: str, dst_host: str,
                            relationship: str, evidence: str,
                            confidence: float) -> None:
    """Record or update a learned device-to-device relationship."""
    if src_host == dst_host:
        return
    await conn.execute("""
        INSERT INTO topology_learned
              (src_host, dst_host, relationship, evidence, confidence, event_count, first_seen, last_seen)
        VALUES ($1, $2, $3, $4, $5, 1, NOW(), NOW())
        ON CONFLICT (src_host, dst_host, relationship) DO UPDATE
        SET last_seen   = NOW(),
            event_count = topology_learned.event_count + 1,
            confidence  = GREATEST(topology_learned.confidence, EXCLUDED.confidence),
            evidence    = CASE WHEN EXCLUDED.confidence >= topology_learned.confidence
                               THEN EXCLUDED.evidence ELSE topology_learned.evidence END
    """, src_host, dst_host, relationship, evidence, confidence)


async def topology_learner_loop(pool: asyncpg.Pool) -> None:
    """Background task: scan recent events every 60s to build topology knowledge.

    Two learning strategies:
    1. Syslog-source mapping  — event.source_ip  (set by syslog receiver) directly
       maps the UDP sender IP to the reported hostname.
    2. Firewall-log cross-ref — when firewall host X logs src_ip Y, and Y matches
       a known syslog sender, X and Y are on the same L3 segment. If Y is NOT yet
       known, we at least record that X saw Y.
    """
    await asyncio.sleep(20)          # let workers warm up first
    while True:
        try:
            await _run_topology_learning(pool)
        except Exception as e:
            log.debug(f"topology learner error: {e}")
        await asyncio.sleep(60)


async def _run_topology_learning(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        # ── 1. Firewall log cross-referencing ─────────────────────────────────
        # Pull recent firewall events: (fw_host, src_ip, dst_ip)
        fw_rows = await conn.fetch("""
            SELECT host AS fw_host,
                   structured->>'src_ip' AS src_ip,
                   structured->>'dst_ip' AS dst_ip
            FROM events
            WHERE timestamp > NOW() - INTERVAL '5 minutes'
              AND structured->>'type' = 'firewall_event'
              AND structured->>'src_ip' IS NOT NULL
            LIMIT 2000
        """)

        if fw_rows:
            # All known IP→host mappings (for cross-ref)
            known_ip_map = {
                r["ip"]: r["host"]
                for r in await conn.fetch(
                    "SELECT ip, host FROM host_ip_map WHERE confidence >= 0.8"
                )
            }

            for row in fw_rows:
                fw_host = row["fw_host"]
                src_ip  = row["src_ip"] or ""
                dst_ip  = row["dst_ip"] or ""

                # Record: firewall saw this src IP
                if src_ip and _RFC1918.match(src_ip):
                    await _upsert_host_ip(conn, src_ip, fw_host,
                                          "firewall_log", 0.4)

                # Cross-reference: if src_ip is a known syslog host → link them
                src_known_host = known_ip_map.get(src_ip)
                if src_known_host and src_known_host != fw_host:
                    await _upsert_topology(
                        conn, fw_host, src_known_host,
                        "firewall_sees",
                        f"{fw_host} firewall logs show traffic from {src_known_host} ({src_ip})",
                        0.7,
                    )

                dst_known_host = known_ip_map.get(dst_ip)
                if dst_known_host and dst_known_host != fw_host:
                    await _upsert_topology(
                        conn, fw_host, dst_known_host,
                        "firewall_sees",
                        f"{fw_host} firewall logs show traffic to {dst_known_host} ({dst_ip})",
                        0.6,
                    )

        # ── 2. Infer host co-activity: hosts that log at the same time are likely
        #      on the same network (weak signal but useful for "what happened")
        # This is deliberately lightweight — just pull recent host pairs that
        # share events in the same minute and aren't already linked.
        minute_pairs = await conn.fetch("""
            SELECT a.host AS ha, b.host AS hb,
                   COUNT(*) AS shared_minutes
            FROM (
                SELECT DISTINCT host, date_trunc('minute', timestamp) AS minute
                FROM events
                WHERE timestamp > NOW() - INTERVAL '10 minutes'
            ) a
            JOIN (
                SELECT DISTINCT host, date_trunc('minute', timestamp) AS minute
                FROM events
                WHERE timestamp > NOW() - INTERVAL '10 minutes'
            ) b ON a.minute = b.minute AND a.host < b.host
            GROUP BY a.host, b.host
            HAVING COUNT(*) >= 3
            LIMIT 50
        """)
        for row in minute_pairs:
            # Very weak signal — only record if they share many minutes
            if row["shared_minutes"] >= 5:
                await _upsert_topology(
                    conn, row["ha"], row["hb"],
                    "co_active",
                    f"Both hosts log frequently in the same time windows",
                    0.3,
                )


async def feedback_pubsub_loop(redis_client, pool: asyncpg.Pool):
    """Subscribe to loglm:feedback so user clicks invalidate the fast LLM
    signature cache immediately, not on the next 30s periodic refresh."""
    while True:
        try:
            pubsub = redis_client.pubsub()
            await pubsub.subscribe("loglm:feedback")
            log.info("feedback pubsub listening on loglm:feedback")
            async for msg in pubsub.listen():
                if msg.get("type") != "message":
                    continue
                await _refresh_feedback(pool, force_clear=True)
        except Exception as e:
            log.warning(f"feedback pubsub disconnected: {e}; reconnecting in 5s")
            await asyncio.sleep(5)


async def monitor_workers_loop(redis_client, pool: asyncpg.Pool, http_client: httpx.AsyncClient, worker_tasks: dict[int, asyncio.Task]):
    """Watchdog: periodically log queue depths + pool usage, and restart any
    worker that has stopped making progress. Runs every 30s.

    Restart reason: a worker blocked on an awaited DB call forever (e.g. pool
    exhaustion + acquire hang, or a Postgres statement never returning) would
    otherwise just disappear from the log. Restarting unsticks the pipeline."""
    await asyncio.sleep(30)
    while True:
        try:
            now = asyncio.get_running_loop().time()
            stalled: list[int] = []
            for wid, last in list(_worker_last_seen.items()):
                if now - last > WORKER_STALL_SEC:
                    stalled.append(wid)

            try:
                qhi = await redis_client.xlen(streams.STREAM_HI)
                qmid = await redis_client.xlen(streams.STREAM_MID)
                qlo = await redis_client.xlen(streams.STREAM_LO)
                qanalysis = await redis_client.xlen(streams.STREAM_ANALYSIS)
                for q, v in [(streams.STREAM_HI, qhi), (streams.STREAM_MID, qmid),
                             (streams.STREAM_LO, qlo), (streams.STREAM_ANALYSIS, qanalysis)]:
                    proc_metrics.queue_depth.labels(q).set(v)
            except Exception:
                qhi = qmid = qlo = qanalysis = -1
            pool_size = pool.get_size() if pool else -1
            pool_free = pool.get_idle_size() if pool else -1
            total_processed = sum(_worker_processed.values())
            log.info(
                f"[watchdog] workers={len(worker_tasks)} processed={total_processed} "
                f"qraw={qhi}/{qmid}/{qlo} qanalysis={qanalysis} "
                f"pool={pool_size} idle={pool_free} stalled={stalled or '-'}"
            )

            for wid in stalled:
                task = worker_tasks.get(wid)
                if task is None or task.done():
                    continue
                log.warning(f"[watchdog] worker {wid} stalled for >{WORKER_STALL_SEC}s — restarting")
                task.cancel()
                try:
                    await asyncio.wait_for(task, timeout=5)
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    pass
                except Exception as e:
                    log.debug(f"[watchdog] worker {wid} cancel exception: {e}")
                # Spawn replacement
                _worker_last_seen[wid] = asyncio.get_running_loop().time()
                worker_tasks[wid] = asyncio.create_task(
                    process_loop(wid, redis_client, pool, http_client)
                )
        except Exception as e:
            log.warning(f"[watchdog] loop iteration failed: {e}")
        await asyncio.sleep(30)


_shutdown_event = asyncio.Event()


def _sigterm_handler():
    log.info("SIGTERM received — draining workers then exiting")
    _shutdown_event.set()


async def main():
    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(signal.SIGTERM, _sigterm_handler)
        loop.add_signal_handler(signal.SIGINT, _sigterm_handler)
    except NotImplementedError:
        pass  # Windows

    await proc_metrics.start()

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    pool: asyncpg.Pool | None = None
    last_err = None
    for _ in range(30):
        try:
            pool = await asyncpg.create_pool(
                POSTGRES_DSN,
                min_size=PG_POOL_MIN,
                max_size=PG_POOL_MAX,
                timeout=PG_ACQUIRE_TIMEOUT,
                command_timeout=60,
            )
            break
        except Exception as e:
            last_err = e
            log.info("Waiting for Postgres...")
            await asyncio.sleep(2)
    if pool is None:
        raise RuntimeError(f"Postgres not reachable after 60s: {last_err}")
    log.info(f"Postgres pool ready min={PG_POOL_MIN} max={PG_POOL_MAX}")

    async with pool.acquire() as conn:
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
        """)
    await anomaly.init_schema(pool)
    await partitions.ensure_partitions(pool)
    await sigma_engine.load_from_dir(pool)
    await sigma_engine.load_from_db(pool)
    await distill.init_schema(pool)

    http_client = httpx.AsyncClient()

    for _ in range(30):
        try:
            await redis_client.ping()
            break
        except Exception:
            log.info("Waiting for Redis...")
            await asyncio.sleep(2)

    geoip.init()
    await fast_categorizer.init_client()
    if fast_categorizer.enabled():
        log.info("Fast LLM categorizer enabled")
    else:
        log.info("Fast LLM categorizer disabled (PROCESSOR_USE_FAST_LLM=0)")

    await streams.ensure_groups(redis_client)
    await streams.drain_legacy_lists(redis_client)

    log.info(f"Starting {PROCESSOR_WORKERS} processor workers, backpressure "
             f"high={ANALYSIS_BACKPRESSURE_HIGH} hard={ANALYSIS_BACKPRESSURE_HARD}")

    # Workers are standalone tasks (not in a TaskGroup) so the watchdog can
    # cancel + respawn them individually without tearing down the process.
    now0 = asyncio.get_running_loop().time()
    worker_tasks: dict[int, asyncio.Task] = {}
    for i in range(PROCESSOR_WORKERS):
        _worker_last_seen[i] = now0
        _worker_processed[i] = 0
        worker_tasks[i] = asyncio.create_task(
            process_loop(i, redis_client, pool, http_client)
        )

    bg_tasks: list[asyncio.Task] = []
    try:
        bg_tasks.append(asyncio.create_task(monitor_workers_loop(redis_client, pool, http_client, worker_tasks)))
        bg_tasks.append(asyncio.create_task(librenms_loop(redis_client, http_client)))
        bg_tasks.append(asyncio.create_task(cleanup_loop()))
        bg_tasks.append(asyncio.create_task(feedback_refresh_loop(pool)))
        bg_tasks.append(asyncio.create_task(feedback_pubsub_loop(redis_client, pool)))
        bg_tasks.append(asyncio.create_task(retention_loop(pool)))
        bg_tasks.append(asyncio.create_task(anomaly_baseline_loop(pool, redis_client)))
        bg_tasks.append(asyncio.create_task(partition_loop(pool)))
        bg_tasks.append(asyncio.create_task(sigma_engine.reload_loop(pool)))
        bg_tasks.append(asyncio.create_task(distill.promote_loop(pool)))
        bg_tasks.append(asyncio.create_task(topology_learner_loop(pool)))

        await _shutdown_event.wait()
    finally:
        log.info("shutting down — cancelling workers + background tasks")
        for t in bg_tasks:
            t.cancel()
        for t in worker_tasks.values():
            t.cancel()
        all_tasks = bg_tasks + list(worker_tasks.values())
        await asyncio.gather(*all_tasks, return_exceptions=True)
        await proc_metrics.stop()
        await fast_categorizer.close_client()
        await http_client.aclose()
        await pool.close()
        log.info("processor shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())
