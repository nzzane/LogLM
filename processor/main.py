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
from datetime import datetime, timezone

import asyncpg
import httpx
import redis.asyncio as aioredis

from parser import parse
from filter import classify, _rate_limiter, get_feedback_cache
import fast_categorizer
import anomaly

logging.basicConfig(level=logging.INFO, format="%(asctime)s [processor] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

REDIS_URL = os.environ["REDIS_URL"]
POSTGRES_DSN = os.environ["POSTGRES_DSN"]
LOKI_URL = os.environ.get("LOKI_URL", "http://loki:3100")
LIBRENMS_URL = os.environ.get("LIBRENMS_URL", "")
LIBRENMS_TOKEN = os.environ.get("LIBRENMS_TOKEN", "")
LIBRENMS_POLL_INTERVAL = 60  # seconds


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


async def record_event_pg(pool: asyncpg.Pool, event: dict, verdict: str):
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO events (timestamp, host, source, severity, program, message, structured, verdict)
            VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)
            """,
            datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")),
            event["host"],
            event["source"],
            event["severity"],
            event["program"],
            event["message"],
            json.dumps(event.get("structured", {})),
            verdict,
        )


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
            await redis_client.rpush("loglm:raw", json.dumps(event))
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


async def process_loop(redis_client, pool: asyncpg.Pool, http_client: httpx.AsyncClient):
    """Drain loglm:raw forever. Catches per-event errors so one bad event
    can't crash the loop, and catches Redis disconnects with a backoff so
    a brief redis blip doesn't kill the processor."""
    log.info("Processor started, draining loglm:raw")
    redis_backoff = 1.0
    while True:
        try:
            item = await redis_client.blpop("loglm:raw", timeout=1)
            redis_backoff = 1.0  # success → reset backoff
        except (aioredis.ConnectionError, aioredis.TimeoutError, OSError) as e:
            log.warning(f"Redis blpop failed: {e}; retry in {redis_backoff:.1f}s")
            await asyncio.sleep(redis_backoff)
            redis_backoff = min(redis_backoff * 2, 30.0)
            continue
        if item is None:
            continue

        _, raw_bytes = item
        try:
            raw = json.loads(raw_bytes)
        except json.JSONDecodeError:
            continue

        try:
            event = parse(raw)
            verdict = await _resolve_verdict(event)
        except Exception as e:
            log.warning(f"parse/classify failed: {e}")
            continue

        if verdict == "drop":
            continue

        # Loki + Postgres in parallel, but each failure is logged + tolerated
        # individually so one slow backend can't crash the pipeline.
        try:
            results = await asyncio.gather(
                send_to_loki(http_client, event, verdict),
                record_event_pg(pool, event, verdict),
                anomaly.insert_firewall_flow(pool, event),
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, Exception):
                    log.warning(f"sink write failed: {r}")
        except Exception as e:
            log.warning(f"event sink crash: {e}")

        # Anomaly learning runs on every keep/store event. A detected anomaly
        # gets both persisted AND pushed to the analysis queue so the deep LLM
        # correlates it with other recent events.
        try:
            anomalies = await anomaly.track(pool, event)
            for a in anomalies:
                await anomaly.insert_anomaly(pool, a)
                try:
                    anom_event = {
                        "timestamp": event["timestamp"],
                        "host": a["host"],
                        "source": "anomaly",
                        "severity": a.get("severity", "warning"),
                        "facility": "daemon",
                        "program": a.get("program", ""),
                        "message": f"{a['title']}: {a.get('description','')}",
                        "structured": {
                            "type": a["kind"],
                            "baseline": a.get("baseline"),
                            "observed": a.get("observed"),
                            "signature": a.get("signature"),
                        },
                    }
                    await redis_client.rpush("loglm:analysis", json.dumps(anom_event))
                except Exception as e:
                    log.debug(f"anomaly queue push failed: {e}")
        except Exception as e:
            log.debug(f"anomaly track crash: {e}")

        # Concerning firewall flows also get forwarded straight to the deep LLM
        # even if the fast LLM said "store". These are the kind of thing the
        # user explicitly wants surfaced.
        s = event.get("structured") or {}
        force_analyze = (
            s.get("type") == "firewall_event" and bool(s.get("concerning"))
        )

        if verdict == "keep" or force_analyze:
            try:
                await redis_client.rpush("loglm:analysis", json.dumps(event))
            except Exception as e:
                log.warning(f"could not enqueue for analysis: {e}")


async def librenms_loop(redis_client, http_client: httpx.AsyncClient):
    while True:
        await poll_librenms(redis_client, http_client)
        await asyncio.sleep(LIBRENMS_POLL_INTERVAL)


async def cleanup_loop():
    while True:
        await asyncio.sleep(1800)
        _rate_limiter.cleanup()


async def anomaly_baseline_loop(pool: asyncpg.Pool):
    """Periodically fold completed 1h windows into each signature's learned
    baseline (EMA). Runs every 5 minutes — cheap UPDATE, only rows whose
    1h window has expired actually get touched."""
    while True:
        await asyncio.sleep(300)
        try:
            updated = await anomaly.roll_baselines(pool)
            if updated:
                log.info(f"anomaly baselines rolled for {updated} signatures")
        except Exception as e:
            log.debug(f"baseline roll failed: {e}")


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
    (e.g. processor was restarting when feedback was published)."""
    while True:
        await _refresh_feedback(pool)
        await asyncio.sleep(30)


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


async def main():
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    pool: asyncpg.Pool | None = None
    last_err = None
    for _ in range(30):
        try:
            pool = await asyncpg.create_pool(POSTGRES_DSN, min_size=2, max_size=5)
            break
        except Exception as e:
            last_err = e
            log.info("Waiting for Postgres...")
            await asyncio.sleep(2)
    if pool is None:
        raise RuntimeError(f"Postgres not reachable after 60s: {last_err}")

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

    http_client = httpx.AsyncClient()

    for _ in range(30):
        try:
            await redis_client.ping()
            break
        except Exception:
            log.info("Waiting for Redis...")
            await asyncio.sleep(2)

    await fast_categorizer.init_client()
    if fast_categorizer.enabled():
        log.info("Fast LLM categorizer enabled")
    else:
        log.info("Fast LLM categorizer disabled (PROCESSOR_USE_FAST_LLM=0)")

    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(process_loop(redis_client, pool, http_client))
            tg.create_task(librenms_loop(redis_client, http_client))
            tg.create_task(cleanup_loop())
            tg.create_task(feedback_refresh_loop(pool))
            tg.create_task(feedback_pubsub_loop(redis_client, pool))
            tg.create_task(retention_loop(pool))
            tg.create_task(anomaly_baseline_loop(pool))
    finally:
        await fast_categorizer.close_client()
        await http_client.aclose()
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
