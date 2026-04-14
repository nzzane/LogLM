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
from datetime import datetime, timezone

import asyncpg
import httpx
import redis.asyncio as aioredis

from parser import parse
from filter import classify, _rate_limiter

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


async def process_loop(redis_client, pool: asyncpg.Pool, http_client: httpx.AsyncClient):
    log.info("Processor started, draining loglm:raw")
    while True:
        item = await redis_client.blpop("loglm:raw", timeout=1)
        if item is None:
            continue
        _, raw_bytes = item
        try:
            raw = json.loads(raw_bytes)
        except json.JSONDecodeError:
            continue

        event = parse(raw)
        verdict = classify(event)

        if verdict == "drop":
            continue

        await asyncio.gather(
            send_to_loki(http_client, event, verdict),
            record_event_pg(pool, event, verdict),
        )

        if verdict == "keep":
            await redis_client.rpush("loglm:analysis", json.dumps(event))


async def librenms_loop(redis_client, http_client: httpx.AsyncClient):
    while True:
        await poll_librenms(redis_client, http_client)
        await asyncio.sleep(LIBRENMS_POLL_INTERVAL)


async def cleanup_loop():
    while True:
        await asyncio.sleep(1800)
        _rate_limiter.cleanup()


async def main():
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    pool = await asyncpg.create_pool(POSTGRES_DSN, min_size=2, max_size=5)
    http_client = httpx.AsyncClient()

    for _ in range(30):
        try:
            await redis_client.ping()
            break
        except Exception:
            log.info("Waiting for Redis...")
            await asyncio.sleep(2)

    async with asyncio.TaskGroup() as tg:
        tg.create_task(process_loop(redis_client, pool, http_client))
        tg.create_task(librenms_loop(redis_client, http_client))
        tg.create_task(cleanup_loop())


if __name__ == "__main__":
    asyncio.run(main())
