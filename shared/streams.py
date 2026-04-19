"""
Redis Streams abstraction for LogLM's priority event pipeline.

Replaces the LIST-based (RPUSH/BLPOP) queues with Redis Streams, gaining:
  - Consumer groups → at-least-once delivery, no lost events on crash
  - XACK → explicit completion, pending entries re-delivered after timeout
  - MAXLEN trimming → bounded memory without a separate cron
  - Per-entry IDs → natural ordering + dedup by stream position
  - DLQ → events that fail N times get moved aside for inspection

Stream layout mirrors the old priority lists:
  loglm:raw:hi   → loglm:stream:hi
  loglm:raw:mid  → loglm:stream:mid
  loglm:raw:lo   → loglm:stream:lo
  loglm:analysis → loglm:stream:analysis
  loglm:dlq      → dead-letter queue (all priorities)

Consumer group: "processors" for raw, "analyzers" for analysis.
Each worker is a consumer named "w{id}" within the group.
"""

from __future__ import annotations

import json
import logging
import os

import redis.asyncio as aioredis

log = logging.getLogger(__name__)

# Stream keys.
STREAM_HI = "loglm:stream:hi"
STREAM_MID = "loglm:stream:mid"
STREAM_LO = "loglm:stream:lo"
STREAM_ANALYSIS = "loglm:stream:analysis"          # general syslog
STREAM_ANALYSIS_SNMP = "loglm:stream:analysis:snmp"   # SNMP / network hardware
STREAM_ANALYSIS_NGINX = "loglm:stream:analysis:nginx"  # nginx / web proxy
STREAM_DLQ = "loglm:dlq"

RAW_STREAMS = [STREAM_HI, STREAM_MID, STREAM_LO]
ANALYSIS_STREAMS = [STREAM_ANALYSIS, STREAM_ANALYSIS_SNMP, STREAM_ANALYSIS_NGINX]

# Consumer groups.
GROUP_PROCESSORS = "processors"
GROUP_ANALYZERS = "analyzers"

# Trimming: approximate MAXLEN per stream. ~100k entries × ~500B ≈ 50MB each.
MAXLEN = int(os.environ.get("STREAM_MAXLEN", "100000"))

# Pending entry redelivery: events not ACKed within this window (ms) are
# re-claimed by XAUTOCLAIM. Set generously — a slow LLM call can take 2min.
CLAIM_MIN_IDLE_MS = int(os.environ.get("STREAM_CLAIM_IDLE_MS", "120000"))

# After this many delivery attempts, move to DLQ instead of re-claiming.
MAX_DELIVERIES = int(os.environ.get("STREAM_MAX_DELIVERIES", "5"))


async def ensure_groups(redis: aioredis.Redis) -> None:
    """Create consumer groups if they don't exist. Idempotent."""
    for stream in RAW_STREAMS:
        try:
            await redis.xgroup_create(stream, GROUP_PROCESSORS, id="0", mkstream=True)
        except aioredis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise
    for stream in ANALYSIS_STREAMS:
        try:
            await redis.xgroup_create(stream, GROUP_ANALYZERS, id="0", mkstream=True)
        except aioredis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise
    log.info("stream consumer groups ready")


async def xadd_event(
    redis: aioredis.Redis,
    stream: str,
    event_json: str,
    maxlen: int = MAXLEN,
) -> str:
    """Add one serialised event to a stream. Returns the entry ID."""
    return await redis.xadd(stream, {"d": event_json}, maxlen=maxlen, approximate=True)


async def xadd_batch(
    redis: aioredis.Redis,
    stream: str,
    events: list[str],
    maxlen: int = MAXLEN,
) -> int:
    """Pipeline-add a batch of events. Returns count added."""
    if not events:
        return 0
    pipe = redis.pipeline(transaction=False)
    for ev in events:
        pipe.xadd(stream, {"d": ev}, maxlen=maxlen, approximate=True)
    await pipe.execute()
    return len(events)


async def xread_group(
    redis: aioredis.Redis,
    group: str,
    consumer: str,
    streams: list[str],
    count: int = 1,
    block_ms: int = 1000,
) -> list[tuple[str, str, str]]:
    """Read new entries from multiple streams via consumer group.
    Returns [(stream, entry_id, event_json), ...]."""
    stream_ids = {s: ">" for s in streams}
    result = await redis.xreadgroup(
        group, consumer, stream_ids, count=count, block=block_ms,
    )
    if not result:
        return []
    out = []
    for stream_name, entries in result:
        s = stream_name if isinstance(stream_name, str) else stream_name.decode()
        for entry_id, fields in entries:
            eid = entry_id if isinstance(entry_id, str) else entry_id.decode()
            data = fields.get("d") or fields.get(b"d") or ""
            if isinstance(data, bytes):
                data = data.decode()
            out.append((s, eid, data))
    return out


async def xack(
    redis: aioredis.Redis,
    stream: str,
    group: str,
    entry_id: str,
) -> None:
    """Acknowledge + delete a successfully processed entry."""
    await redis.xack(stream, group, entry_id)
    await redis.xdel(stream, entry_id)


async def claim_stale(
    redis: aioredis.Redis,
    group: str,
    consumer: str,
    streams: list[str],
) -> list[tuple[str, str, str]]:
    """Reclaim entries that have been pending too long. Entries that exceed
    MAX_DELIVERIES are moved to the DLQ."""
    reclaimed = []
    for stream in streams:
        try:
            result = await redis.xautoclaim(
                stream, group, consumer,
                min_idle_time=CLAIM_MIN_IDLE_MS,
                start_id="0-0",
                count=10,
            )
            if not result or len(result) < 2:
                continue
            entries = result[1]
            for entry_id, fields in entries:
                eid = entry_id if isinstance(entry_id, str) else entry_id.decode()
                data = fields.get("d") or fields.get(b"d") or ""
                if isinstance(data, bytes):
                    data = data.decode()
                info = await redis.xpending_range(stream, group, eid, eid, 1)
                deliveries = info[0]["times_delivered"] if info else 1
                if deliveries >= MAX_DELIVERIES:
                    await redis.xadd(STREAM_DLQ, {
                        "d": data,
                        "src": stream,
                        "deliveries": str(deliveries),
                    })
                    await xack(redis, stream, group, eid)
                    log.warning(f"DLQ: {stream} entry {eid} after {deliveries} attempts")
                else:
                    reclaimed.append((stream, eid, data))
        except Exception as e:
            log.debug(f"xautoclaim {stream} failed: {e}")
    return reclaimed


# ── Legacy bridge ───────────────────────────────────────────────────────────
# On startup, drain any remaining LIST entries into streams so a rolling
# upgrade from LIST→Stream doesn't lose in-flight events.

_LEGACY_MAP = {
    "loglm:raw:hi": STREAM_HI,
    "loglm:raw:mid": STREAM_MID,
    "loglm:raw:lo": STREAM_LO,
    "loglm:raw": STREAM_MID,
    "loglm:analysis": STREAM_ANALYSIS,
}


async def drain_legacy_lists(redis: aioredis.Redis) -> int:
    """Move events from old LIST keys into the corresponding streams."""
    total = 0
    for list_key, stream_key in _LEGACY_MAP.items():
        moved = 0
        while True:
            item = await redis.lpop(list_key)
            if item is None:
                break
            await redis.xadd(stream_key, {"d": item}, maxlen=MAXLEN, approximate=True)
            moved += 1
        if moved:
            log.info(f"drained {moved} events from legacy {list_key} → {stream_key}")
            total += moved
    return total
