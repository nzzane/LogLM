"""
Intelligent Logging Pipeline — Three-Tier Storage with Feedback Loop.

=============================================================================
Tier Definitions
=============================================================================

  HOT  (events table, verdict='keep', age < WARM_THRESHOLD_DAYS)
       Full row, indexed, directly queryable via the log browser.
       Events that generated an alert inherit a ``retention_boost`` that
       delays their graduation to WARM by BOOST_EXTRA_DAYS.

  WARM (events table, any verdict, WARM_THRESHOLD_DAYS < age < COLD_THRESHOLD_DAYS)
       Still in the main ``events`` partitioned table but in an older
       partition.  The log browser shows them on request.  No extra overhead.

  COLD (cold_events_archive table)
       Events older than COLD_THRESHOLD_DAYS are compressed as a JSONB blob
       keyed by (host, source, date).  The original rows are deleted from
       ``events``.  Cold data is only searched via /api/logs/cold.

=============================================================================
Feedback Loop
=============================================================================

When a Tier 2 or Tier 3 alert fires, the analyzer writes the contributing
``event_ids`` into ``alert_event_links``.  The tiering engine reads this
table and marks those events with ``retention_boost=TRUE`` in the events
table — they stay in HOT for BOOST_EXTRA_DAYS longer.

This implements the "learning from errors" requirement: events that once
mattered are kept queryable longer for post-incident forensics.

=============================================================================
Background Task
=============================================================================

  archive_cold_batch():  Called hourly by the background task.
    1. Find events older than COLD_THRESHOLD_DAYS with no retention_boost.
    2. Group them by (host, source, date).
    3. Compress each group into a JSONB blob in cold_events_archive.
    4. DELETE the originals from events.
    5. Record archive stats per batch.

  search_cold(pool, query, host, start, end, limit):
    Full-text ILIKE search against cold_events_archive.search_index.
    Returns decompressed matching events from the blob.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone, timedelta, date
from enum import Enum
from typing import Any

import asyncpg

log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

WARM_THRESHOLD_DAYS  = int(os.environ.get("LOG_WARM_DAYS",  "7"))
COLD_THRESHOLD_DAYS  = int(os.environ.get("LOG_COLD_DAYS",  "30"))
BOOST_EXTRA_DAYS     = int(os.environ.get("LOG_BOOST_DAYS", "14"))
ARCHIVE_BATCH_SIZE   = int(os.environ.get("LOG_ARCHIVE_BATCH", "2000"))
ARCHIVE_INTERVAL_S   = int(os.environ.get("LOG_ARCHIVE_INTERVAL_S", "3600"))

# ── Tier definitions ──────────────────────────────────────────────────────────

class EventTier(str, Enum):
    HOT  = "hot"
    WARM = "warm"
    COLD = "cold"


def classify_tier(event_timestamp: datetime, has_boost: bool, verdict: str) -> EventTier:
    """Return the expected storage tier for an event."""
    age_days = (datetime.now(timezone.utc) - event_timestamp).days
    effective_warm = WARM_THRESHOLD_DAYS + (BOOST_EXTRA_DAYS if has_boost else 0)
    effective_cold = COLD_THRESHOLD_DAYS + (BOOST_EXTRA_DAYS if has_boost else 0)
    if age_days < effective_warm:
        return EventTier.HOT
    if age_days < effective_cold:
        return EventTier.WARM
    return EventTier.COLD


# ── Feedback loop: mark alert-linked events ───────────────────────────────────

async def mark_alert_events_for_retention(pool: asyncpg.Pool, alert_id: int) -> int:
    """
    Given an alert_id, find all events that were analysed in the batch that
    generated this alert (using alert_event_links) and set retention_boost=TRUE.
    Returns the count of events updated.

    This is the feedback loop: "this batch was important — keep the raw events
    queryable longer, even as they age past the normal WARM threshold."
    """
    try:
        async with pool.acquire() as conn:
            # alert_event_links: populated by analyzer when it fires an alert
            event_ids = await conn.fetch(
                "SELECT event_id FROM alert_event_links WHERE alert_id=$1",
                alert_id,
            )
            if not event_ids:
                return 0
            ids = [r["event_id"] for r in event_ids]
            result = await conn.execute(
                "UPDATE events SET retention_boost=TRUE WHERE id = ANY($1)",
                ids,
            )
        n = int(result.split()[-1]) if result else 0
        log.debug(f"retention_boost: {n} events linked to alert {alert_id}")
        return n
    except Exception as e:
        log.debug(f"mark_alert_events failed: {e}")
        return 0


async def apply_retention_boost_from_recent_alerts(pool: asyncpg.Pool, hours: int = 2) -> int:
    """
    Scan alerts from the last `hours` hours via the raw_result event_count field
    and mark all events in those batches for retention.  Called at startup and
    by the archive loop before archiving to avoid premature cold-tiering of
    recently-important events.
    """
    try:
        async with pool.acquire() as conn:
            # Join events to alerts via affected_hosts and time window
            result = await conn.execute(
                """UPDATE events SET retention_boost = TRUE
                   WHERE timestamp > NOW() - ($1 * INTERVAL '1 hour')
                     AND host IN (
                         SELECT UNNEST(affected_hosts) FROM alerts
                         WHERE timestamp > NOW() - ($1 * INTERVAL '1 hour')
                     )
                     AND verdict = 'keep'
                     AND NOT COALESCE(retention_boost, FALSE)""",
                hours,
            )
        n = int(result.split()[-1]) if result else 0
        if n:
            log.info(f"log_tiers: retention_boost applied to {n} events from recent alerts")
        return n
    except Exception as e:
        log.debug(f"apply_retention_boost failed: {e}")
        return 0


# ── Cold archival ─────────────────────────────────────────────────────────────

async def archive_cold_batch(pool: asyncpg.Pool) -> dict:
    """
    Move qualifying events to cold storage in one batch.
    Returns stats dict: {archived: N, deleted: N, skipped: N}
    """
    stats = {"archived": 0, "deleted": 0, "skipped": 0, "errors": 0}
    cutoff = datetime.now(timezone.utc) - timedelta(days=COLD_THRESHOLD_DAYS)

    # Protect boosted events from early archival
    await apply_retention_boost_from_recent_alerts(pool, hours=COLD_THRESHOLD_DAYS * 24)

    try:
        async with pool.acquire() as conn:
            # Identify candidate groups (host, source, date) to archive
            groups = await conn.fetch(
                """SELECT host, source, DATE(timestamp) AS day, COUNT(*) AS cnt
                   FROM events
                   WHERE timestamp < $1
                     AND NOT COALESCE(retention_boost, FALSE)
                   GROUP BY host, source, DATE(timestamp)
                   ORDER BY day
                   LIMIT 100""",
                cutoff,
            )

        for group in groups:
            host   = group["host"]
            source = group["source"]
            day    = group["day"]
            day_start = datetime.combine(day,   datetime.min.time(), tzinfo=timezone.utc)
            day_end   = datetime.combine(day + timedelta(days=1),
                                          datetime.min.time(), tzinfo=timezone.utc)

            try:
                async with pool.acquire() as conn:
                    rows = await conn.fetch(
                        """SELECT id, timestamp, severity, program, message, structured
                           FROM events
                           WHERE host=$1 AND source=$2
                             AND timestamp >= $3 AND timestamp < $4
                             AND NOT COALESCE(retention_boost, FALSE)
                           ORDER BY timestamp
                           LIMIT $5""",
                        host, source, day_start, day_end, ARCHIVE_BATCH_SIZE,
                    )
                    if not rows:
                        continue

                    events_blob = [
                        {
                            "id":         r["id"],
                            "ts":         r["timestamp"].isoformat(),
                            "sev":        r["severity"],
                            "prog":       r["program"] or "",
                            "msg":        r["message"],
                            "structured": dict(r["structured"] or {}),
                        }
                        for r in rows
                    ]
                    search_index = " ".join(
                        r["message"][:100] for r in rows
                    )[:60000]

                    await conn.execute(
                        """INSERT INTO cold_events_archive
                               (host, source, archived_date, event_count,
                                events_blob, search_index)
                           VALUES ($1, $2, $3, $4, $5::jsonb, $6)
                           ON CONFLICT (host, source, archived_date)
                           DO UPDATE SET
                               events_blob   = cold_events_archive.events_blob || $5::jsonb,
                               event_count   = cold_events_archive.event_count + $4,
                               search_index  = cold_events_archive.search_index || ' ' || $6,
                               archived_at   = NOW()""",
                        host, source, day, len(rows),
                        json.dumps(events_blob),
                        search_index,
                    )

                    ids = [r["id"] for r in rows]
                    del_result = await conn.execute(
                        "DELETE FROM events WHERE id = ANY($1)", ids
                    )
                    deleted_n = int(del_result.split()[-1]) if del_result else len(ids)
                    stats["archived"] += len(rows)
                    stats["deleted"]  += deleted_n

            except Exception as e:
                log.warning(f"cold archive failed for {host}/{source}/{day}: {e}")
                stats["errors"] += 1

    except Exception as e:
        log.error(f"archive_cold_batch outer error: {e}", exc_info=True)
        stats["errors"] += 1

    if stats["archived"]:
        log.info(f"cold archive: {stats}")
    return stats


async def search_cold(
    pool: asyncpg.Pool,
    query: str | None = None,
    host:  str | None = None,
    start: datetime | None = None,
    end:   datetime | None = None,
    limit: int = 200,
) -> list[dict]:
    """
    Search cold-archived events.
    Returns individual event dicts decompressed from the blob.
    """
    filters = ["1=1"]
    params: list[Any] = []
    idx = 1

    if host:
        filters.append(f"host = ${idx}"); params.append(host); idx += 1
    if start:
        filters.append(f"archived_date >= ${idx}"); params.append(start.date()); idx += 1
    if end:
        filters.append(f"archived_date <= ${idx}"); params.append(end.date()); idx += 1
    if query:
        filters.append(f"search_index ILIKE ${idx}")
        params.append(f"%{query}%"); idx += 1

    where = " AND ".join(filters)
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                f"""SELECT host, source, archived_date, event_count, events_blob
                    FROM cold_events_archive
                    WHERE {where}
                    ORDER BY archived_date DESC
                    LIMIT 50""",
                *params,
            )
    except Exception as e:
        log.debug(f"cold search failed: {e}")
        return []

    results: list[dict] = []
    for row in rows:
        blob = row["events_blob"]
        events = blob if isinstance(blob, list) else []
        # Filter events within blob by query string if provided
        for ev in events:
            if query and query.lower() not in (ev.get("msg") or "").lower():
                continue
            results.append({
                "host":   row["host"],
                "source": row["source"],
                "tier":   "cold",
                **ev,
            })
        if len(results) >= limit:
            break

    return results[:limit]


async def get_tier_stats(pool: asyncpg.Pool) -> dict:
    """Return counts of events in each tier for the dashboard."""
    try:
        async with pool.acquire() as conn:
            hot = await conn.fetchval(
                "SELECT COUNT(*) FROM events "
                "WHERE timestamp > NOW() - ($1 * INTERVAL '1 day')",
                WARM_THRESHOLD_DAYS,
            )
            warm = await conn.fetchval(
                "SELECT COUNT(*) FROM events "
                "WHERE timestamp <= NOW() - ($1 * INTERVAL '1 day')"
                "  AND timestamp >  NOW() - ($2 * INTERVAL '1 day')",
                WARM_THRESHOLD_DAYS, COLD_THRESHOLD_DAYS,
            )
            cold_groups = await conn.fetchval(
                "SELECT COALESCE(SUM(event_count),0) FROM cold_events_archive"
            )
            boosted = await conn.fetchval(
                "SELECT COUNT(*) FROM events WHERE retention_boost=TRUE"
            )
        return {
            "hot":     int(hot or 0),
            "warm":    int(warm or 0),
            "cold":    int(cold_groups or 0),
            "boosted": int(boosted or 0),
            "hot_threshold_days":  WARM_THRESHOLD_DAYS,
            "cold_threshold_days": COLD_THRESHOLD_DAYS,
            "boost_extra_days":    BOOST_EXTRA_DAYS,
        }
    except Exception as e:
        log.debug(f"get_tier_stats failed: {e}")
        return {"hot": 0, "warm": 0, "cold": 0, "boosted": 0}


# ── Background archival loop ──────────────────────────────────────────────────

async def archive_loop(pool: asyncpg.Pool) -> None:
    """Background task: archives cold events hourly."""
    log.info(f"Log tier archive loop started: cold_threshold={COLD_THRESHOLD_DAYS}d "
             f"interval={ARCHIVE_INTERVAL_S}s")
    # Initial delay: let the application fully start up
    await asyncio.sleep(300)
    while True:
        try:
            stats = await archive_cold_batch(pool)
            if stats["errors"]:
                log.warning(f"cold archive completed with {stats['errors']} errors")
        except Exception as e:
            log.error(f"archive_loop error: {e}", exc_info=True)
        await asyncio.sleep(ARCHIVE_INTERVAL_S)
