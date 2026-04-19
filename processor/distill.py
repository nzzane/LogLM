"""
LLM verdict distillation.

Tracks how the fast LLM classifies each log signature. After a signature
accumulates enough consistent verdicts (PROMOTE_THRESHOLD), auto-promotes
it into event_feedback so the static classifier handles it without LLM.

This reduces LLM calls over time as the system "learns" from its own output.
"""

from __future__ import annotations

import asyncio
import logging
import os

import asyncpg

log = logging.getLogger(__name__)

PROMOTE_THRESHOLD = int(os.environ.get("DISTILL_PROMOTE_THRESHOLD", "20"))
PROMOTE_AGREEMENT = float(os.environ.get("DISTILL_PROMOTE_AGREEMENT", "0.9"))
DISTILL_INTERVAL = int(os.environ.get("DISTILL_INTERVAL_SEC", "600"))


async def init_schema(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS llm_verdict_log (
                id         BIGSERIAL PRIMARY KEY,
                signature  TEXT NOT NULL,
                host       TEXT,
                program    TEXT,
                verdict    TEXT NOT NULL,
                category   TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_llm_verdict_sig
                ON llm_verdict_log (signature);
        """)


async def record(pool: asyncpg.Pool, sig: str, host: str,
                 program: str, verdict: str, category: str) -> None:
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO llm_verdict_log (signature, host, program, verdict, category) "
                "VALUES ($1, $2, $3, $4, $5)",
                sig, host, program, verdict, category,
            )
    except Exception as e:
        log.debug(f"distill record failed: {e}")


async def promote_loop(pool: asyncpg.Pool) -> None:
    await asyncio.sleep(DISTILL_INTERVAL)
    while True:
        try:
            await _promote_batch(pool)
        except Exception as e:
            log.warning(f"distill promote failed: {e}")
        await asyncio.sleep(DISTILL_INTERVAL)


async def _promote_batch(pool: asyncpg.Pool) -> int:
    """Find signatures with enough consistent verdicts, promote to event_feedback."""
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            WITH agg AS (
                SELECT signature, host, program,
                       verdict, COUNT(*) AS cnt,
                       SUM(COUNT(*)) OVER (PARTITION BY signature) AS total
                FROM llm_verdict_log
                WHERE created_at > NOW() - INTERVAL '7 days'
                GROUP BY signature, host, program, verdict
            )
            SELECT signature, host, program, verdict, cnt, total
            FROM agg
            WHERE total >= $1
              AND cnt::float / total >= $2
              AND verdict IN ('keep', 'drop')
            ORDER BY total DESC
            LIMIT 50
        """, PROMOTE_THRESHOLD, PROMOTE_AGREEMENT)

    promoted = 0
    for r in rows:
        pat = r["signature"].split("|", 3)[-1][:200]
        if not pat or len(pat) < 5:
            continue
        fb_verdict = "important" if r["verdict"] == "keep" else "ignore"
        try:
            async with pool.acquire() as conn:
                existing = await conn.fetchval(
                    "SELECT id FROM event_feedback WHERE pattern = $1 AND host = $2",
                    pat, r["host"],
                )
                if existing:
                    continue
                await conn.execute(
                    "INSERT INTO event_feedback (host, program, pattern, verdict) "
                    "VALUES ($1, $2, $3, $4)",
                    r["host"], r["program"], pat, fb_verdict,
                )
            promoted += 1
        except Exception as e:
            log.debug(f"distill promote insert failed: {e}")

    if promoted:
        log.info(f"distill: promoted {promoted} LLM patterns → event_feedback")
    return promoted
