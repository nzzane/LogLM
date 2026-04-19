"""
High-throughput batch writer — buffers events and flushes with COPY.

asyncpg's copy_records_to_table() uses the Postgres COPY protocol which
is 5-10x faster than individual INSERTs at scale. The writer collects
events into a buffer and flushes when either the batch is full or a
time deadline expires — whichever comes first.

Usage:
    writer = BatchWriter(pool, flush_size=500, flush_interval=2.0)
    await writer.start()
    ...
    await writer.push(table, columns, record_tuple)
    ...
    await writer.stop()   # drains remaining buffer
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import asyncpg

log = logging.getLogger(__name__)

DEFAULT_FLUSH_SIZE = int(__import__("os").environ.get("BATCH_FLUSH_SIZE", "500"))
DEFAULT_FLUSH_INTERVAL = float(__import__("os").environ.get("BATCH_FLUSH_INTERVAL", "2.0"))


class BatchWriter:
    __slots__ = (
        "_pool", "_flush_size", "_flush_interval",
        "_buffers", "_lock", "_task", "_stopped",
    )

    def __init__(
        self,
        pool: asyncpg.Pool,
        flush_size: int = DEFAULT_FLUSH_SIZE,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL,
    ):
        self._pool = pool
        self._flush_size = flush_size
        self._flush_interval = flush_interval
        # {(table, columns_tuple): [record_tuples]}
        self._buffers: dict[tuple[str, tuple[str, ...]], list[tuple[Any, ...]]] = {}
        self._lock = asyncio.Lock()
        self._task: asyncio.Task | None = None
        self._stopped = False

    async def start(self) -> None:
        self._task = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        self._stopped = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._flush_all()

    async def push(
        self,
        table: str,
        columns: tuple[str, ...],
        record: tuple[Any, ...],
    ) -> None:
        key = (table, columns)
        batch: list[tuple[Any, ...]] | None = None
        async with self._lock:
            buf = self._buffers.setdefault(key, [])
            buf.append(record)
            if len(buf) >= self._flush_size:
                batch = buf[:]
                buf.clear()
        if batch is not None:
            await self._do_flush(table, columns, batch)

    async def _flush_loop(self) -> None:
        while not self._stopped:
            await asyncio.sleep(self._flush_interval)
            await self._flush_all()

    async def _flush_all(self) -> None:
        async with self._lock:
            snapshot = dict(self._buffers)
            self._buffers.clear()
        for (table, columns), records in snapshot.items():
            if records:
                await self._do_flush(table, columns, records)

    async def _do_flush(
        self,
        table: str,
        columns: tuple[str, ...],
        records: list[tuple[Any, ...]],
    ) -> None:
        t0 = time.perf_counter()
        try:
            async with self._pool.acquire() as conn:
                await conn.copy_records_to_table(
                    table,
                    columns=columns,
                    records=records,
                )
            elapsed = time.perf_counter() - t0
            log.debug(
                f"batch flush {table}: {len(records)} rows in {elapsed:.3f}s "
                f"({len(records)/max(elapsed, 0.001):.0f} rows/s)"
            )
        except Exception as e:
            log.warning(f"batch COPY to {table} failed ({len(records)} rows): {e}")
            await self._fallback_insert(table, columns, records)

    async def _fallback_insert(
        self,
        table: str,
        columns: tuple[str, ...],
        records: list[tuple[Any, ...]],
    ) -> None:
        """Row-by-row INSERT fallback when COPY fails (e.g. constraint
        violation on one row shouldn't drop the whole batch)."""
        col_str = ", ".join(columns)
        placeholders = ", ".join(f"${i+1}" for i in range(len(columns)))
        sql = f"INSERT INTO {table} ({col_str}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"
        ok = 0
        async with self._pool.acquire() as conn:
            for rec in records:
                try:
                    await conn.execute(sql, *rec)
                    ok += 1
                except Exception as e:
                    log.debug(f"fallback insert to {table} failed: {e}")
        if ok < len(records):
            log.warning(f"batch fallback {table}: {ok}/{len(records)} succeeded")
