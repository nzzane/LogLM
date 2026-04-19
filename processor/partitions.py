"""
Partition lifecycle — create ahead, drop old.

Calls the Postgres functions created in init.sql:
  create_monthly_partitions(table, months_ahead)
  drop_old_partitions(table, cutoff_days)

The processor runs ensure_partitions() on startup and every hour so
partitions always exist before any INSERT lands.
"""

from __future__ import annotations

import logging

import asyncpg

log = logging.getLogger(__name__)

PARTITIONED_TABLES = ("events", "firewall_flows", "snmp_metrics")
MONTHS_AHEAD = 2

# Retention cutoffs (days) for partition-level DROP. Must be >= the
# longest retention_policies row for that table.
PARTITION_RETENTION = {
    "events": 120,
    "firewall_flows": 60,
    "snmp_metrics": 120,
}


async def ensure_partitions(pool: asyncpg.Pool) -> int:
    total = 0
    async with pool.acquire() as conn:
        for table in PARTITIONED_TABLES:
            try:
                n = await conn.fetchval(
                    "SELECT create_monthly_partitions($1, $2)",
                    table, MONTHS_AHEAD,
                )
                if n:
                    log.info(f"created {n} partition(s) for {table}")
                    total += n
            except Exception as e:
                log.warning(f"partition create for {table} failed: {e}")
    return total


async def drop_expired(pool: asyncpg.Pool) -> int:
    total = 0
    async with pool.acquire() as conn:
        for table, days in PARTITION_RETENTION.items():
            try:
                n = await conn.fetchval(
                    "SELECT drop_old_partitions($1, $2)",
                    table, days,
                )
                if n:
                    log.info(f"dropped {n} expired partition(s) from {table}")
                    total += n
            except Exception as e:
                log.warning(f"partition drop for {table} failed: {e}")
    return total
