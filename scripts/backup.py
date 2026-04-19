#!/usr/bin/env python3
"""
LogLM backup script.

Dumps Postgres + copies Redis RDB to a timestamped backup directory.
Run via cron or manually: python scripts/backup.py

Environment variables:
  POSTGRES_DSN    — connection string (required)
  BACKUP_DIR      — destination directory (default: ./backups)
  BACKUP_KEEP     — number of old backups to retain (default: 7)
  REDIS_URL       — for recording backup status (optional)
"""

import asyncio
import glob
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

POSTGRES_DSN = os.environ.get("POSTGRES_DSN", "")
BACKUP_DIR = os.environ.get("BACKUP_DIR", "./backups")
BACKUP_KEEP = int(os.environ.get("BACKUP_KEEP", "7"))
REDIS_RDB_PATH = os.environ.get("REDIS_RDB_PATH", "./data/redis/dump.rdb")
POSTGRES_DSN_PARTS = {}


def parse_dsn(dsn: str) -> dict:
    import re
    m = re.match(r"postgresql://(\w+):([^@]+)@([^:]+):(\d+)/(\w+)", dsn)
    if not m:
        return {}
    return {
        "user": m.group(1), "password": m.group(2),
        "host": m.group(3), "port": m.group(4), "dbname": m.group(5),
    }


def pg_dump(dest: Path) -> tuple[bool, str]:
    parts = parse_dsn(POSTGRES_DSN)
    if not parts:
        return False, "cannot parse POSTGRES_DSN"
    env = os.environ.copy()
    env["PGPASSWORD"] = parts["password"]
    outfile = dest / "postgres.sql.gz"
    try:
        proc = subprocess.run(
            ["pg_dump", "-h", parts["host"], "-p", parts["port"],
             "-U", parts["user"], "-d", parts["dbname"],
             "--no-owner", "--no-privileges", "-Z", "6"],
            capture_output=True, env=env, timeout=600,
        )
        if proc.returncode != 0:
            return False, proc.stderr.decode()[:500]
        outfile.write_bytes(proc.stdout)
        return True, f"{outfile.stat().st_size} bytes"
    except FileNotFoundError:
        return False, "pg_dump not found — install postgresql-client"
    except subprocess.TimeoutExpired:
        return False, "pg_dump timed out after 600s"
    except Exception as e:
        return False, str(e)


def copy_redis_rdb(dest: Path) -> tuple[bool, str]:
    src = Path(REDIS_RDB_PATH)
    if not src.is_file():
        return False, f"RDB not found at {REDIS_RDB_PATH}"
    try:
        dst = dest / "redis-dump.rdb"
        shutil.copy2(src, dst)
        return True, f"{dst.stat().st_size} bytes"
    except Exception as e:
        return False, str(e)


def prune_old(base: Path):
    dirs = sorted(base.glob("backup-*"), key=lambda p: p.name, reverse=True)
    for old in dirs[BACKUP_KEEP:]:
        try:
            shutil.rmtree(old)
            print(f"Pruned old backup: {old.name}")
        except Exception as e:
            print(f"Failed to prune {old.name}: {e}")


async def record_backup(kind: str, dest: str, size: int | None,
                         duration: float, status: str, detail: str):
    try:
        import asyncpg
        pool = await asyncpg.create_pool(POSTGRES_DSN, min_size=1, max_size=1)
        async with pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO backup_log (kind, destination, size_bytes, duration_s, status, detail)
                   VALUES ($1, $2, $3, $4, $5, $6)""",
                kind, dest, size, duration, status, detail,
            )
        await pool.close()
    except Exception as e:
        print(f"Failed to record backup in DB: {e}")


def main():
    if not POSTGRES_DSN:
        print("POSTGRES_DSN not set")
        sys.exit(1)

    base = Path(BACKUP_DIR)
    base.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dest = base / f"backup-{ts}"
    dest.mkdir()
    print(f"Backup destination: {dest}")

    t0 = time.time()
    pg_ok, pg_detail = pg_dump(dest)
    pg_dur = time.time() - t0
    pg_size = (dest / "postgres.sql.gz").stat().st_size if pg_ok else None
    print(f"Postgres: {'OK' if pg_ok else 'FAIL'} ({pg_detail})")

    t1 = time.time()
    redis_ok, redis_detail = copy_redis_rdb(dest)
    redis_dur = time.time() - t1
    redis_size = (dest / "redis-dump.rdb").stat().st_size if redis_ok else None
    print(f"Redis: {'OK' if redis_ok else 'FAIL'} ({redis_detail})")

    prune_old(base)

    asyncio.run(record_backup(
        "full", str(dest),
        (pg_size or 0) + (redis_size or 0),
        pg_dur + redis_dur,
        "ok" if pg_ok and redis_ok else "error",
        f"pg={pg_detail}; redis={redis_detail}",
    ))

    if not pg_ok or not redis_ok:
        sys.exit(1)
    print("Backup complete.")


if __name__ == "__main__":
    main()
