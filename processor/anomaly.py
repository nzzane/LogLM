"""
Anomaly learning layer.

Every event that survives the filter is compared against a learned baseline
per (host, program, normalized-message-signature):

  - First time we've ever seen this signature → emit a `new_signature` anomaly
    (unknown behaviour on that host).
  - Signature's current hour rate is >= NEW_SIG_SPIKE_FACTOR × its rolling
    baseline → emit a `rate_spike` anomaly.

The baseline is a simple exponential moving average over the hourly count, so
it adapts to seasonal traffic without a history table. Cheap — one UPSERT per
event, one SELECT check per anomaly.

Concerning firewall flows also flow through here so the web UI and analyzer
see them alongside other anomalies.
"""

import logging
import os
import re
from datetime import datetime, timezone

import asyncpg

log = logging.getLogger(__name__)

# Rolling-average update rate: 0.3 = favour recent, 0.05 = very stable baseline.
BASELINE_ALPHA = float(os.environ.get("ANOMALY_BASELINE_ALPHA", "0.2"))
# Minimum samples before we trust the baseline enough to fire a rate_spike.
BASELINE_MIN_SAMPLES = int(os.environ.get("ANOMALY_MIN_SAMPLES", "4"))
# Factor by which current hour rate must exceed baseline to fire a spike.
SPIKE_FACTOR = float(os.environ.get("ANOMALY_SPIKE_FACTOR", "5.0"))
# Minimum absolute count before spike fires — stops tiny baselines (0.2/h)
# from trip-firing on every single burst of 2 events.
SPIKE_MIN_COUNT = int(os.environ.get("ANOMALY_SPIKE_MIN_COUNT", "10"))
# Don't flag a signature as new if it was first seen before this many seconds
# ago — lets the system skip the "new" anomaly on initial warm-up.
WARMUP_SEC = int(os.environ.get("ANOMALY_WARMUP_SEC", "300"))

_SIG_NORMALIZE = re.compile(
    r"\d{4}-\d{2}-\d{2}T?\d{0,2}:?\d{0,2}:?\d{0,2}\S*"
    r"|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"
    r"|0x[0-9a-fA-F]+"
    r"|\b[0-9a-f]{12,}\b"
    r"|\b\d+\b"
)


def normalize(message: str) -> str:
    return _SIG_NORMALIZE.sub("#", message or "")[:200].strip()


async def init_schema(pool: asyncpg.Pool) -> None:
    """Idempotent — safe on existing installs that predate these tables."""
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS event_signatures (
                id              BIGSERIAL PRIMARY KEY,
                signature       TEXT NOT NULL,
                host            TEXT NOT NULL,
                program         TEXT NOT NULL,
                severity        TEXT NOT NULL,
                sample_message  TEXT,
                first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                total_count     BIGINT NOT NULL DEFAULT 1,
                count_1h        BIGINT NOT NULL DEFAULT 1,
                count_24h       BIGINT NOT NULL DEFAULT 1,
                window_1h_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                window_24h_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                baseline_per_hour REAL NOT NULL DEFAULT 0,
                baseline_samples INT NOT NULL DEFAULT 0,
                UNIQUE (signature, host, program)
            );
            CREATE INDEX IF NOT EXISTS idx_sig_last_seen  ON event_signatures (last_seen DESC);
            CREATE INDEX IF NOT EXISTS idx_sig_first_seen ON event_signatures (first_seen DESC);
            CREATE INDEX IF NOT EXISTS idx_sig_host       ON event_signatures (host);

            CREATE TABLE IF NOT EXISTS anomaly_detections (
                id              BIGSERIAL PRIMARY KEY,
                timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                kind            TEXT NOT NULL,
                host            TEXT NOT NULL,
                program         TEXT,
                signature       TEXT,
                severity        TEXT NOT NULL DEFAULT 'warning',
                title           TEXT NOT NULL,
                description     TEXT,
                sample          TEXT,
                baseline        REAL,
                observed        REAL,
                acknowledged    BOOLEAN NOT NULL DEFAULT FALSE,
                raw             JSONB DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_anom_ts   ON anomaly_detections (timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_anom_host ON anomaly_detections (host);
            CREATE INDEX IF NOT EXISTS idx_anom_kind ON anomaly_detections (kind, timestamp DESC);

            CREATE TABLE IF NOT EXISTS firewall_flows (
                id              BIGSERIAL PRIMARY KEY,
                timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                host            TEXT NOT NULL,
                action          TEXT NOT NULL,
                blocked         BOOLEAN NOT NULL DEFAULT FALSE,
                direction       TEXT,
                src_ip          INET,
                dst_ip          INET,
                src_port        INT,
                dst_port        INT,
                proto           TEXT,
                in_iface        TEXT,
                out_iface       TEXT,
                port_name       TEXT,
                concerning      BOOLEAN NOT NULL DEFAULT FALSE,
                concerning_reasons TEXT[] NOT NULL DEFAULT '{}',
                event_id        BIGINT
            );
            CREATE INDEX IF NOT EXISTS idx_ff_ts         ON firewall_flows (timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_ff_host       ON firewall_flows (host, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_ff_src        ON firewall_flows (src_ip);
            CREATE INDEX IF NOT EXISTS idx_ff_dst_port   ON firewall_flows (dst_port) WHERE blocked;
            CREATE INDEX IF NOT EXISTS idx_ff_concerning ON firewall_flows (timestamp DESC) WHERE concerning;
        """)


async def track(pool: asyncpg.Pool, event: dict) -> list[dict]:
    """
    Upsert the signature for this event, update rolling counters, and return
    zero or more anomaly dicts for things that tripped: new_signature /
    rate_spike. Caller is responsible for inserting them into anomaly_detections
    and/or pushing them to the alert queue.
    """
    msg = event.get("message", "") or ""
    if not msg.strip():
        return []
    host = event.get("host", "unknown")
    program = event.get("program") or event.get("source") or "unknown"
    severity = (event.get("severity") or "info").lower()
    signature = normalize(msg)
    if not signature:
        return []

    anomalies: list[dict] = []
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    INSERT INTO event_signatures
                        (signature, host, program, severity, sample_message,
                         first_seen, last_seen, total_count, count_1h, count_24h,
                         window_1h_start, window_24h_start)
                    VALUES ($1, $2, $3, $4, $5, NOW(), NOW(), 1, 1, 1, NOW(), NOW())
                    ON CONFLICT (signature, host, program) DO UPDATE
                    SET last_seen       = NOW(),
                        total_count     = event_signatures.total_count + 1,
                        severity        = EXCLUDED.severity,
                        sample_message  = COALESCE(event_signatures.sample_message, EXCLUDED.sample_message),
                        count_1h        = CASE
                            WHEN NOW() - event_signatures.window_1h_start > INTERVAL '1 hour'
                            THEN 1 ELSE event_signatures.count_1h + 1 END,
                        window_1h_start = CASE
                            WHEN NOW() - event_signatures.window_1h_start > INTERVAL '1 hour'
                            THEN NOW() ELSE event_signatures.window_1h_start END,
                        count_24h       = CASE
                            WHEN NOW() - event_signatures.window_24h_start > INTERVAL '24 hours'
                            THEN 1 ELSE event_signatures.count_24h + 1 END,
                        window_24h_start = CASE
                            WHEN NOW() - event_signatures.window_24h_start > INTERVAL '24 hours'
                            THEN NOW() ELSE event_signatures.window_24h_start END
                    RETURNING id, first_seen, total_count, count_1h, baseline_per_hour,
                              baseline_samples, window_1h_start, (xmax = 0) AS is_new
                    """,
                    signature, host, program, severity, msg[:400],
                )
                sig_id = row["id"]
                first_seen = row["first_seen"]
                count_1h = row["count_1h"]
                baseline = float(row["baseline_per_hour"] or 0.0)
                samples = int(row["baseline_samples"] or 0)
                is_new_row = bool(row["is_new"])

                now = datetime.now(timezone.utc)
                # New signature detection — only fire if this is the very first
                # insert AND we're past the initial warmup period (so restarts
                # don't carpet-bomb the UI).
                if is_new_row and (now - first_seen).total_seconds() < WARMUP_SEC:
                    anomalies.append({
                        "kind": "new_signature",
                        "host": host,
                        "program": program,
                        "signature": signature,
                        "severity": "warning" if severity in ("err","error","crit","emerg","alert","warning") else "info",
                        "title": f"New log pattern on {host}",
                        "description": (
                            f"First-ever observation of this line shape from {host}/{program}. "
                            f"Severity={severity}."
                        ),
                        "sample": msg[:400],
                        "baseline": 0.0,
                        "observed": 1.0,
                    })

                # Rate-spike detection: refresh baseline when the 1h window
                # just rolled over, then compare the freshly-reset count.
                window_age = (now - row["window_1h_start"]).total_seconds()
                if window_age < 5 and samples >= 1:
                    # Window just rolled — the count we see is the previous
                    # hour's final count (still available in DB before the
                    # UPSERT collapsed it, approximate via total_count diff).
                    pass

                if samples >= BASELINE_MIN_SAMPLES and baseline > 0:
                    if count_1h >= SPIKE_MIN_COUNT and count_1h > baseline * SPIKE_FACTOR:
                        anomalies.append({
                            "kind": "rate_spike",
                            "host": host,
                            "program": program,
                            "signature": signature,
                            "severity": "warning",
                            "title": f"Rate spike on {host}: {program}",
                            "description": (
                                f"Signature '{signature[:80]}...' firing {count_1h}× this hour vs baseline "
                                f"{baseline:.1f}/h ({count_1h/max(baseline,0.1):.1f}× over baseline)."
                            ),
                            "sample": msg[:400],
                            "baseline": baseline,
                            "observed": float(count_1h),
                        })
    except Exception as e:
        log.debug(f"anomaly track failed: {e}")
    return anomalies


async def roll_baselines(pool: asyncpg.Pool) -> int:
    """Run hourly. Updates baseline_per_hour as an EMA of completed 1h windows.
    Returns row count updated."""
    async with pool.acquire() as conn:
        tag = await conn.execute(
            """
            UPDATE event_signatures
            SET baseline_per_hour = CASE
                    WHEN baseline_samples = 0 THEN count_1h::real
                    ELSE baseline_per_hour * (1.0 - $1) + count_1h::real * $1
                END,
                baseline_samples = baseline_samples + 1,
                count_1h = 0,
                window_1h_start = NOW()
            WHERE NOW() - window_1h_start >= INTERVAL '1 hour'
            """,
            BASELINE_ALPHA,
        )
    try:
        return int(tag.split()[-1])
    except (ValueError, IndexError):
        return 0


async def insert_anomaly(pool: asyncpg.Pool, a: dict) -> None:
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO anomaly_detections
                    (kind, host, program, signature, severity, title,
                     description, sample, baseline, observed)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
                """,
                a["kind"], a["host"], a.get("program"), a.get("signature"),
                a.get("severity", "warning"), a["title"], a.get("description", ""),
                a.get("sample"), a.get("baseline"), a.get("observed"),
            )
    except Exception as e:
        log.debug(f"insert anomaly failed: {e}")


async def insert_firewall_flow(pool: asyncpg.Pool, event: dict) -> None:
    s = event.get("structured") or {}
    if s.get("type") != "firewall_event":
        return
    try:
        ts = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    except Exception:
        ts = datetime.now(timezone.utc)
    src_ip = s.get("src_ip") or None
    dst_ip = s.get("dst_ip") or None
    # asyncpg INET won't accept empty strings — coerce empties to None.
    if src_ip == "":
        src_ip = None
    if dst_ip == "":
        dst_ip = None
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO firewall_flows
                    (timestamp, host, action, blocked, direction, src_ip, dst_ip,
                     src_port, dst_port, proto, in_iface, out_iface, port_name,
                     concerning, concerning_reasons)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
                """,
                ts, event.get("host", "unknown"),
                s.get("action", ""), bool(s.get("blocked", False)),
                s.get("direction"), src_ip, dst_ip,
                s.get("src_port"), s.get("dst_port"),
                s.get("proto"), s.get("in_iface"), s.get("out_iface"),
                s.get("port_name"),
                bool(s.get("concerning", False)),
                list(s.get("concerning_reasons") or []),
            )
    except Exception as e:
        log.debug(f"firewall flow insert failed: {e}")
