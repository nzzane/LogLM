"""
Anomaly learning layer.

Every event that survives the filter is compared against a learned baseline
per (host, program, normalized-message-signature):

  - First time we've ever seen this signature → emit a `new_signature` anomaly
    (unknown behaviour on that host).
  - Signature's current hour rate is >= SPIKE_FACTOR × its rolling
    baseline → emit a `rate_spike` anomaly.
  - Hour-of-day seasonality: baselines are tracked per hour bucket (0-23)
    so "busy at 9am" doesn't false-positive.
  - Silence detection: if a host that normally logs goes quiet for
    SILENCE_THRESHOLD_SEC, emit a `host_silence` anomaly.
  - Burst detection: if many distinct signatures fire from one host in a
    short window, emit a `burst` anomaly (possible incident).

The baseline is an adaptive EMA — alpha shrinks as variance decreases
(stable patterns change slowly, volatile ones track quickly).
"""

import logging
import math
import os
import re
import time
from datetime import datetime, timezone

import asyncpg

log = logging.getLogger(__name__)

BASELINE_ALPHA = float(os.environ.get("ANOMALY_BASELINE_ALPHA", "0.2"))
BASELINE_ALPHA_MIN = float(os.environ.get("ANOMALY_ALPHA_MIN", "0.05"))
BASELINE_ALPHA_MAX = float(os.environ.get("ANOMALY_ALPHA_MAX", "0.4"))
BASELINE_MIN_SAMPLES = int(os.environ.get("ANOMALY_MIN_SAMPLES", "4"))
SPIKE_FACTOR = float(os.environ.get("ANOMALY_SPIKE_FACTOR", "5.0"))
SPIKE_MIN_COUNT = int(os.environ.get("ANOMALY_SPIKE_MIN_COUNT", "10"))
WARMUP_SEC = int(os.environ.get("ANOMALY_WARMUP_SEC", "300"))
SILENCE_THRESHOLD_SEC = int(os.environ.get("ANOMALY_SILENCE_SEC", "1800"))
SILENCE_MIN_EVENTS = int(os.environ.get("ANOMALY_SILENCE_MIN_EVENTS", "50"))
BURST_WINDOW_SEC = int(os.environ.get("ANOMALY_BURST_WINDOW_SEC", "60"))
BURST_MIN_SIGS = int(os.environ.get("ANOMALY_BURST_MIN_SIGS", "15"))

_SIG_NORMALIZE = re.compile(
    r"\d{4}-\d{2}-\d{2}T?\d{0,2}:?\d{0,2}:?\d{0,2}\S*"
    r"|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"
    r"|0x[0-9a-fA-F]+"
    r"|\b[0-9a-f]{12,}\b"
    r"|\b\d+\b"
)


def normalize(message: str) -> str:
    return _SIG_NORMALIZE.sub("#", message or "")[:200].strip()


# ── Process-local burst tracker ──────────────────────────────────────────────
# Tracks distinct signature count per host within BURST_WINDOW_SEC.
_burst_tracker: dict[str, list[float]] = {}
_burst_fired: dict[str, float] = {}


def _track_burst(host: str) -> bool:
    """Record a signature event for host. Return True if burst threshold crossed."""
    now = time.monotonic()
    window = _burst_tracker.setdefault(host, [])
    window.append(now)
    cutoff = now - BURST_WINDOW_SEC
    _burst_tracker[host] = [t for t in window if t > cutoff]
    if len(_burst_tracker[host]) >= BURST_MIN_SIGS:
        last = _burst_fired.get(host, 0.0)
        if now - last > BURST_WINDOW_SEC * 3:
            _burst_fired[host] = now
            return True
    return False


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
                baseline_variance REAL NOT NULL DEFAULT 0,
                hourly_baselines REAL[] NOT NULL DEFAULT '{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}',
                hourly_samples   INT[]  NOT NULL DEFAULT '{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}',
                UNIQUE (signature, host, program)
            );
            CREATE INDEX IF NOT EXISTS idx_sig_last_seen  ON event_signatures (last_seen DESC);
            CREATE INDEX IF NOT EXISTS idx_sig_first_seen ON event_signatures (first_seen DESC);
            CREATE INDEX IF NOT EXISTS idx_sig_host       ON event_signatures (host);

            -- Host-level activity tracking for silence detection.
            CREATE TABLE IF NOT EXISTS host_activity (
                host            TEXT PRIMARY KEY,
                last_event      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                events_24h      BIGINT NOT NULL DEFAULT 0,
                window_start    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                avg_rate_per_h  REAL NOT NULL DEFAULT 0,
                samples         INT  NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_host_activity_last ON host_activity (last_event DESC);

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
        # Migrate existing installs — add new columns if they don't exist.
        await conn.execute("""
            ALTER TABLE event_signatures ADD COLUMN IF NOT EXISTS baseline_variance REAL NOT NULL DEFAULT 0;
            ALTER TABLE event_signatures ADD COLUMN IF NOT EXISTS hourly_baselines REAL[] NOT NULL DEFAULT '{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}';
            ALTER TABLE event_signatures ADD COLUMN IF NOT EXISTS hourly_samples   INT[]  NOT NULL DEFAULT '{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}';
        """)


async def track(conn, event: dict) -> list[dict]:
    """
    Upsert the signature for this event, update rolling counters, and return
    zero or more anomaly dicts for things that tripped: new_signature /
    rate_spike. Caller passes an already-acquired connection so the worker
    holds ONE connection for the full event chain rather than three (the old
    pool-acquire version deadlocked under load).
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
                          baseline_samples, baseline_variance,
                          hourly_baselines, hourly_samples,
                          window_1h_start, (xmax = 0) AS is_new
                """,
                signature, host, program, severity, msg[:400],
            )
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
                    "severity": "warning" if severity in ("err", "error", "crit", "emerg", "alert", "warning") else "info",
                    "title": f"New log pattern on {host}",
                    "description": (
                        f"First-ever observation of this line shape from {host}/{program}. "
                        f"Severity={severity}."
                    ),
                    "sample": msg[:400],
                    "baseline": 0.0,
                    "observed": 1.0,
                })

            # Rate-spike detection with hour-of-day seasonality.
            # Use per-hour baseline if available, fall back to global.
            hour = datetime.now(timezone.utc).hour
            hourly_bl = row.get("hourly_baselines") or [0.0] * 24
            hourly_sa = row.get("hourly_samples") or [0] * 24
            effective_baseline = baseline
            if len(hourly_bl) > hour and hourly_sa[hour] >= BASELINE_MIN_SAMPLES:
                effective_baseline = max(hourly_bl[hour], 0.1)

            if samples >= BASELINE_MIN_SAMPLES and effective_baseline > 0:
                if count_1h >= SPIKE_MIN_COUNT and count_1h > effective_baseline * SPIKE_FACTOR:
                    anomalies.append({
                        "kind": "rate_spike",
                        "host": host,
                        "program": program,
                        "signature": signature,
                        "severity": "warning",
                        "title": f"Rate spike on {host}: {program}",
                        "description": (
                            f"Signature '{signature[:80]}...' firing {count_1h}× this hour vs baseline "
                            f"{effective_baseline:.1f}/h ({count_1h / max(effective_baseline, 0.1):.1f}× over)."
                        ),
                        "sample": msg[:400],
                        "baseline": effective_baseline,
                        "observed": float(count_1h),
                    })

            # Burst detection — many distinct sigs from same host in short window.
            if _track_burst(host):
                anomalies.append({
                    "kind": "burst",
                    "host": host,
                    "program": program,
                    "signature": "",
                    "severity": "high",
                    "title": f"Log burst from {host}",
                    "description": (
                        f"{BURST_MIN_SIGS}+ distinct log patterns from {host} in "
                        f"{BURST_WINDOW_SEC}s — possible incident."
                    ),
                    "sample": msg[:400],
                    "baseline": 0.0,
                    "observed": float(BURST_MIN_SIGS),
                })

    except Exception as e:
        log.debug(f"anomaly track failed: {e}")

    # Update host activity (best-effort, outside main transaction).
    try:
        await conn.execute(
            """INSERT INTO host_activity (host, last_event, events_24h, window_start)
               VALUES ($1, NOW(), 1, NOW())
               ON CONFLICT (host) DO UPDATE SET
                   last_event = NOW(),
                   events_24h = CASE
                       WHEN NOW() - host_activity.window_start > INTERVAL '24 hours'
                       THEN 1 ELSE host_activity.events_24h + 1 END,
                   window_start = CASE
                       WHEN NOW() - host_activity.window_start > INTERVAL '24 hours'
                       THEN NOW() ELSE host_activity.window_start END""",
            host,
        )
    except Exception:
        pass

    return anomalies


async def roll_baselines(pool: asyncpg.Pool) -> int:
    """Run every 5 min. Updates baseline_per_hour as adaptive EMA + hourly
    bucket. Alpha adapts: low-variance sigs use lower alpha (more stable),
    high-variance sigs track faster."""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT id, count_1h, baseline_per_hour, baseline_samples,
                      baseline_variance, hourly_baselines, hourly_samples,
                      window_1h_start
               FROM event_signatures
               WHERE NOW() - window_1h_start >= INTERVAL '1 hour'
               LIMIT 5000"""
        )
        if not rows:
            return 0

        hour = datetime.now(timezone.utc).hour
        updated = 0
        for r in rows:
            count = float(r["count_1h"])
            old_bl = float(r["baseline_per_hour"] or 0)
            old_var = float(r["baseline_variance"] or 0)
            samples = int(r["baseline_samples"] or 0)

            if samples == 0:
                new_bl = count
                new_var = 0.0
                alpha = BASELINE_ALPHA
            else:
                diff = count - old_bl
                new_var = old_var * 0.8 + (diff * diff) * 0.2
                cv = math.sqrt(new_var) / max(old_bl, 1.0)
                alpha = min(BASELINE_ALPHA_MAX,
                            max(BASELINE_ALPHA_MIN, BASELINE_ALPHA * (1.0 + cv)))
                new_bl = old_bl * (1.0 - alpha) + count * alpha

            hbl = list(r["hourly_baselines"] or [0.0] * 24)
            hsa = list(r["hourly_samples"] or [0] * 24)
            while len(hbl) < 24:
                hbl.append(0.0)
            while len(hsa) < 24:
                hsa.append(0)
            h_alpha = 0.3 if hsa[hour] < 5 else 0.15
            hbl[hour] = hbl[hour] * (1 - h_alpha) + count * h_alpha if hsa[hour] > 0 else count
            hsa[hour] = min(hsa[hour] + 1, 1000)

            try:
                await conn.execute(
                    """UPDATE event_signatures
                       SET baseline_per_hour = $2, baseline_samples = baseline_samples + 1,
                           baseline_variance = $3,
                           hourly_baselines = $4, hourly_samples = $5,
                           count_1h = 0, window_1h_start = NOW()
                       WHERE id = $1""",
                    r["id"], new_bl, new_var, hbl, hsa,
                )
                updated += 1
            except Exception as e:
                log.debug(f"baseline update {r['id']} failed: {e}")

    return updated


async def check_silence(pool: asyncpg.Pool) -> list[dict]:
    """Find hosts that normally log but have gone silent. Returns anomalies."""
    anomalies: list[dict] = []
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT host, last_event, events_24h, avg_rate_per_h, samples
                   FROM host_activity
                   WHERE samples >= $1
                     AND avg_rate_per_h > 1.0
                     AND last_event < NOW() - ($2 * INTERVAL '1 second')
                   LIMIT 20""",
                BASELINE_MIN_SAMPLES, SILENCE_THRESHOLD_SEC,
            )
        for r in rows:
            anomalies.append({
                "kind": "host_silence",
                "host": r["host"],
                "program": "",
                "signature": "",
                "severity": "high",
                "title": f"Host {r['host']} went silent",
                "description": (
                    f"No events from {r['host']} for >{SILENCE_THRESHOLD_SEC}s. "
                    f"Normal rate: {r['avg_rate_per_h']:.1f}/h over {r['samples']} samples."
                ),
                "sample": "",
                "baseline": float(r["avg_rate_per_h"]),
                "observed": 0.0,
            })
    except Exception as e:
        log.debug(f"silence check failed: {e}")
    return anomalies


async def roll_host_activity(pool: asyncpg.Pool) -> int:
    """Update host-level hourly rate baselines. Run alongside roll_baselines."""
    try:
        async with pool.acquire() as conn:
            tag = await conn.execute(
                """UPDATE host_activity
                   SET avg_rate_per_h = CASE
                           WHEN samples = 0 THEN events_24h::real / GREATEST(EXTRACT(EPOCH FROM NOW() - window_start) / 3600, 1)
                           ELSE avg_rate_per_h * 0.8 + (events_24h::real / GREATEST(EXTRACT(EPOCH FROM NOW() - window_start) / 3600, 1)) * 0.2
                       END,
                       samples = samples + 1,
                       events_24h = 0,
                       window_start = NOW()
                   WHERE NOW() - window_start >= INTERVAL '1 hour'"""
            )
        return int(tag.split()[-1])
    except Exception:
        return 0


async def insert_anomaly(conn, a: dict) -> None:
    try:
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


async def insert_firewall_flow(conn, event: dict) -> None:
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
