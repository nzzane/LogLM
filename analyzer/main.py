"""
Analyzer service.

Two concurrent loops:
  1. Alert analysis — drains loglm:analysis queue, asks LLM if anomalous
  2. Memory summariser — every MEMORY_INTERVAL, builds a compressed summary of
     recent events + SNMP metrics and stores it in memory_summaries table.
     These summaries are used by the chat system as long-term memory.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone, timedelta

import asyncpg
import httpx
import redis.asyncio as aioredis

logging.basicConfig(level=logging.INFO, format="%(asctime)s [analyzer] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

REDIS_URL = os.environ["REDIS_URL"]
POSTGRES_DSN = os.environ["POSTGRES_DSN"]
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
# Deep model used for analysis + memory summaries. Falls back to legacy OLLAMA_MODEL.
OLLAMA_MODEL = os.environ.get(
    "OLLAMA_MODEL_DEEP",
    os.environ.get("OLLAMA_MODEL", "llama3.1:8b-instruct-q4_K_M"),
)
OLLAMA_MAX_CONCURRENT = int(os.environ.get("OLLAMA_MAX_CONCURRENT", "2"))
OLLAMA_KEEP_ALIVE = os.environ.get("OLLAMA_KEEP_ALIVE", "30m")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
ANALYSIS_INTERVAL = int(os.environ.get("ANALYSIS_INTERVAL_SECONDS", "60"))
ALERT_COOLDOWN = int(os.environ.get("ALERT_COOLDOWN_SECONDS", "300"))
MEMORY_INTERVAL = int(os.environ.get("MEMORY_INTERVAL_SECONDS", "300"))  # 5 min
MAX_BATCH = 50
MAX_MSG_LEN = 200

_ollama_sem = asyncio.Semaphore(OLLAMA_MAX_CONCURRENT)

# ── Prompts ────────────────────────────────────────────────────────────────────

ANALYSIS_SYSTEM = """You are a security and infrastructure analyst reviewing log events from a home/small-office network.
Devices include: Unifi router/firewall, Unifi access points, nginx reverse proxy, Linux servers, Raspberry Pis, Unraid NAS, and Docker containers.
You also receive SNMP polling data (interface stats, wifi clients, CPU load, errors) from routers and APs, plus pre-classified SNMP alerts (link_down, link_flap, cpu_high, errors_high) emitted by the SNMP monitor when hard thresholds are breached.

Your job: analyse the provided log/metric/alert batch and decide whether anything warrants a NEW operator-visible alert.

PRIORITY ORDER — follow strictly:
1. USER-FLAGGED IMPORTANT examples below (if present) override every other rule. If a similar event is in the batch, alert.
2. USER-FLAGGED IGNORE examples below (if present) suppress alerts even when other rules would fire.
3. Pre-classified snmp_alert events (structured.type == "snmp_alert") are already known to be concerning — restate them and correlate with related events when possible.
4. The hard rules below.

Respond ONLY with valid JSON in this exact schema:
{
  "alert": true | false,
  "severity": "critical" | "high" | "medium" | "low",
  "title": "<short one-line summary>",
  "description": "<2-4 sentences explaining what is happening and why it is concerning>",
  "affected_hosts": ["host1", "host2"],
  "recommended_action": "<brief action>",
  "false_positive_risk": "high" | "medium" | "low"
}

If nothing notable is found, respond with: {"alert": false}

Do NOT include any text outside the JSON object.
Hard rules:
- Multiple SSH failures from the same IP = credential stuffing attempt
- >5 firewall blocks from same IP in short window = port scan
- 5xx errors from nginx = service degradation
- Authentication failures + privilege changes = possible compromise
- Container crashes = service outage
- Interface going down or flapping = network fault, alert HIGH
- Sustained CPU >85% or memory pressure = capacity / DDoS / runaway process
- Sudden drop in wifi clients = potential AP failure
- SNMP errors_high alert + linkDown trap on the same host = correlated hardware fault, alert HIGH
- Multiple snmp_alert events on different hosts within seconds = upstream outage, alert CRITICAL
"""

MEMORY_SYSTEM = """You are a system monitoring assistant. Given a batch of recent events and metrics,
produce a concise summary paragraph (3-6 sentences) describing:
1. Overall system health (normal / degraded / critical)
2. Notable events (security, failures, changes)
3. SNMP metric trends (traffic, client counts, errors, CPU)
4. Anything that changed compared to the previous summary (if provided)

Be specific: mention hostnames, IPs, counts, and timeframes. This summary will be stored as
memory and retrieved later when a user asks "what happened?" or "anything look different?".
Respond with ONLY the summary paragraph — no JSON, no headers."""

# ── Helpers ────────────────────────────────────────────────────────────────────

def build_alert_prompt(events: list[dict], aliases: dict[str, str]) -> str:
    lines = []
    for e in events:
        host = aliases.get(e.get("host", ""), e.get("host", "?"))
        ts = e.get("timestamp", "")[:19]
        sev = e.get("severity", "info").upper()
        src = e.get("source", "syslog")
        msg = e.get("message", "")[:MAX_MSG_LEN]
        line = f"[{ts}] {sev} {host} ({src}): {msg}"
        # Surface SNMP alert metadata so the LLM doesn't have to re-derive it.
        struct = e.get("structured") or {}
        st = struct.get("type") if isinstance(struct, dict) else None
        if st == "snmp_alert":
            line += (
                f"  [snmp_alert kind={struct.get('alert_type')}"
                f" target={struct.get('target')}"
                f" value={struct.get('value')}]"
            )
        elif st == "snmp_trap":
            line += (
                f"  [snmp_trap name={struct.get('trap_name')}"
                f" desc={struct.get('trap_desc','')[:80]}]"
            )
        lines.append(line)
    return f"Analyse these {len(events)} events:\n\n" + "\n".join(lines)


async def get_aliases(pool: asyncpg.Pool) -> dict[str, str]:
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT raw_name, alias FROM service_aliases")
        return {r["raw_name"]: r["alias"] for r in rows}


async def get_feedback_examples(pool: asyncpg.Pool, limit: int = 20) -> list[dict]:
    """Most-recent user-flagged events. Used as in-context training for the LLM."""
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT pattern, host, program, verdict, created_at "
                "FROM event_feedback ORDER BY created_at DESC LIMIT $1",
                limit,
            )
        return [dict(r) for r in rows]
    except Exception as e:
        log.debug(f"feedback fetch failed: {e}")
        return []


def build_feedback_block(rows: list[dict]) -> str:
    if not rows:
        return ""
    important = [r for r in rows if r.get("verdict") == "important"][:10]
    ignore    = [r for r in rows if r.get("verdict") == "ignore"][:10]
    if not important and not ignore:
        return ""
    parts = ["\nUSER-FLAGGED TRAINING EXAMPLES (treat similar lines accordingly):"]
    if important:
        parts.append("Marked IMPORTANT (alert on similar):")
        for r in important:
            host = (r.get("host") or "?")[:30]
            prog = (r.get("program") or "?")[:20]
            pat = (r.get("pattern") or "")[:160]
            parts.append(f'  - {host} {prog}: "{pat}"')
    if ignore:
        parts.append("Marked IGNORE (do NOT alert on similar, even if rules match):")
        for r in ignore:
            host = (r.get("host") or "?")[:30]
            prog = (r.get("program") or "?")[:20]
            pat = (r.get("pattern") or "")[:160]
            parts.append(f'  - {host} {prog}: "{pat}"')
    return "\n".join(parts)


async def call_ollama(http_client: httpx.AsyncClient, prompt: str,
                      system: str, max_tokens: int = 512) -> str | None:
    """Generic Ollama call. Retries with exponential backoff on 503/transient
    transport errors so a temporarily overloaded Ollama instance does not
    cascade into a flood of failed analyses."""
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "system": system,
        "stream": False,
        "keep_alive": OLLAMA_KEEP_ALIVE,
        "options": {
            "temperature": 0.1,
            "num_predict": max_tokens,
        },
    }
    async with _ollama_sem:
        delay = 2.0
        for attempt in range(4):
            try:
                resp = await http_client.post(
                    f"{OLLAMA_URL}/api/generate",
                    json=payload,
                    timeout=120,
                )
                # Retry transient overload codes from Ollama / reverse proxy.
                if resp.status_code in (429, 502, 503, 504):
                    if attempt < 3:
                        log.warning(
                            f"Ollama {resp.status_code} (attempt {attempt+1}), "
                            f"backing off {delay:.1f}s")
                        await asyncio.sleep(delay)
                        delay *= 2
                        continue
                resp.raise_for_status()
                return resp.json().get("response", "").strip()
            except (httpx.ReadTimeout, httpx.ConnectTimeout,
                    httpx.RemoteProtocolError, httpx.ConnectError) as e:
                if attempt < 3:
                    log.warning(f"Ollama transport error {type(e).__name__}, "
                                f"retry in {delay:.1f}s")
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                log.error(f"Ollama call failed after retries: {e}")
                return None
            except Exception as e:
                log.error(f"Ollama call failed: {e}")
                return None
        log.error("Ollama call exhausted retries")
        return None


def extract_json(text: str) -> dict | None:
    start = text.find("{")
    end = text.rfind("}") + 1
    if start == -1 or end == 0:
        return None
    try:
        return json.loads(text[start:end])
    except json.JSONDecodeError:
        return None


def _cooldown_key(result: dict) -> str:
    hosts = ",".join(sorted(result.get("affected_hosts", [])))
    sev = result.get("severity", "medium")
    return f"{hosts}:{sev}:{result.get('title','')[:40]}"


async def _dedup_or_insert(pool: asyncpg.Pool, result: dict, event_count: int) -> tuple[bool, int]:
    """
    Returns (was_new, seen_count).
    If a recent alert (within ALERT_COOLDOWN) has the same cooldown_key,
    increments its seen_count and returns (False, new_count).
    Else inserts a new row and returns (True, 1).
    """
    key = _cooldown_key(result)
    async with pool.acquire() as conn:
        existing = await conn.fetchrow(
            """
            SELECT id, seen_count FROM alerts
            WHERE cooldown_key = $1
              AND last_seen > NOW() - ($2 * INTERVAL '1 second')
            ORDER BY last_seen DESC LIMIT 1
            """,
            key, ALERT_COOLDOWN,
        )
        if existing:
            new_count = (existing["seen_count"] or 1) + 1
            await conn.execute(
                "UPDATE alerts SET seen_count=$1, last_seen=NOW(), event_count=event_count+$2 WHERE id=$3",
                new_count, event_count, existing["id"],
            )
            return False, new_count

        await conn.execute(
            """INSERT INTO alerts
                   (timestamp, severity, title, description, affected_hosts,
                    recommended_action, false_positive_risk, event_count,
                    raw_result, cooldown_key, seen_count, last_seen)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,1,$1)""",
            datetime.now(timezone.utc),
            result.get("severity", "medium"),
            result.get("title", "Unknown"),
            result.get("description", ""),
            result.get("affected_hosts", []),
            result.get("recommended_action", ""),
            result.get("false_positive_risk", "medium"),
            event_count,
            json.dumps(result),
            key,
        )
        return True, 1


SEVERITY_COLORS = {"critical": 0xFF0000, "high": 0xFF6600, "medium": 0xFFAA00, "low": 0x00AAFF}
SEVERITY_EMOJI = {"critical": "\U0001f6a8", "high": "\u26a0\ufe0f", "medium": "\U0001f536", "low": "\u2139\ufe0f"}


async def post_discord(http_client: httpx.AsyncClient, result: dict, event_count: int):
    if not DISCORD_WEBHOOK_URL:
        log.warning("No DISCORD_WEBHOOK_URL set")
        return
    sev = result.get("severity", "medium")
    embed = {
        "title": f"{SEVERITY_EMOJI.get(sev, '')} {result.get('title', 'Anomaly Detected')}",
        "description": result.get("description", ""),
        "color": SEVERITY_COLORS.get(sev, 0xFFAA00),
        "fields": [
            {"name": "Severity", "value": sev.upper(), "inline": True},
            {"name": "Affected Hosts", "value": ", ".join(result.get("affected_hosts", ["unknown"])), "inline": True},
            {"name": "FP Risk", "value": result.get("false_positive_risk", "?"), "inline": True},
            {"name": "Action", "value": result.get("recommended_action", "Investigate"), "inline": False},
            {"name": "Events", "value": str(event_count), "inline": True},
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": "LogLM"},
    }
    try:
        resp = await http_client.post(DISCORD_WEBHOOK_URL, json={"embeds": [embed]}, timeout=10)
        if resp.status_code in (200, 204):
            log.info(f"Discord alert: {result.get('title')}")
        else:
            log.warning(f"Discord failed: {resp.status_code}")
    except Exception as e:
        log.error(f"Discord error: {e}")


# ── Schema migration (idempotent) ─────────────────────────────────────────────

async def ensure_alert_schema(pool: asyncpg.Pool):
    async with pool.acquire() as conn:
        await conn.execute("""
            ALTER TABLE alerts ADD COLUMN IF NOT EXISTS cooldown_key TEXT;
            ALTER TABLE alerts ADD COLUMN IF NOT EXISTS seen_count   INT DEFAULT 1;
            ALTER TABLE alerts ADD COLUMN IF NOT EXISTS last_seen    TIMESTAMPTZ;
            UPDATE alerts SET last_seen = timestamp WHERE last_seen IS NULL;
            CREATE INDEX IF NOT EXISTS idx_alerts_cooldown_key ON alerts (cooldown_key, last_seen DESC);
        """)


# ── Alert analysis loop ───────────────────────────────────────────────────────

async def analyze_loop(redis_client, pool: asyncpg.Pool, http_client: httpx.AsyncClient):
    log.info(f"Alert analyzer started. Model={OLLAMA_MODEL}, interval={ANALYSIS_INTERVAL}s")

    while True:
        await asyncio.sleep(ANALYSIS_INTERVAL)

        events = []
        for _ in range(MAX_BATCH):
            item = await redis_client.lpop("loglm:analysis")
            if item is None:
                break
            try:
                events.append(json.loads(item))
            except json.JSONDecodeError:
                continue

        if not events:
            continue

        log.info(f"Analyzing batch of {len(events)} events")
        aliases = await get_aliases(pool)
        prompt = build_alert_prompt(events, aliases)
        feedback = await get_feedback_examples(pool)
        system = ANALYSIS_SYSTEM + build_feedback_block(feedback)
        text = await call_ollama(http_client, prompt, system)
        if not text:
            continue

        result = extract_json(text)
        if result is None:
            log.warning(f"LLM non-JSON: {text[:200]}")
            continue
        if not result.get("alert"):
            continue

        log.info(f"ALERT [{result.get('severity','?')}]: {result.get('title','?')}")
        was_new, seen = await _dedup_or_insert(pool, result, len(events))
        if not was_new:
            log.info(f"Dedup: incremented existing alert (seen {seen}×)")
            continue
        await post_discord(http_client, result, len(events))


# ── Memory summariser loop ────────────────────────────────────────────────────

async def memory_loop(redis_client, pool: asyncpg.Pool, http_client: httpx.AsyncClient):
    log.info(f"Memory summariser started, interval={MEMORY_INTERVAL}s")

    while True:
        await asyncio.sleep(MEMORY_INTERVAL)
        try:
            await build_memory_summary(redis_client, pool, http_client)
        except Exception as e:
            log.error(f"Memory summary failed: {e}", exc_info=True)


async def build_memory_summary(redis_client, pool: asyncpg.Pool, http_client: httpx.AsyncClient):
    now = datetime.now(timezone.utc)
    period_start = now - timedelta(seconds=MEMORY_INTERVAL)

    async with pool.acquire() as conn:
        # Get recent event stats
        stats = await conn.fetchrow("""
            SELECT
                COUNT(*)                                                     AS total,
                COUNT(*) FILTER (WHERE severity IN ('emerg','alert','crit','err','error'))  AS errors,
                COUNT(*) FILTER (WHERE severity = 'warning')                 AS warnings,
                COUNT(DISTINCT host)                                         AS unique_hosts,
                array_agg(DISTINCT source)                                   AS sources
            FROM events
            WHERE timestamp > $1
        """, period_start)

        # Get notable events (errors/warnings, max 20)
        notable = await conn.fetch("""
            SELECT timestamp, host, source, severity, message
            FROM events
            WHERE timestamp > $1 AND severity IN ('emerg','alert','crit','err','error','warning')
            ORDER BY timestamp DESC
            LIMIT 20
        """, period_start)

        # Get recent alerts
        recent_alerts = await conn.fetch("""
            SELECT timestamp, severity, title, affected_hosts
            FROM alerts
            WHERE timestamp > $1
            ORDER BY timestamp DESC
            LIMIT 5
        """, period_start)

        # Get previous summary for comparison
        prev_summary = await conn.fetchval("""
            SELECT summary FROM memory_summaries ORDER BY timestamp DESC LIMIT 1
        """)

    # Get latest SNMP metrics from Redis
    snmp_data = await redis_client.hgetall("loglm:snmp_latest")
    snmp_summaries = []
    for host, data_str in snmp_data.items():
        try:
            d = json.loads(data_str)
            parts = [f"{d.get('sys_name', host)}"]
            if d.get("avg_cpu") is not None:
                parts.append(f"CPU={d['avg_cpu']}%")
            if d.get("wifi_clients"):
                parts.append(f"wifi_clients={d['wifi_clients']}")
            ifaces = d.get("interfaces", {})
            down = [v["name"] for v in ifaces.values() if v.get("status") == "down"]
            if down:
                parts.append(f"DOWN={','.join(down)}")
            snmp_summaries.append(" ".join(parts))
        except Exception:
            pass

    # Trend deltas from snmp_metrics history (last hour vs current).
    # Lets the summary actually say "CPU jumped from X to Y on host Z".
    snmp_trends: list[str] = []
    try:
        async with pool.acquire() as conn:
            trend_rows = await conn.fetch("""
                WITH recent AS (
                    SELECT host,
                           AVG(avg_cpu)        FILTER (WHERE timestamp > NOW() - INTERVAL '5 minutes')  AS cpu_now,
                           AVG(avg_cpu)        FILTER (WHERE timestamp BETWEEN NOW() - INTERVAL '1 hour' AND NOW() - INTERVAL '5 minutes') AS cpu_prev,
                           SUM(total_errors)   FILTER (WHERE timestamp > NOW() - INTERVAL '5 minutes')  AS err_now,
                           SUM(total_errors)   FILTER (WHERE timestamp BETWEEN NOW() - INTERVAL '1 hour' AND NOW() - INTERVAL '5 minutes') AS err_prev,
                           MAX(interfaces_down) FILTER (WHERE timestamp > NOW() - INTERVAL '5 minutes') AS down_now
                    FROM snmp_metrics
                    WHERE timestamp > NOW() - INTERVAL '1 hour'
                    GROUP BY host
                )
                SELECT * FROM recent
                WHERE cpu_now IS NOT NULL OR err_now IS NOT NULL
            """)
        for r in trend_rows:
            host = r["host"]
            cpu_now = r["cpu_now"]
            cpu_prev = r["cpu_prev"]
            err_now = r["err_now"]
            err_prev = r["err_prev"]
            bits: list[str] = []
            if cpu_now is not None and cpu_prev is not None and cpu_prev > 0:
                delta = cpu_now - cpu_prev
                if abs(delta) >= 15:
                    bits.append(f"CPU {cpu_prev:.0f}%→{cpu_now:.0f}%")
            if err_now and err_prev is not None:
                if err_now >= 5 * max(err_prev, 1):
                    bits.append(f"errors {int(err_prev)}→{int(err_now)}")
            if r["down_now"] and r["down_now"] > 0:
                bits.append(f"{r['down_now']} ifaces down")
            if bits:
                snmp_trends.append(f"{host}: " + ", ".join(bits))
    except Exception as e:
        log.debug(f"snmp trend query failed: {e}")

    # Build prompt
    lines = [f"Time period: {period_start.isoformat()} to {now.isoformat()}"]
    lines.append(f"Events: {stats['total']} total, {stats['errors']} errors, {stats['warnings']} warnings, {stats['unique_hosts']} hosts")

    if notable:
        lines.append("\nNotable events:")
        for e in notable[:10]:
            lines.append(f"  [{e['timestamp'].strftime('%H:%M:%S')}] {e['severity'].upper()} {e['host']}: {e['message'][:150]}")

    if recent_alerts:
        lines.append("\nAlerts fired:")
        for a in recent_alerts:
            lines.append(f"  [{a['severity'].upper()}] {a['title']} (hosts: {', '.join(a['affected_hosts'] or ['?'])})")

    if snmp_summaries:
        lines.append(f"\nSNMP metrics: {'; '.join(snmp_summaries)}")

    if snmp_trends:
        lines.append(f"\nSNMP trends (last hour): {'; '.join(snmp_trends)}")

    if prev_summary:
        lines.append(f"\nPrevious summary for comparison:\n{prev_summary}")

    prompt = "\n".join(lines)
    summary_text = await call_ollama(http_client, prompt, MEMORY_SYSTEM, max_tokens=300)

    if not summary_text:
        log.warning("Memory summary: no LLM response")
        return

    # Store summary
    key_events = [
        {"ts": e["timestamp"].isoformat(), "host": e["host"], "msg": e["message"][:100]}
        for e in (notable or [])[:5]
    ]
    stats_json = {
        "total_events": stats["total"],
        "errors": stats["errors"],
        "warnings": stats["warnings"],
        "unique_hosts": stats["unique_hosts"],
    }

    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO memory_summaries (timestamp, period_start, period_end, summary, key_events, stats)
               VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb)""",
            now, period_start, now, summary_text,
            json.dumps(key_events), json.dumps(stats_json),
        )

    # Also store SNMP metrics for history
    for host, data_str in snmp_data.items():
        try:
            d = json.loads(data_str)
            ifaces = d.get("interfaces", {})
            up_count = sum(1 for v in ifaces.values() if v.get("status") == "up")
            down_count = sum(1 for v in ifaces.values() if v.get("status") == "down")
            total_in = sum(v.get("in_bps") or 0 for v in ifaces.values())
            total_out = sum(v.get("out_bps") or 0 for v in ifaces.values())
            total_err = sum((v.get("in_errors") or 0) + (v.get("out_errors") or 0) for v in ifaces.values())

            async with pool.acquire() as conn:
                await conn.execute(
                    """INSERT INTO snmp_metrics (timestamp, host, sys_name, avg_cpu, wifi_clients,
                                                 interfaces_up, interfaces_down, total_in_bps,
                                                 total_out_bps, total_errors, raw_data)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)""",
                    now, host, d.get("sys_name"),
                    d.get("avg_cpu"), d.get("wifi_clients"),
                    up_count, down_count, total_in, total_out, total_err,
                    json.dumps(d),
                )
        except Exception as e:
            log.debug(f"SNMP metric store error for {host}: {e}")

    log.info(f"Memory summary stored ({len(summary_text)} chars)")


# ── Ollama readiness check ─────────────────────────────────────────────────────

async def wait_for_ollama(http_client: httpx.AsyncClient):
    for _ in range(120):
        try:
            r = await http_client.get(f"{OLLAMA_URL}/api/tags", timeout=5)
            if r.status_code == 200:
                log.info("Ollama is ready")
                return
        except Exception:
            pass
        log.info("Waiting for Ollama...")
        await asyncio.sleep(5)
    log.warning("Ollama not ready after 10 min — proceeding anyway")


# ── Main ───────────────────────────────────────────────────────────────────────

async def main():
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    pool = await asyncpg.create_pool(POSTGRES_DSN, min_size=2, max_size=5)
    limits = httpx.Limits(
        max_connections=OLLAMA_MAX_CONCURRENT,
        max_keepalive_connections=OLLAMA_MAX_CONCURRENT,
        keepalive_expiry=600.0,
    )
    http_client = httpx.AsyncClient(limits=limits, timeout=httpx.Timeout(300.0, connect=5.0))

    for _ in range(30):
        try:
            await redis_client.ping()
            break
        except Exception:
            log.info("Waiting for Redis...")
            await asyncio.sleep(2)

    await ensure_alert_schema(pool)
    await wait_for_ollama(http_client)

    async with asyncio.TaskGroup() as tg:
        tg.create_task(analyze_loop(redis_client, pool, http_client))
        tg.create_task(memory_loop(redis_client, pool, http_client))


if __name__ == "__main__":
    asyncio.run(main())
