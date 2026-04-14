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
import time
from datetime import datetime, timezone, timedelta

import asyncpg
import httpx
import redis.asyncio as aioredis

logging.basicConfig(level=logging.INFO, format="%(asctime)s [analyzer] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

REDIS_URL = os.environ["REDIS_URL"]
POSTGRES_DSN = os.environ["POSTGRES_DSN"]
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1:8b-instruct-q4_K_M")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
ANALYSIS_INTERVAL = int(os.environ.get("ANALYSIS_INTERVAL_SECONDS", "60"))
ALERT_COOLDOWN = int(os.environ.get("ALERT_COOLDOWN_SECONDS", "300"))
MEMORY_INTERVAL = int(os.environ.get("MEMORY_INTERVAL_SECONDS", "300"))  # 5 min
MAX_BATCH = 50
MAX_MSG_LEN = 200

_alert_cooldowns: dict[str, float] = {}

# ── Prompts ────────────────────────────────────────────────────────────────────

ANALYSIS_SYSTEM = """You are a security and infrastructure analyst reviewing log events from a home/small-office network.
Devices include: Unifi router/firewall, Unifi access points, nginx reverse proxy, Linux servers, Raspberry Pis, Unraid NAS, and Docker containers.
You also receive SNMP polling data (interface stats, wifi clients, CPU load, errors) from routers and APs.

Your job: analyse the provided log/metric batch and identify anomalies, security threats, or service issues.

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
Rules:
- Multiple SSH failures from the same IP = credential stuffing attempt
- >5 firewall blocks from same IP in short window = port scan
- 5xx errors from nginx = service degradation
- Authentication failures + privilege changes = possible compromise
- Container crashes = service outage
- Interface going down or high error rates = network issue
- Sudden drop in wifi clients = potential AP failure
- High CPU on router = possible DDoS or misconfiguration
- SNMP poll showing interface errors increasing = cable/hardware issue
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
        lines.append(f"[{ts}] {sev} {host} ({src}): {msg}")
    return f"Analyse these {len(events)} log events:\n\n" + "\n".join(lines)


async def get_aliases(pool: asyncpg.Pool) -> dict[str, str]:
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT raw_name, alias FROM service_aliases")
        return {r["raw_name"]: r["alias"] for r in rows}


async def call_ollama(http_client: httpx.AsyncClient, prompt: str,
                      system: str, max_tokens: int = 512) -> str | None:
    """Generic Ollama call, returns raw text response."""
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "system": system,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": max_tokens,
        },
    }
    try:
        resp = await http_client.post(
            f"{OLLAMA_URL}/api/generate",
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except Exception as e:
        log.error(f"Ollama call failed: {e}")
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
    return f"{hosts}:{result.get('title','')[:40]}"


def _is_cooled_down(result: dict) -> bool:
    key = _cooldown_key(result)
    last = _alert_cooldowns.get(key, 0.0)
    if time.monotonic() - last < ALERT_COOLDOWN:
        return True
    _alert_cooldowns[key] = time.monotonic()
    return False


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


async def store_alert(pool: asyncpg.Pool, result: dict, event_count: int):
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO alerts (timestamp, severity, title, description, affected_hosts,
                                   recommended_action, false_positive_risk, event_count, raw_result)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)""",
            datetime.now(timezone.utc),
            result.get("severity", "medium"),
            result.get("title", "Unknown"),
            result.get("description", ""),
            result.get("affected_hosts", []),
            result.get("recommended_action", ""),
            result.get("false_positive_risk", "medium"),
            event_count,
            json.dumps(result),
        )


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
        text = await call_ollama(http_client, prompt, ANALYSIS_SYSTEM)
        if not text:
            continue

        result = extract_json(text)
        if result is None:
            log.warning(f"LLM non-JSON: {text[:200]}")
            continue
        if not result.get("alert"):
            continue

        log.info(f"ALERT [{result.get('severity','?')}]: {result.get('title','?')}")
        if _is_cooled_down(result):
            log.info("Cooldown suppressed")
            continue

        await asyncio.gather(
            post_discord(http_client, result, len(events)),
            store_alert(pool, result, len(events)),
        )


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
    http_client = httpx.AsyncClient()

    for _ in range(30):
        try:
            await redis_client.ping()
            break
        except Exception:
            log.info("Waiting for Redis...")
            await asyncio.sleep(2)

    await wait_for_ollama(http_client)

    async with asyncio.TaskGroup() as tg:
        tg.create_task(analyze_loop(redis_client, pool, http_client))
        tg.create_task(memory_loop(redis_client, pool, http_client))


if __name__ == "__main__":
    asyncio.run(main())
