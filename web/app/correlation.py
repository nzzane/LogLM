"""
Correlation Engine — Advanced pattern-matching across events, alerts, and SNMP data.

=============================================================================
Architecture
=============================================================================

The engine operates in two modes:

  REACTIVE (query-time):
    Called from the API to correlate a specific alert or time window on demand.
    Returns a CorrelatedIncident within seconds.

  PROACTIVE (background, every CORRELATION_SCAN_INTERVAL seconds):
    Scans the recent event window for unlinked alerts and new anomaly clusters.
    Writes CorrelatedIncident rows to the DB automatically; these appear in
    the OpsCenter dashboard and Pre-Alert report feed.

=============================================================================
Failure Patterns
=============================================================================

Each pattern is a named heuristic applied to a sorted event timeline.
Patterns are scored (0-1.0 confidence) and the highest-scoring match wins.

  cascade_link_failure:
    Trigger: SNMP link_down OR interface_flap
    Look-for: connectivity loss events on topology-linked hosts within 30s
    Root cause: Physical fault on the triggering interface

  resource_exhaustion:
    Trigger: snmp_alert cpu_high OR snmp_alert memory_high
    Look-for: OOM kill, segfault, service crash within 120s on same host
    Root cause: Resource starvation; identify runaway process from logs

  security_escalation:
    Trigger: port_scan OR ssh_brute_force category
    Look-for: auth_failure, privilege_escalation, anomalous_new_process
    Root cause: Active intrusion attempt; correlate external IP across events

  service_degradation:
    Trigger: 5xx error rate spike from nginx stream
    Look-for: upstream host CPU/memory pressure, circuit-breaker logs
    Root cause: Backend capacity issue or deployment failure

  network_storm:
    Trigger: Total error count across all SNMP hosts > STORM_ERROR_THRESHOLD
    Look-for: Multiple simultaneous link_down events across different devices
    Root cause: Spanning-tree loop, BGP route leak, or upstream carrier event

  host_isolation:
    Trigger: host_silence anomaly (host stopped logging)
    Look-for: No SNMP data from that host AND firewall blocks to that host
    Root cause: Host down (OS crash, power failure, network partition)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any

import asyncpg

log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

CORRELATION_WINDOW_S    = int(os.environ.get("CORRELATION_WINDOW_S",    "300"))
CORRELATION_SCAN_INTERVAL = int(os.environ.get("CORRELATION_SCAN_INTERVAL", "120"))
STORM_ERROR_THRESHOLD   = int(os.environ.get("STORM_ERROR_THRESHOLD",   "500"))
MIN_CONFIDENCE          = float(os.environ.get("CORRELATION_MIN_CONFIDENCE", "0.35"))

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class CorrelatedIncident:
    title:             str
    pattern_matched:   str
    confidence:        float        # 0.0 — 1.0
    root_cause:        str
    affected_hosts:    list[str]
    evidence:          list[str]    # human-readable evidence strings
    first_event_at:    str
    last_event_at:     str
    event_ids:         list[int]
    alert_ids:         list[int]
    recommended_actions: list[str]
    severity:          str = "medium"   # critical | high | medium | low


# ── Pattern definitions ───────────────────────────────────────────────────────

async def _pattern_cascade_link(events: list[dict], topo: dict[str, list[str]]) -> CorrelatedIncident | None:
    """
    Cascade link failure: a link-down event on host A triggers connectivity
    losses on topology-linked neighbours within 30 seconds.
    """
    triggers = [
        e for e in events
        if (e.get("source") in ("snmp_monitor", "snmp_trap")
            or (e.get("structured") or {}).get("alert_type") in ("link_down", "link_flap"))
        and e.get("severity") in ("emerg", "alert", "crit", "err", "error", "warning")
    ]
    if not triggers:
        return None

    evidence: list[str] = []
    affected: set[str] = set()
    event_ids: list[int] = []
    alert_ids: list[int] = []

    for trigger in triggers[:5]:
        trigger_host = trigger.get("host", "")
        trigger_ts = _parse_ts(trigger.get("timestamp"))
        if not trigger_ts:
            continue
        affected.add(trigger_host)
        event_ids.append(trigger.get("id", 0))
        evidence.append(
            f"[{_fmt_ts(trigger_ts)}] {trigger_host}: {trigger.get('message','')[:120]}"
        )

        # Find downstream events within 30s on topology neighbours
        neighbours = topo.get(trigger_host, [])
        window_end = trigger_ts + timedelta(seconds=30)
        downstream = [
            e for e in events
            if e.get("host") in neighbours
            and e.get("host") != trigger_host
            and _parse_ts(e.get("timestamp"))
            and trigger_ts <= _parse_ts(e.get("timestamp")) <= window_end
            and any(kw in (e.get("message") or "").lower()
                    for kw in ("unreachable", "refused", "timeout", "down", "loss",
                               "connect", "failed", "offline"))
        ]
        for d in downstream[:4]:
            affected.add(d.get("host", ""))
            event_ids.append(d.get("id", 0))
            evidence.append(
                f"[{_fmt_ts(_parse_ts(d.get('timestamp')))}] "
                f"{d.get('host','')} ← downstream: {d.get('message','')[:100]}"
            )

    if len(affected) < 2:
        return None

    confidence = min(0.9, 0.4 + 0.1 * len(affected) + 0.15 * len(triggers))
    return CorrelatedIncident(
        title=f"Cascade link failure — {len(affected)} hosts affected",
        pattern_matched="cascade_link_failure",
        confidence=confidence,
        root_cause=(
            f"Physical or logical fault on link at "
            f"{', '.join(sorted(affected)[:3])}. "
            f"{len(triggers)} link-down event(s) triggered downstream connectivity loss."
        ),
        affected_hosts=sorted(affected),
        evidence=evidence,
        first_event_at=_fmt_ts(min(
            (_parse_ts(e.get("timestamp")) or datetime.now(timezone.utc))
            for e in events
        )),
        last_event_at=_fmt_ts(max(
            (_parse_ts(e.get("timestamp")) or datetime.now(timezone.utc))
            for e in events
        )),
        event_ids=[i for i in event_ids if i],
        alert_ids=alert_ids,
        recommended_actions=[
            "Inspect physical cabling and SFP modules on the triggering interface.",
            "Check CDP/LLDP neighbour table to identify the upstream switch port.",
            "Review spanning-tree topology for accidental loop formation.",
        ],
        severity="high",
    )


async def _pattern_resource_exhaustion(events: list[dict]) -> CorrelatedIncident | None:
    """CPU/Memory high → service crash within 120 seconds on same host."""
    cpu_events = [
        e for e in events
        if (e.get("structured") or {}).get("alert_type") in ("cpu_high", "memory_high")
        or "cpu" in (e.get("message") or "").lower() and "high" in (e.get("message") or "").lower()
    ]
    if not cpu_events:
        return None

    evidence: list[str] = []
    affected: set[str] = set()
    event_ids: list[int] = []

    for trigger in cpu_events[:5]:
        ts = _parse_ts(trigger.get("timestamp"))
        host = trigger.get("host", "")
        if not ts:
            continue
        affected.add(host)
        event_ids.append(trigger.get("id", 0))
        evidence.append(f"[{_fmt_ts(ts)}] {host}: {trigger.get('message','')[:120]}")

        window_end = ts + timedelta(seconds=120)
        crashes = [
            e for e in events
            if e.get("host") == host
            and _parse_ts(e.get("timestamp"))
            and ts < _parse_ts(e.get("timestamp")) <= window_end
            and any(kw in (e.get("message") or "").lower()
                    for kw in ("oom", "killed", "segfault", "core dump", "out of memory",
                               "worker process exited", "died", "crash", "panic"))
        ]
        for c in crashes[:3]:
            event_ids.append(c.get("id", 0))
            evidence.append(
                f"[{_fmt_ts(_parse_ts(c.get('timestamp')))}] "
                f"{host} CRASH: {c.get('message','')[:120]}"
            )

    if len(evidence) < 2:
        return None

    confidence = min(0.88, 0.45 + 0.1 * len(evidence))
    return CorrelatedIncident(
        title=f"Resource exhaustion → service crash on {', '.join(sorted(affected)[:2])}",
        pattern_matched="resource_exhaustion",
        confidence=confidence,
        root_cause=(
            "Sustained CPU or memory pressure caused process termination. "
            "OOM killer or application watchdog triggered service restart."
        ),
        affected_hosts=sorted(affected),
        evidence=evidence,
        first_event_at=evidence[0][:21] if evidence else "",
        last_event_at=evidence[-1][:21] if evidence else "",
        event_ids=[i for i in event_ids if i],
        alert_ids=[],
        recommended_actions=[
            "Identify the process consuming the resource: check journalctl + ps output.",
            "Review deployment history — resource exhaustion often follows a new rollout.",
            "Check for memory leaks with valgrind or heap profiling on the crashing service.",
            "Consider adding resource limits (Docker --memory, k8s requests/limits).",
        ],
        severity="high",
    )


async def _pattern_security_escalation(events: list[dict]) -> CorrelatedIncident | None:
    """Port-scan or brute-force → authentication failure on same external IP."""
    scan_events = [
        e for e in events
        if any(kw in (e.get("message") or "").lower()
               for kw in ("port scan", "brute", "scan", "probe", "nmap"))
        or (e.get("structured") or {}).get("type") in ("sigma_hit",)
        and "scan" in str((e.get("structured") or {}).get("tags", [])).lower()
    ]
    auth_fails = [
        e for e in events
        if any(kw in (e.get("message") or "").lower()
               for kw in ("authentication failure", "invalid user", "failed password",
                          "unauthorized", "access denied", "login failed"))
    ]
    if not scan_events or not auth_fails:
        return None

    evidence = []
    event_ids = []
    affected: set[str] = set()

    for e in scan_events[:3]:
        evidence.append(f"[{e.get('timestamp','')[:19]}] SCAN: {e.get('message','')[:120]}")
        event_ids.append(e.get("id", 0))
        affected.add(e.get("host", ""))
    for e in auth_fails[:5]:
        evidence.append(f"[{e.get('timestamp','')[:19]}] AUTH FAIL: {e.get('message','')[:120]}")
        event_ids.append(e.get("id", 0))
        affected.add(e.get("host", ""))

    confidence = min(0.85, 0.5 + 0.06 * len(auth_fails))
    return CorrelatedIncident(
        title=f"Security escalation: scan → auth-failures on {len(affected)} host(s)",
        pattern_matched="security_escalation",
        confidence=confidence,
        root_cause=(
            f"Network reconnaissance followed by targeted authentication attacks "
            f"against {', '.join(sorted(affected)[:3])}. Possible coordinated intrusion attempt."
        ),
        affected_hosts=sorted(affected),
        evidence=evidence,
        first_event_at=evidence[0][:21] if evidence else "",
        last_event_at=evidence[-1][:21] if evidence else "",
        event_ids=[i for i in event_ids if i],
        alert_ids=[],
        recommended_actions=[
            "Block the source IP at the firewall perimeter immediately.",
            "Enable fail2ban or equivalent on all SSH-exposed services.",
            "Audit successful logins from external IPs in the past 24h.",
            "Check /var/log/auth.log for any successful sessions from the attacker IP.",
        ],
        severity="critical",
    )


async def _pattern_network_storm(events: list[dict], snmp_metrics: list[dict]) -> CorrelatedIncident | None:
    """Multiple simultaneous link failures across different devices — storm or carrier event."""
    link_downs = [
        e for e in events
        if (e.get("structured") or {}).get("alert_type") == "link_down"
    ]
    unique_hosts = {e.get("host") for e in link_downs}
    if len(unique_hosts) < 3:
        return None

    high_errors = [
        m for m in snmp_metrics
        if (m.get("total_errors") or 0) > STORM_ERROR_THRESHOLD
    ]

    evidence = [
        f"[{e.get('timestamp','')[:19]}] {e.get('host','')} link_down: {e.get('message','')[:80]}"
        for e in link_downs[:8]
    ]
    evidence += [
        f"SNMP: {m.get('host','')} errors={m.get('total_errors')}"
        for m in high_errors[:3]
    ]

    confidence = min(0.92, 0.5 + 0.07 * len(unique_hosts))
    return CorrelatedIncident(
        title=f"Network storm — {len(link_downs)} simultaneous link failures across {len(unique_hosts)} devices",
        pattern_matched="network_storm",
        confidence=confidence,
        root_cause=(
            f"Simultaneous link failures across {len(unique_hosts)} devices suggest a "
            f"spanning-tree loop, BGP route leak, upstream carrier outage, or widespread "
            f"power event. Total SNMP error rate is elevated across the network."
        ),
        affected_hosts=sorted(unique_hosts),
        evidence=evidence,
        first_event_at=events[0].get("timestamp", "")[:19] if events else "",
        last_event_at=events[-1].get("timestamp", "")[:19] if events else "",
        event_ids=[e.get("id", 0) for e in link_downs[:20] if e.get("id")],
        alert_ids=[],
        recommended_actions=[
            "Check upstream ISP status / carrier NOC immediately.",
            "Inspect STP root bridge election — unexpected root bridge change can cause storm.",
            "Enable BPDU guard and root guard on access-layer ports.",
            "Review BGP peer state on all edge routers.",
        ],
        severity="critical",
    )


# ── Main correlation entrypoint ───────────────────────────────────────────────

async def correlate(
    pool: asyncpg.Pool,
    window_seconds: int = CORRELATION_WINDOW_S,
    host_filter: str | None = None,
) -> list[CorrelatedIncident]:
    """
    Analyse the most recent `window_seconds` of events and SNMP metrics.
    Returns zero or more CorrelatedIncident objects, sorted by confidence descending.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)

    async with pool.acquire() as conn:
        # Recent notable events
        filters = ["timestamp > $1",
                   "severity IN ('emerg','alert','crit','err','error','warning')"]
        params: list[Any] = [cutoff]
        if host_filter:
            filters.append("host = $2"); params.append(host_filter)

        event_rows = await conn.fetch(
            f"""SELECT id, timestamp, host, source, severity, program,
                       message, structured
                FROM events
                WHERE {' AND '.join(filters)}
                ORDER BY timestamp
                LIMIT 500""",
            *params,
        )

        # Topology neighbours
        topo_rows = await conn.fetch(
            "SELECT src_host, dst_host FROM topology_learned WHERE confidence >= 0.5"
        )

        # Recent SNMP metrics
        snmp_rows = await conn.fetch(
            """SELECT host, avg_cpu, total_errors, interfaces_down,
                      timestamp
               FROM snmp_metrics
               WHERE timestamp > $1
               ORDER BY timestamp""",
            cutoff,
        )

    events = [dict(r) for r in event_rows]
    topo: dict[str, list[str]] = {}
    for r in topo_rows:
        topo.setdefault(r["src_host"], []).append(r["dst_host"])
        topo.setdefault(r["dst_host"], []).append(r["src_host"])
    snmp = [dict(r) for r in snmp_rows]

    if not events:
        return []

    # Run all patterns concurrently
    results = await asyncio.gather(
        _pattern_cascade_link(events, topo),
        _pattern_resource_exhaustion(events),
        _pattern_security_escalation(events),
        _pattern_network_storm(events, snmp),
        return_exceptions=True,
    )

    incidents = [
        r for r in results
        if isinstance(r, CorrelatedIncident)
        and r.confidence >= MIN_CONFIDENCE
    ]
    incidents.sort(key=lambda x: x.confidence, reverse=True)
    return incidents


async def persist_incident(pool: asyncpg.Pool, incident: CorrelatedIncident) -> int:
    """Write an incident to the correlated_incidents table. Returns the row id."""
    async with pool.acquire() as conn:
        row_id = await conn.fetchval(
            """INSERT INTO correlated_incidents
                   (title, pattern_matched, confidence, root_cause,
                    affected_hosts, evidence, event_ids, alert_ids,
                    recommended_actions, severity,
                    first_event_at, last_event_at)
               VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,
                       $9::jsonb,$10,$11,$12)
               RETURNING id""",
            incident.title,
            incident.pattern_matched,
            incident.confidence,
            incident.root_cause,
            incident.affected_hosts,
            json.dumps(incident.evidence),
            json.dumps(incident.event_ids),
            json.dumps(incident.alert_ids),
            json.dumps(incident.recommended_actions),
            incident.severity,
            incident.first_event_at or None,
            incident.last_event_at or None,
        )
    return row_id


async def correlation_scan_loop(pool: asyncpg.Pool, redis_client) -> None:
    """
    Background task: runs every CORRELATION_SCAN_INTERVAL seconds.
    Detects new incidents and persists them; skips patterns whose output
    was already stored in the last 10 minutes (same pattern_matched key).
    """
    log.info(f"Correlation scan loop started, interval={CORRELATION_SCAN_INTERVAL}s")
    while True:
        await asyncio.sleep(CORRELATION_SCAN_INTERVAL)
        try:
            incidents = await correlate(pool)
            for inc in incidents:
                # Dedup: skip if same pattern fired in the last 10 minutes
                async with pool.acquire() as conn:
                    already = await conn.fetchval(
                        """SELECT id FROM correlated_incidents
                           WHERE pattern_matched = $1
                             AND detected_at > NOW() - INTERVAL '10 minutes'
                           LIMIT 1""",
                        inc.pattern_matched,
                    )
                if already:
                    continue
                row_id = await persist_incident(pool, inc)
                log.info(f"Correlation: new incident {row_id} "
                         f"[{inc.pattern_matched}] conf={inc.confidence:.2f} "
                         f"sev={inc.severity}")
                try:
                    await redis_client.publish("loglm:correlation", json.dumps({
                        "id":       row_id,
                        "title":    inc.title,
                        "pattern":  inc.pattern_matched,
                        "severity": inc.severity,
                        "confidence": inc.confidence,
                    }))
                except Exception:
                    pass
        except Exception as e:
            log.error(f"Correlation scan error: {e}", exc_info=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_ts(s: Any) -> datetime | None:
    if isinstance(s, datetime):
        return s if s.tzinfo else s.replace(tzinfo=timezone.utc)
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


def _fmt_ts(dt: datetime | None) -> str:
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S")
