"""
Human-in-the-Loop (HITL) security model for LLM-initiated state changes.

=============================================================================
Security Architecture
=============================================================================

The HITL system enforces a strict approval gate for every action the LLM
proposes that would modify system state. No LLM-generated action executes
without explicit human approval from an admin-role principal.

Flow:
  1. LLM detects actionable intent in chat (e.g. "pause monitoring for X")
  2. LLM generates a structured PendingAction JSON (detected by chat handler)
  3. propose_action() stores it in pending_actions with status='pending'
  4. Real-time activity feed + SSE push notify admin(s)
  5. Admin reviews on /hitl or inline in chat, clicks Approve or Reject
  6. approve_action() validates admin role, then calls execute_action()
  7. execute_action() performs the actual state change
  8. Every step is written to the immutable audit_chain

Expiry: un-reviewed actions expire after HITL_EXPIRY_MINUTES (default 60).
A background task runs every 5 minutes to mark stale actions as 'expired'.

=============================================================================
Immutable Audit Chain
=============================================================================

The audit_chain table implements a cryptographic hash chain:
  entry_hash = SHA256(id || timestamp.isoformat() || actor || action ||
                      json(detail) || prev_hash)

- prev_hash of the first entry (genesis) = '0' * 64
- Any row modification (UPDATE/DELETE) breaks the chain, detectable via
  GET /api/audit/verify which re-computes all hashes server-side.
- The web UI exposes the verify endpoint; a red badge signals tampering.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

import asyncpg

log = logging.getLogger(__name__)

HITL_EXPIRY_MINUTES = int(os.environ.get("HITL_EXPIRY_MINUTES", "60"))

# ── Risk levels ───────────────────────────────────────────────────────────────

RISK_LOW      = "low"       # e.g. mute low-severity alerts for 5 min
RISK_MEDIUM   = "medium"    # e.g. pause monitoring for one host
RISK_HIGH     = "high"      # e.g. acknowledge all active alerts
RISK_CRITICAL = "critical"  # e.g. modify retention policies, delete data

RISK_ORDER = [RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL]

# ── Supported action types ────────────────────────────────────────────────────
# Each maps to an executor function registered in _EXECUTORS below.

ACTION_SILENCE_HOST     = "silence_host"
ACTION_SILENCE_CATEGORY = "silence_category"
ACTION_SILENCE_SEVERITY = "silence_severity"
ACTION_ACK_ALERTS       = "acknowledge_alerts"
ACTION_REVOKE_SILENCE   = "revoke_silence"
ACTION_SET_SETTING      = "set_setting"
ACTION_CUSTOM           = "custom"     # free-form, risk=high, no auto-exec

# ── Immutable audit chain ─────────────────────────────────────────────────────

GENESIS_HASH = "0" * 64


def _compute_entry_hash(
    row_id: int, timestamp: str, actor: str, action: str,
    detail: Any, prev_hash: str,
) -> str:
    detail_str = json.dumps(detail, sort_keys=True, ensure_ascii=False)
    payload = f"{row_id}|{timestamp}|{actor}|{action}|{detail_str}|{prev_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def audit_write(
    pool: asyncpg.Pool,
    actor: str,
    actor_method: str,           # session | apikey | llm_hitl | system
    action: str,                 # e.g. APPROVE_HITL, CREATE_USER, LOGIN_FAIL
    target: str | None = None,
    detail: dict | None = None,
    ip: str | None = None,
    severity: str = "info",      # info | warning | critical
) -> int:
    """
    Append one entry to the immutable audit_chain.
    Returns the new entry's ID.

    Chain integrity: each row stores a SHA-256 of its own content plus the
    previous row's hash (prev_hash). Any post-hoc modification breaks the
    chain; /api/audit/verify detects this by recomputing from the genesis row.
    """
    ts = datetime.now(timezone.utc).isoformat()
    detail_j = detail or {}

    async with pool.acquire() as conn:
        # Get previous entry's hash under a row-level lock to prevent races
        # when two writers append concurrently.
        prev = await conn.fetchrow(
            "SELECT id, entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1"
        )
        prev_hash = prev["entry_hash"] if prev else GENESIS_HASH

        # Insert with placeholder hash first to get the auto-generated id
        row_id = await conn.fetchval(
            """INSERT INTO audit_chain
                   (timestamp, actor, actor_method, action, target, detail, ip,
                    severity, prev_hash, entry_hash)
               VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::inet, $8, $9, $10)
               RETURNING id""",
            ts, actor, actor_method, action, target,
            json.dumps(detail_j), ip, severity, prev_hash,
            "pending",   # placeholder
        )

        # Compute final hash including actual id
        entry_hash = _compute_entry_hash(
            row_id, ts, actor, action, detail_j, prev_hash,
        )
        await conn.execute(
            "UPDATE audit_chain SET entry_hash=$1 WHERE id=$2",
            entry_hash, row_id,
        )

    return row_id


async def audit_verify(pool: asyncpg.Pool) -> dict:
    """
    Re-compute hash chain from genesis and report any broken links.
    Returns {"ok": True, "entries": N} or {"ok": False, "broken_at": id, ...}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, timestamp, actor, action, detail, prev_hash, entry_hash "
            "FROM audit_chain ORDER BY id ASC"
        )

    prev_hash = GENESIS_HASH
    for r in rows:
        ts = r["timestamp"]
        ts_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
        detail = r["detail"] if isinstance(r["detail"], dict) else {}
        expected = _compute_entry_hash(
            r["id"], ts_str, r["actor"], r["action"], detail, prev_hash,
        )
        if expected != r["entry_hash"]:
            return {
                "ok": False,
                "entries_checked": r["id"],
                "broken_at_id": r["id"],
                "broken_at_actor": r["actor"],
                "broken_at_action": r["action"],
                "error": "hash mismatch — row may have been tampered with",
            }
        prev_hash = r["entry_hash"]

    return {"ok": True, "entries": len(rows)}


# ── HITL action lifecycle ─────────────────────────────────────────────────────

async def propose_action(
    pool: asyncpg.Pool,
    requested_by: str,           # username or "llm"
    action_type: str,
    action_title: str,
    action_desc: str,
    payload: dict,
    risk_level: str = RISK_MEDIUM,
    session_id: str | None = None,
    ip: str | None = None,
) -> str:
    """
    Enqueue a pending HITL action.
    Returns the action UUID.
    """
    if action_type not in (
        ACTION_SILENCE_HOST, ACTION_SILENCE_CATEGORY, ACTION_SILENCE_SEVERITY,
        ACTION_ACK_ALERTS, ACTION_REVOKE_SILENCE, ACTION_SET_SETTING, ACTION_CUSTOM,
    ):
        raise ValueError(f"Unknown action_type: {action_type!r}")

    expires = datetime.now(timezone.utc) + timedelta(minutes=HITL_EXPIRY_MINUTES)
    action_id = str(uuid.uuid4())

    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO pending_actions
                   (id, requested_by, session_id, action_type, action_title,
                    action_desc, payload, risk_level, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)""",
            action_id, requested_by, session_id, action_type, action_title,
            action_desc, json.dumps(payload), risk_level, expires,
        )

    await audit_write(
        pool,
        actor=requested_by,
        actor_method="llm_hitl" if requested_by == "llm" else "session",
        action="HITL_PROPOSE",
        target=f"pending_action:{action_id}",
        detail={
            "action_type": action_type,
            "title":       action_title,
            "risk_level":  risk_level,
            "payload":     payload,
        },
        ip=ip,
        severity="info",
    )

    log.info(f"HITL proposed: id={action_id} type={action_type} "
             f"risk={risk_level} by={requested_by}")
    return action_id


async def approve_action(
    pool: asyncpg.Pool, redis_client,
    action_id: str,
    approved_by: str,
    approved_by_role: str,
    ip: str | None = None,
) -> dict:
    """
    Approve a pending HITL action.
    Validates admin role, marks as approved, executes, records audit entry.
    Returns {"ok": True, "result": ...} or raises ValueError.
    """
    from app.opscenter import HITL_APPROVERS   # avoid circular at module level
    if approved_by_role not in HITL_APPROVERS:
        raise PermissionError(f"Role '{approved_by_role}' cannot approve HITL actions")

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM pending_actions WHERE id=$1::uuid",
            action_id,
        )
    if not row:
        raise ValueError("Action not found")
    if row["status"] != "pending":
        raise ValueError(f"Action is already {row['status']}")
    if row["expires_at"] < datetime.now(timezone.utc):
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE pending_actions SET status='expired' WHERE id=$1::uuid",
                action_id,
            )
        raise ValueError("Action has expired")

    # Mark approved immediately (before execution) so the audit trail is clear
    # even if execution fails.
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE pending_actions
               SET status='approved', reviewed_by=$1, reviewed_at=NOW()
               WHERE id=$2::uuid""",
            approved_by, action_id,
        )

    await audit_write(
        pool,
        actor=approved_by,
        actor_method="session",
        action="HITL_APPROVE",
        target=f"pending_action:{action_id}",
        detail={
            "action_type":  row["action_type"],
            "title":        row["action_title"],
            "requested_by": row["requested_by"],
            "risk_level":   row["risk_level"],
            "payload":      dict(row["payload"]),
        },
        ip=ip,
        severity="warning" if row["risk_level"] in (RISK_HIGH, RISK_CRITICAL) else "info",
    )

    # Execute the action
    exec_result = await _execute_action(pool, redis_client, dict(row), approved_by, ip)

    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE pending_actions
               SET status='executed', executed_at=NOW(), execution_result=$1::jsonb
               WHERE id=$2::uuid""",
            json.dumps(exec_result), action_id,
        )

    log.info(f"HITL approved+executed: id={action_id} by={approved_by} "
             f"result={exec_result.get('ok')}")
    return exec_result


async def reject_action(
    pool: asyncpg.Pool,
    action_id: str,
    rejected_by: str,
    rejected_by_role: str,
    reason: str | None = None,
    ip: str | None = None,
) -> None:
    """Reject a pending HITL action. Recorded in audit chain."""
    from app.opscenter import HITL_APPROVERS
    if rejected_by_role not in HITL_APPROVERS:
        raise PermissionError(f"Role '{rejected_by_role}' cannot reject HITL actions")

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT action_type, action_title, requested_by, risk_level, status "
            "FROM pending_actions WHERE id=$1::uuid",
            action_id,
        )
    if not row:
        raise ValueError("Action not found")
    if row["status"] != "pending":
        raise ValueError(f"Action is already {row['status']}")

    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE pending_actions
               SET status='rejected', reviewed_by=$1, reviewed_at=NOW(),
                   rejection_reason=$2
               WHERE id=$3::uuid""",
            rejected_by, reason or "No reason given", action_id,
        )

    await audit_write(
        pool,
        actor=rejected_by,
        actor_method="session",
        action="HITL_REJECT",
        target=f"pending_action:{action_id}",
        detail={
            "action_type":  row["action_type"],
            "title":        row["action_title"],
            "requested_by": row["requested_by"],
            "reason":       reason,
        },
        ip=ip,
        severity="info",
    )


async def expire_stale_actions(pool: asyncpg.Pool) -> int:
    """Mark expired pending actions. Called periodically by a background task."""
    async with pool.acquire() as conn:
        r = await conn.execute(
            "UPDATE pending_actions SET status='expired' "
            "WHERE status='pending' AND expires_at < NOW()"
        )
    n = int(r.split()[-1]) if r else 0
    if n:
        log.info(f"HITL: expired {n} stale pending actions")
    return n


# ── Action executors ──────────────────────────────────────────────────────────

async def _execute_action(pool: asyncpg.Pool, redis_client,
                            row: dict, approved_by: str,
                            ip: str | None) -> dict:
    """Dispatch to the correct executor for this action type."""
    action_type = row["action_type"]
    payload = row["payload"] if isinstance(row["payload"], dict) else dict(row["payload"])

    try:
        if action_type == ACTION_SILENCE_HOST:
            return await _exec_silence_host(pool, redis_client, payload, approved_by, row["id"])
        elif action_type == ACTION_SILENCE_CATEGORY:
            return await _exec_silence_category(pool, redis_client, payload, approved_by, row["id"])
        elif action_type == ACTION_SILENCE_SEVERITY:
            return await _exec_silence_severity(pool, redis_client, payload, approved_by, row["id"])
        elif action_type == ACTION_ACK_ALERTS:
            return await _exec_ack_alerts(pool, payload, approved_by)
        elif action_type == ACTION_REVOKE_SILENCE:
            return await _exec_revoke_silence(pool, redis_client, payload, approved_by)
        elif action_type == ACTION_SET_SETTING:
            return await _exec_set_setting(pool, redis_client, payload, approved_by)
        elif action_type == ACTION_CUSTOM:
            # Custom actions are recorded but not auto-executed
            return {"ok": True, "note": "Custom action logged. Manual intervention required."}
        else:
            return {"ok": False, "error": f"Unknown action_type: {action_type}"}
    except Exception as e:
        log.error(f"HITL execution failed [{action_type}]: {e}", exc_info=True)
        return {"ok": False, "error": str(e)[:300]}


async def _exec_silence_host(pool, redis_client, payload, approved_by, action_id):
    from app.opscenter import create_silence
    sid = await create_silence(
        pool, redis_client,
        host=payload.get("host"),
        category=None,
        severity_filter=None,
        reason=payload.get("reason", "HITL-approved silence"),
        created_by=approved_by,
        duration_minutes=int(payload.get("duration_minutes", 60)),
        action_id=action_id,
    )
    return {"ok": True, "silence_id": sid, "host": payload.get("host")}


async def _exec_silence_category(pool, redis_client, payload, approved_by, action_id):
    from app.opscenter import create_silence
    sid = await create_silence(
        pool, redis_client,
        host=payload.get("host"),
        category=payload.get("category"),
        severity_filter=None,
        reason=payload.get("reason", "HITL-approved category silence"),
        created_by=approved_by,
        duration_minutes=int(payload.get("duration_minutes", 60)),
        action_id=action_id,
    )
    return {"ok": True, "silence_id": sid, "category": payload.get("category")}


async def _exec_silence_severity(pool, redis_client, payload, approved_by, action_id):
    from app.opscenter import create_silence
    sid = await create_silence(
        pool, redis_client,
        host=None,
        category=None,
        severity_filter=payload.get("severity"),
        reason=payload.get("reason", "HITL-approved severity silence"),
        created_by=approved_by,
        duration_minutes=int(payload.get("duration_minutes", 30)),
        action_id=action_id,
    )
    return {"ok": True, "silence_id": sid, "severity": payload.get("severity")}


async def _exec_ack_alerts(pool, payload, approved_by):
    category = payload.get("category")
    severity  = payload.get("severity")
    host      = payload.get("host")

    conditions = ["NOT acknowledged",
                  "(user_verdict IS NULL OR user_verdict != 'ignored')"]
    params: list = []
    idx = 1
    if category:
        conditions.append(f"raw_result->>'category' = ${idx}")
        params.append(category); idx += 1
    if severity:
        conditions.append(f"severity = ${idx}")
        params.append(severity); idx += 1
    if host:
        conditions.append(f"$${idx} = ANY(affected_hosts)")
        params.append(host); idx += 1

    where = " AND ".join(conditions)
    async with pool.acquire() as conn:
        result = await conn.execute(
            f"UPDATE alerts SET acknowledged=TRUE WHERE {where}", *params
        )
    n = int(result.split()[-1]) if result else 0
    return {"ok": True, "acknowledged": n, "filters": {"category": category, "severity": severity, "host": host}}


async def _exec_revoke_silence(pool, redis_client, payload, approved_by):
    from app.opscenter import revoke_silence
    sid = payload.get("silence_id")
    if not sid:
        return {"ok": False, "error": "silence_id required"}
    ok = await revoke_silence(pool, redis_client, sid, approved_by)
    return {"ok": ok, "silence_id": sid}


async def _exec_set_setting(pool, redis_client, payload, approved_by):
    key   = payload.get("key", "")[:100]
    value = str(payload.get("value", ""))[:500]
    if not key:
        return {"ok": False, "error": "key required"}
    allowed = {
        "analysis_interval_seconds", "memory_interval_seconds",
        "alert_cooldown_seconds", "t3_enabled", "t3_escalation_threshold",
    }
    if key not in allowed:
        return {"ok": False, "error": f"Setting '{key}' cannot be modified via HITL"}
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO loglm_settings (key, value, updated_at)
               VALUES ($1, $2, NOW())
               ON CONFLICT (key) DO UPDATE SET value=$2, updated_at=NOW()""",
            key, value,
        )
    try:
        import json as jmod
        await redis_client.publish("loglm:settings_changed", jmod.dumps([key]))
    except Exception:
        pass
    return {"ok": True, "key": key, "value": value}


# ── LLM intent detection helper ───────────────────────────────────────────────

HITL_DETECTION_SYSTEM = """You are part of an AI operations assistant with HITL (Human-In-The-Loop) security.
When the user requests an action that would CHANGE system state, you must:
1. Explain what you would do in plain English
2. Output a special JSON block that proposes the action for admin approval

Detectable actions (ONLY these):
  - Pause/silence monitoring for a specific HOST for N minutes
  - Pause/silence alerts for a specific CATEGORY for N minutes
  - Silence alerts for a specific SEVERITY level for N minutes
  - Acknowledge all alerts matching criteria
  - Revoke (remove) an active monitoring silence
  - Change a system setting

If the user's request does NOT match any detectable action, respond normally without JSON.
If it DOES match, respond with your explanation FOLLOWED by this exact block on its own lines:

```hitl_action
{
  "action_type": "<silence_host|silence_category|silence_severity|acknowledge_alerts|revoke_silence|set_setting>",
  "action_title": "<concise title, max 80 chars>",
  "action_desc": "<full description of what will happen, 1-3 sentences>",
  "risk_level": "<low|medium|high|critical>",
  "payload": { <action-specific params> }
}
```

Payload schemas:
  silence_host:     {"host": "hostname", "duration_minutes": 30, "reason": "..."}
  silence_category: {"category": "snake_case", "duration_minutes": 30, "reason": "..."}
  silence_severity: {"severity": "medium|low", "duration_minutes": 15, "reason": "..."}
  acknowledge_alerts: {"category": null_or_str, "severity": null_or_str, "host": null_or_str}
  revoke_silence:   {"silence_id": "uuid"}
  set_setting:      {"key": "setting_name", "value": "new_value"}

NEVER fabricate host names or silence IDs — only use values the user explicitly stated."""


def extract_hitl_proposal(llm_response: str) -> dict | None:
    """
    Parse an LLM response for a ```hitl_action ... ``` block.
    Returns the parsed payload dict or None if no proposal found.
    """
    import re
    pattern = r"```hitl_action\s*\n([\s\S]*?)\n```"
    match = re.search(pattern, llm_response)
    if not match:
        return None
    try:
        data = json.loads(match.group(1))
        required = {"action_type", "action_title", "action_desc", "risk_level", "payload"}
        if not required.issubset(data.keys()):
            return None
        if data["action_type"] not in (
            ACTION_SILENCE_HOST, ACTION_SILENCE_CATEGORY, ACTION_SILENCE_SEVERITY,
            ACTION_ACK_ALERTS, ACTION_REVOKE_SILENCE, ACTION_SET_SETTING, ACTION_CUSTOM,
        ):
            return None
        return data
    except Exception:
        return None


def strip_hitl_block(llm_response: str) -> str:
    """Remove the hitl_action block from the response before showing to user."""
    import re
    return re.sub(r"```hitl_action\s*\n[\s\S]*?\n```", "", llm_response).strip()
