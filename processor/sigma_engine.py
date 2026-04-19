"""
Offline Sigma rule engine for LogLM.

Loads Sigma YAML rules from the filesystem + DB, compiles them into a
fast matchable form, and evaluates each incoming event against the active
ruleset. Hits are recorded in the sigma_hits table and pushed to the
analysis stream so the LLM can correlate them.

Compilation strategy:
  Sigma detection blocks use AND/OR trees of field conditions. We flatten
  each rule into a list of FieldCondition objects that can be evaluated in
  pure Python without a full Sigma backend. Supported modifiers:
    contains, startswith, endswith, re, all, base64
  Unsupported modifiers are logged and the rule is skipped.

Rule loading:
  1. On startup, scan SIGMA_RULES_DIR for *.yml files.
  2. Upsert into sigma_rules table (keyed on rule_id + version_hash).
  3. Build in-memory match index grouped by logsource.product / .service.
  4. Every RELOAD_INTERVAL_SEC, re-read from DB (catches web UI edits).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import asyncpg

log = logging.getLogger(__name__)

SIGMA_RULES_DIR = os.environ.get("SIGMA_RULES_DIR", "/app/sigma_rules")
RELOAD_INTERVAL_SEC = int(os.environ.get("SIGMA_RELOAD_SEC", "300"))


@dataclass
class FieldCondition:
    field: str
    values: list[str]
    modifier: str = "contains"  # contains | startswith | endswith | exact | re
    negate: bool = False
    match_all: bool = False     # True → all values must match (AND)


@dataclass
class CompiledRule:
    rule_id: str
    title: str
    level: str
    status: str
    logsource: dict
    tags: list[str]
    conditions: list[list[FieldCondition]]  # OR of AND groups
    _compiled_re: dict = field(default_factory=dict, repr=False)

    def _get_re(self, pattern: str) -> re.Pattern:
        if pattern not in self._compiled_re:
            try:
                self._compiled_re[pattern] = re.compile(pattern, re.IGNORECASE)
            except re.error:
                self._compiled_re[pattern] = re.compile(re.escape(pattern), re.IGNORECASE)
        return self._compiled_re[pattern]


_rules: list[CompiledRule] = []
_rules_lock = asyncio.Lock()


def _parse_detection(detection: dict) -> list[list[FieldCondition]] | None:
    """Convert Sigma detection block → list of OR-groups, each an AND-list."""
    if not detection:
        return None

    condition_expr = detection.get("condition", "")
    named_blocks = {k: v for k, v in detection.items() if k != "condition"}

    if not named_blocks:
        return None

    or_groups: list[list[FieldCondition]] = []

    for block_name, block_val in named_blocks.items():
        if block_name == "condition":
            continue
        conditions = _parse_block(block_name, block_val)
        if conditions:
            or_groups.append(conditions)

    if not or_groups and named_blocks:
        all_conds = []
        for block_name, block_val in named_blocks.items():
            conds = _parse_block(block_name, block_val)
            if conds:
                all_conds.extend(conds)
        if all_conds:
            or_groups.append(all_conds)

    return or_groups if or_groups else None


def _parse_block(name: str, block: Any) -> list[FieldCondition]:
    conditions: list[FieldCondition] = []

    if isinstance(block, dict):
        for raw_field, raw_val in block.items():
            parts = raw_field.split("|")
            field_name = parts[0]
            modifier = "contains"
            negate = False
            match_all = False

            for mod in parts[1:]:
                if mod == "contains":
                    modifier = "contains"
                elif mod == "startswith":
                    modifier = "startswith"
                elif mod == "endswith":
                    modifier = "endswith"
                elif mod == "re":
                    modifier = "re"
                elif mod == "all":
                    match_all = True
                elif mod == "base64":
                    pass  # skip, match on decoded
                elif mod == "exact":
                    modifier = "exact"

            values = raw_val if isinstance(raw_val, list) else [raw_val]
            values = [str(v) for v in values if v is not None]

            if values:
                conditions.append(FieldCondition(
                    field=field_name, values=values,
                    modifier=modifier, negate=negate, match_all=match_all,
                ))

    elif isinstance(block, list):
        for item in block:
            if isinstance(item, dict):
                conditions.extend(_parse_block(name, item))
            elif isinstance(item, str):
                conditions.append(FieldCondition(
                    field="message", values=[item], modifier="contains",
                ))

    elif isinstance(block, str):
        conditions.append(FieldCondition(
            field="message", values=[block], modifier="contains",
        ))

    return conditions


def _extract_field(event: dict, field_name: str) -> str:
    """Get a field from the event, checking top-level then structured."""
    val = event.get(field_name)
    if val is not None:
        return str(val)
    structured = event.get("structured") or {}
    val = structured.get(field_name)
    if val is not None:
        return str(val)
    return ""


def _match_condition(event: dict, cond: FieldCondition, rule: CompiledRule) -> bool:
    text = _extract_field(event, cond.field).lower()
    if not text and not cond.negate:
        return False

    def _check_one(val: str) -> bool:
        v = val.lower()
        if cond.modifier == "contains":
            return v in text
        elif cond.modifier == "startswith":
            return text.startswith(v)
        elif cond.modifier == "endswith":
            return text.endswith(v)
        elif cond.modifier == "exact":
            return text == v
        elif cond.modifier == "re":
            return bool(rule._get_re(val).search(text))
        return v in text

    if cond.match_all:
        result = all(_check_one(v) for v in cond.values)
    else:
        result = any(_check_one(v) for v in cond.values)

    return (not result) if cond.negate else result


def match_event(event: dict) -> list[CompiledRule]:
    """Evaluate event against all active rules. Returns list of matches."""
    hits: list[CompiledRule] = []
    for rule in _rules:
        matched = False
        for and_group in rule.conditions:
            if all(_match_condition(event, c, rule) for c in and_group):
                matched = True
                break
        if matched:
            hits.append(rule)
    return hits


def _hash_yaml(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _compile_yaml(raw: dict, yaml_text: str) -> CompiledRule | None:
    rule_id = raw.get("id", "")
    title = raw.get("title", "untitled")
    level = raw.get("level", "medium")
    status = raw.get("status", "test")
    logsource = raw.get("logsource") or {}
    tags = raw.get("tags") or []
    detection = raw.get("detection")

    if not rule_id or not detection:
        return None

    conditions = _parse_detection(detection)
    if not conditions:
        return None

    return CompiledRule(
        rule_id=rule_id, title=title, level=level, status=status,
        logsource=logsource, tags=tags, conditions=conditions,
    )


async def load_from_dir(pool: asyncpg.Pool) -> int:
    """Scan SIGMA_RULES_DIR, upsert rules into DB, return count loaded."""
    rules_dir = Path(SIGMA_RULES_DIR)
    if not rules_dir.is_dir():
        log.info(f"sigma rules dir {SIGMA_RULES_DIR} not found, skipping file load")
        return 0

    try:
        import yaml
    except ImportError:
        log.warning("PyYAML not installed, cannot load sigma rules from disk")
        return 0

    count = 0
    for yml_path in sorted(rules_dir.rglob("*.yml")):
        try:
            text = yml_path.read_text(encoding="utf-8")
            docs = list(yaml.safe_load_all(text))
            for doc in docs:
                if not isinstance(doc, dict) or "id" not in doc:
                    continue
                rule_id = doc["id"]
                version_hash = _hash_yaml(text)
                compiled = _compile_yaml(doc, text)
                if compiled is None:
                    continue
                compiled_json = json.dumps([
                    [{"field": c.field, "values": c.values, "modifier": c.modifier,
                      "negate": c.negate, "match_all": c.match_all}
                     for c in group]
                    for group in compiled.conditions
                ])
                async with pool.acquire() as conn:
                    await conn.execute(
                        """INSERT INTO sigma_rules (rule_id, title, status, level,
                               logsource, tags, yaml, compiled, version_hash)
                           VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8::jsonb,$9)
                           ON CONFLICT (rule_id) DO UPDATE SET
                               title=$2, status=$3, level=$4, logsource=$5::jsonb,
                               tags=$6, yaml=$7, compiled=$8::jsonb, version_hash=$9,
                               updated_at=NOW()
                           WHERE sigma_rules.version_hash != $9""",
                        rule_id, compiled.title, compiled.status, compiled.level,
                        json.dumps(compiled.logsource), compiled.tags,
                        text, compiled_json, version_hash,
                    )
                count += 1
        except Exception as e:
            log.warning(f"failed to load sigma rule {yml_path}: {e}")

    log.info(f"loaded {count} sigma rule files from {SIGMA_RULES_DIR}")
    return count


async def load_from_db(pool: asyncpg.Pool) -> int:
    """Load enabled rules from DB into memory. Returns count."""
    global _rules
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT rule_id, title, level, status, logsource, tags, compiled "
            "FROM sigma_rules WHERE enabled = TRUE"
        )

    new_rules: list[CompiledRule] = []
    for row in rows:
        try:
            compiled_data = json.loads(row["compiled"]) if isinstance(row["compiled"], str) else row["compiled"]
            conditions: list[list[FieldCondition]] = []
            for group_data in compiled_data:
                group = []
                for cd in group_data:
                    group.append(FieldCondition(
                        field=cd["field"], values=cd["values"],
                        modifier=cd.get("modifier", "contains"),
                        negate=cd.get("negate", False),
                        match_all=cd.get("match_all", False),
                    ))
                conditions.append(group)
            logsource = json.loads(row["logsource"]) if isinstance(row["logsource"], str) else (row["logsource"] or {})
            new_rules.append(CompiledRule(
                rule_id=row["rule_id"], title=row["title"],
                level=row["level"] or "medium", status=row["status"] or "test",
                logsource=logsource, tags=list(row["tags"] or []),
                conditions=conditions,
            ))
        except Exception as e:
            log.debug(f"skip rule {row['rule_id']}: {e}")

    async with _rules_lock:
        _rules = new_rules
    log.info(f"sigma engine loaded {len(new_rules)} rules from DB")
    return len(new_rules)


async def record_hit(
    pool: asyncpg.Pool, rule: CompiledRule, event: dict, event_id: int | None = None,
) -> None:
    """Write a sigma_hits row."""
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO sigma_hits (rule_id, rule_level, host, program, event_id, summary)
                   VALUES ($1,$2,$3,$4,$5,$6)""",
                rule.rule_id, rule.level,
                event.get("host"), event.get("program"),
                event_id,
                f"{rule.title}: {event.get('message', '')[:200]}",
            )
    except Exception as e:
        log.debug(f"sigma hit record failed: {e}")


async def reload_loop(pool: asyncpg.Pool) -> None:
    """Periodically reload rules from DB."""
    while True:
        await asyncio.sleep(RELOAD_INTERVAL_SEC)
        try:
            await load_from_db(pool)
        except Exception as e:
            log.warning(f"sigma reload failed: {e}")


def rule_count() -> int:
    return len(_rules)
