"""
Fast LLM categorizer — runs the small model against incoming events to decide
keep/store/drop and tag importance/category. Designed to be cheap: concurrency
capped, short prompts, tiny num_predict, persistent connection pool.

Bypassed entirely when PROCESSOR_USE_FAST_LLM=0 — falls back to static rules.
"""

import asyncio
import json
import logging
import os
import re
from collections import OrderedDict

import httpx

log = logging.getLogger(__name__)

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL_FAST = os.environ.get("OLLAMA_MODEL_FAST", "llama3.2:1b")
OLLAMA_KEEP_ALIVE = os.environ.get("OLLAMA_KEEP_ALIVE", "30m")
USE_FAST_LLM = os.environ.get("PROCESSOR_USE_FAST_LLM", "0") in ("1", "true", "yes")
FAST_TIMEOUT = float(os.environ.get("PROCESSOR_FAST_TIMEOUT", "4.0"))
FAST_CONCURRENT = int(os.environ.get("PROCESSOR_FAST_CONCURRENT", "4"))

_sem = asyncio.Semaphore(FAST_CONCURRENT)
_client: httpx.AsyncClient | None = None

# Few-shot user-feedback examples are refreshed by the processor's feedback loop.
# Kept tiny because the small model's context budget is limited.
MAX_FEEDBACK_EXAMPLES = 8
_feedback_examples: list[str] = []

# Signature cache lets every event "go through" the small LLM logically while
# only paying for one inference per unique log shape. Keeps cost bounded under
# bursty syslog loads (1000s of identical lines per second is common).
SIG_CACHE_MAX = int(os.environ.get("PROCESSOR_FAST_SIG_CACHE", "5000"))
_sig_cache: "OrderedDict[str, dict]" = OrderedDict()
_SIG_NORMALIZE = re.compile(
    r"\d{4}-\d{2}-\d{2}T?\d{0,2}:?\d{0,2}:?\d{0,2}\S*"  # timestamps
    r"|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"             # IPv4 +port
    r"|0x[0-9a-fA-F]+"                                    # hex
    r"|\b[0-9a-f]{12,}\b"                                 # ids/hashes
    r"|\b\d+\b"                                            # any number
)


def _signature(event: dict) -> str:
    msg = event.get("message", "") or ""
    sig = _SIG_NORMALIZE.sub("#", msg)[:160].strip()
    return f"{event.get('host','')}|{event.get('program','') or ''}|{event.get('severity','info')}|{sig}"


def _cache_get(sig: str) -> dict | None:
    val = _sig_cache.get(sig)
    if val is not None:
        _sig_cache.move_to_end(sig)
    return val


def _cache_put(sig: str, val: dict) -> None:
    _sig_cache[sig] = val
    _sig_cache.move_to_end(sig)
    while len(_sig_cache) > SIG_CACHE_MAX:
        _sig_cache.popitem(last=False)

CATEGORIZE_SYSTEM_BASE = (
    "You are a log triage classifier. Output ONLY one JSON object with two keys:\n"
    '  "verdict": "keep" | "store" | "drop"\n'
    '  "category": "security" | "network" | "service" | "config" | "noise" | "other"\n'
    "Rules:\n"
    "- Auth failures, firewall blocks, port scans, intrusions => keep + security\n"
    "- Service crashes, OOM, container died, segfaults => keep + service\n"
    "- Interface down, link errors, packet loss => keep + network\n"
    "- Routine cron/dhcp/health-check/info noise => drop + noise\n"
    "- Otherwise: store + other\n"
    "No prose. JSON only."
)


def set_feedback_examples(rows: list[dict]) -> None:
    """Called by processor every 30s with the latest event_feedback rows.
    Converts a small subset into few-shot examples used as in-context training.
    Most-recent rows should appear first in `rows`."""
    global _feedback_examples
    important = [r for r in rows if r.get("verdict") == "important"]
    ignore    = [r for r in rows if r.get("verdict") == "ignore"]
    half = MAX_FEEDBACK_EXAMPLES // 2
    picks = important[:half] + ignore[:half]
    out: list[str] = []
    for r in picks:
        host = (r.get("host") or "?")[:30]
        program = (r.get("program") or "?")[:20]
        pat = (r.get("pattern") or "")[:120]
        verdict = "keep" if r.get("verdict") == "important" else "drop"
        out.append(f'  {host} {program}: "{pat}" -> {verdict}')
    _feedback_examples = out


def _build_system_prompt() -> str:
    if not _feedback_examples:
        return CATEGORIZE_SYSTEM_BASE
    return (
        CATEGORIZE_SYSTEM_BASE
        + "\nUser-flagged examples (treat similar lines the same way):\n"
        + "\n".join(_feedback_examples)
    )


def enabled() -> bool:
    return USE_FAST_LLM


async def init_client():
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            limits=httpx.Limits(
                max_connections=FAST_CONCURRENT,
                max_keepalive_connections=FAST_CONCURRENT,
                keepalive_expiry=600.0,
            ),
            timeout=httpx.Timeout(FAST_TIMEOUT, connect=2.0),
        )
        log.info(f"Fast categorizer ready: model={OLLAMA_MODEL_FAST}, "
                 f"concurrency={FAST_CONCURRENT}, timeout={FAST_TIMEOUT}s")


async def close_client():
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


async def categorize(event: dict) -> dict | None:
    """
    Returns {"verdict": ..., "category": ...} or None on failure.
    Caller should fall back to static rules on None.

    Uses a signature cache so repeated event shapes (same host+program+normalized
    message) reuse the LLM verdict without re-querying. This means every event is
    "classified" by the fast LLM logically, while inference cost stays bounded.
    """
    if not USE_FAST_LLM or _client is None:
        return None

    sig = _signature(event)
    cached = _cache_get(sig)
    if cached is not None:
        return cached

    msg = (event.get("message", "") or "")[:240]
    host = event.get("host", "")
    sev = event.get("severity", "info")
    program = event.get("program", "") or ""
    prompt = f"[{sev}] {host} {program}: {msg}"

    payload = {
        "model": OLLAMA_MODEL_FAST,
        "prompt": prompt,
        "system": _build_system_prompt(),
        "stream": False,
        "format": "json",
        "keep_alive": OLLAMA_KEEP_ALIVE,
        "options": {"temperature": 0.0, "num_predict": 32},
    }

    async with _sem:
        try:
            # Hard outer deadline so a stalled Ollama can't block the whole
            # processor pipeline. FAST_TIMEOUT covers both connect + read.
            r = await asyncio.wait_for(
                _client.post(f"{OLLAMA_URL}/api/generate", json=payload),
                timeout=FAST_TIMEOUT + 1.0,
            )
            r.raise_for_status()
            text = r.json().get("response", "").strip()
        except asyncio.TimeoutError:
            log.debug("fast categorize timeout; falling back to static rules")
            return None
        except Exception as e:
            log.debug(f"fast categorize fail: {e}")
            return None

    try:
        result = json.loads(text)
    except json.JSONDecodeError:
        log.debug(f"fast categorize bad json: {text[:120]}")
        return None

    verdict = result.get("verdict")
    if verdict not in ("keep", "store", "drop"):
        return None
    out = {
        "verdict": verdict,
        "category": result.get("category", "other"),
    }
    _cache_put(sig, out)
    return out


def cache_stats() -> dict:
    return {"size": len(_sig_cache), "max": SIG_CACHE_MAX}


def clear_sig_cache() -> int:
    """Wipe the signature cache. Called when user feedback changes so the
    NEXT occurrence of a previously-cached log line is re-classified against
    the new feedback rules instead of returning the stale verdict."""
    n = len(_sig_cache)
    _sig_cache.clear()
    if n:
        log.info(f"fast categorizer: cleared {n} signature cache entries")
    return n
