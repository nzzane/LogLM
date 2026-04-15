"""
Pure-Python syslog receiver (RFC 3164 + RFC 5424).
Listens on UDP and TCP port 514, parses incoming syslog messages,
and pushes JSON events to Redis list loglm:raw.

Replaces rsyslog — no native packages needed, runs on any arch.
"""

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone

import redis.asyncio as aioredis

logging.basicConfig(level=logging.INFO, format="%(asctime)s [syslog-rx] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 514
BATCH_SIZE = int(os.environ.get("SYSLOG_BATCH_SIZE", "200"))
BATCH_FLUSH_MS = int(os.environ.get("SYSLOG_BATCH_FLUSH_MS", "50"))
QUEUE_MAX = int(os.environ.get("SYSLOG_QUEUE_MAX", "20000"))

# Burst-dedup: drop identical (host, program, normalized-message) lines seen
# more than once per window. The signature cache downstream already does this
# at LLM cost level, but doing it here avoids shipping 1000s of duplicates to
# redis in the first place. Counter is emitted periodically so no silent loss.
DEDUP_WINDOW_SEC = float(os.environ.get("SYSLOG_DEDUP_WINDOW_SEC", "5"))
DEDUP_MAX_KEYS = int(os.environ.get("SYSLOG_DEDUP_MAX_KEYS", "10000"))

_queue: asyncio.Queue[str] | None = None

# Syslog severity names (RFC 5424 §6.2.1)
SEVERITY_NAMES = {
    0: "emerg", 1: "alert", 2: "crit", 3: "err",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

# RFC 3164: <PRI>TIMESTAMP HOSTNAME APP-NAME[PID]: MSG
_RFC3164_RE = re.compile(
    r"<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?:(?P<program>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*)?"
    r"(?P<message>.*)"
)

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
_RFC5424_RE = re.compile(
    r"<(?P<pri>\d{1,3})>"
    r"(?P<version>\d)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>\S+)\s+"
    r"(?P<pid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<sd>(?:\[.*?\])+|-)\s*"
    r"(?P<message>.*)"
)


def parse_priority(pri: int) -> tuple[str, str]:
    facility = FACILITY_NAMES.get(pri >> 3, f"facility{pri >> 3}")
    severity = SEVERITY_NAMES.get(pri & 0x07, "info")
    return facility, severity


def parse_syslog(data: str, addr: tuple[str, int] | None = None) -> dict:
    """Parse a raw syslog line into a canonical JSON-serializable dict."""
    data = data.strip()
    now_iso = datetime.now(timezone.utc).isoformat()
    source_ip = addr[0] if addr else "unknown"

    # Try RFC 5424 first
    m = _RFC5424_RE.match(data)
    if m:
        pri = int(m.group("pri"))
        facility, severity = parse_priority(pri)
        hostname = m.group("hostname") if m.group("hostname") != "-" else source_ip
        return {
            "timestamp": m.group("timestamp") if m.group("timestamp") != "-" else now_iso,
            "host": hostname,
            "hostname": hostname,
            "severity": severity,
            "facility": facility,
            "tag": m.group("program") or "",
            "program": m.group("program") if m.group("program") != "-" else "",
            "pid": m.group("pid") if m.group("pid") != "-" else "",
            "message": m.group("message") or "",
        }

    # Try RFC 3164
    m = _RFC3164_RE.match(data)
    if m:
        pri = int(m.group("pri"))
        facility, severity = parse_priority(pri)
        hostname = m.group("hostname") or source_ip
        return {
            "timestamp": now_iso,
            "host": hostname,
            "hostname": hostname,
            "severity": severity,
            "facility": facility,
            "tag": m.group("program") or "",
            "program": m.group("program") or "",
            "pid": m.group("pid") or "",
            "message": m.group("message") or "",
        }

    # Fallback: unparseable
    return {
        "timestamp": now_iso,
        "host": source_ip,
        "hostname": source_ip,
        "severity": "info",
        "facility": "user",
        "tag": "",
        "program": "",
        "pid": "",
        "message": data,
    }


_dropped = 0
_deduped = 0

# Pre-enqueue burst dedup state: signature → (last_seen_monotonic, count)
_dedup_seen: dict[str, tuple[float, int]] = {}
_dedup_last_prune = 0.0

_DEDUP_NORMALIZE = re.compile(
    r"\d{4}-\d{2}-\d{2}T?\d{0,2}:?\d{0,2}:?\d{0,2}\S*"
    r"|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"
    r"|0x[0-9a-fA-F]+"
    r"|\b[0-9a-f]{12,}\b"
    r"|\b\d+\b"
)


def _dedup_signature(event: dict) -> str:
    msg = event.get("message", "") or ""
    sig = _DEDUP_NORMALIZE.sub("#", msg)[:160]
    return f"{event.get('host','')}|{event.get('program','') or ''}|{sig}"


def _should_dedup(event: dict) -> bool:
    """Return True if this event is a burst duplicate and should be dropped.
    Keeps the first occurrence per window so downstream still sees it."""
    global _dedup_last_prune
    if DEDUP_WINDOW_SEC <= 0:
        return False
    # Never dedup high-severity lines — we want every error to reach the LLM
    # even if the same error repeats rapidly.
    sev = (event.get("severity") or "info").lower()
    if sev in ("emerg", "alert", "crit", "err", "error"):
        return False
    now = asyncio.get_running_loop().time()
    # Periodic prune to bound memory. Runs at most once per window.
    if now - _dedup_last_prune > DEDUP_WINDOW_SEC:
        cutoff = now - DEDUP_WINDOW_SEC
        for k in list(_dedup_seen.keys()):
            if _dedup_seen[k][0] < cutoff:
                del _dedup_seen[k]
        _dedup_last_prune = now
        # Hard cap in case of signature explosion.
        if len(_dedup_seen) > DEDUP_MAX_KEYS:
            _dedup_seen.clear()
    sig = _dedup_signature(event)
    entry = _dedup_seen.get(sig)
    if entry is None or now - entry[0] > DEDUP_WINDOW_SEC:
        _dedup_seen[sig] = (now, 1)
        return False
    _dedup_seen[sig] = (entry[0], entry[1] + 1)
    return True


def enqueue(event: dict):
    global _dropped, _deduped
    if _should_dedup(event):
        _deduped += 1
        if _deduped % 1000 == 0:
            log.info(f"burst dedup: {_deduped} duplicate events suppressed total")
        return
    try:
        _queue.put_nowait(json.dumps(event))
    except asyncio.QueueFull:
        _dropped += 1
        if _dropped % 500 == 0:
            log.warning(f"Queue full, dropped {_dropped} events total")


class UDPSyslogProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return
        enqueue(parse_syslog(text, addr))


async def handle_tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    log.info(f"TCP connection from {addr}")
    try:
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=300)
            if not line:
                break
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            enqueue(parse_syslog(text, addr))
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        log.debug(f"TCP client error: {e}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def batch_writer(redis_client: aioredis.Redis):
    """Drain queue into Redis in batches to avoid one-rpush-per-message."""
    total = 0
    flush_interval = BATCH_FLUSH_MS / 1000.0
    while True:
        batch: list[str] = []
        try:
            first = await asyncio.wait_for(_queue.get(), timeout=1.0)
            batch.append(first)
        except asyncio.TimeoutError:
            continue
        deadline = asyncio.get_running_loop().time() + flush_interval
        while len(batch) < BATCH_SIZE:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            try:
                item = await asyncio.wait_for(_queue.get(), timeout=remaining)
                batch.append(item)
            except asyncio.TimeoutError:
                break
        try:
            await redis_client.rpush("loglm:raw", *batch)
            total += len(batch)
            if total // 1000 != (total - len(batch)) // 1000:
                log.info(f"syslog batcher: {total} events pushed (qsize={_queue.qsize()})")
        except Exception as e:
            log.warning(f"Redis batch push failed: {e}, requeueing {len(batch)}")
            for item in batch:
                try:
                    _queue.put_nowait(item)
                except asyncio.QueueFull:
                    break
            await asyncio.sleep(1)


async def main():
    global _queue
    _queue = asyncio.Queue(maxsize=QUEUE_MAX)

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)

    for _ in range(30):
        try:
            await redis_client.ping()
            break
        except Exception:
            log.info("Waiting for Redis...")
            await asyncio.sleep(2)

    log.info(f"Syslog receiver starting on {LISTEN_HOST}:{LISTEN_PORT} (UDP+TCP, "
             f"batch={BATCH_SIZE}, flush={BATCH_FLUSH_MS}ms, qmax={QUEUE_MAX})")

    loop = asyncio.get_running_loop()

    transport, _protocol = await loop.create_datagram_endpoint(
        UDPSyslogProtocol,
        local_addr=(LISTEN_HOST, LISTEN_PORT),
    )

    server = await asyncio.start_server(
        handle_tcp_client, LISTEN_HOST, LISTEN_PORT,
    )

    log.info("Syslog receiver ready (UDP + TCP)")

    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(batch_writer(redis_client))
            tg.create_task(server.serve_forever())
    finally:
        transport.close()
        server.close()


if __name__ == "__main__":
    asyncio.run(main())
