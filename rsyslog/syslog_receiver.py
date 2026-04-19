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

import streams

logging.basicConfig(level=logging.INFO, format="%(asctime)s [syslog-rx] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 514
GELF_PORT = int(os.environ.get("GELF_PORT", "12201"))
JSON_PORT = int(os.environ.get("JSON_PORT", "5140"))
GELF_ENABLED = os.environ.get("GELF_ENABLED", "1") in ("1", "true", "yes")
JSON_ENABLED = os.environ.get("JSON_ENABLED", "1") in ("1", "true", "yes")
BATCH_SIZE = int(os.environ.get("SYSLOG_BATCH_SIZE", "200"))
BATCH_FLUSH_MS = int(os.environ.get("SYSLOG_BATCH_FLUSH_MS", "50"))
QUEUE_MAX = int(os.environ.get("SYSLOG_QUEUE_MAX", "20000"))

# Burst-dedup: drop identical (host, program, normalized-message) lines seen
# more than once per window. The signature cache downstream already does this
# at LLM cost level, but doing it here avoids shipping 1000s of duplicates to
# redis in the first place. Counter is emitted periodically so no silent loss.
DEDUP_WINDOW_SEC = float(os.environ.get("SYSLOG_DEDUP_WINDOW_SEC", "5"))
DEDUP_MAX_KEYS = int(os.environ.get("SYSLOG_DEDUP_MAX_KEYS", "10000"))

# ── Priority routing ─────────────────────────────────────────────────────────
# Three Redis queues. The processor BLPOPs them in priority order so a flood
# of firewall noise can never starve a high-priority security event.
RAW_QUEUE_HI  = "loglm:raw:hi"   # auth / sshd / sudo / pam / err+/ snmp_alert
RAW_QUEUE_MID = "loglm:raw:mid"  # general server logs
RAW_QUEUE_LO  = "loglm:raw:lo"   # firewall / dhcp / routine / nginx access

# Program names are matched against event.program anchored as an exact-token
# match (program is a single identifier, not free text, so `== "sshd"` is safer
# than a regex that also matches "ssh-agent" or "sshdebug").
_HI_PROGRAMS = frozenset({
    "sshd", "sudo", "pam", "pam_unix", "polkit", "login", "passwd",
    "gdm", "kdm", "cron-pam", "systemd-logind", "kerberos", "krb5",
    "fail2ban", "crowdsec", "wazuh", "samba", "smbd", "winbindd",
})
_LO_PROGRAMS = frozenset({
    "ufw", "iptables", "nft", "nftables", "netfilter", "filterlog", "firewall",
    "dhclient", "dhcpd", "isc-dhcp", "dnsmasq", "chronyd", "ntpd",
    "systemd-timesyncd", "nginx", "httpd", "apache2", "named", "unbound",
})

# Message-content patterns. Anchored with (?:^|[^A-Z]) before BUG: so it does
# NOT match DEBUG:, WARNBUG:, etc. Everything case-sensitive where the original
# token is conventionally uppercase (BUG:, OOM, Panic) to cut false positives.
_HI_MSG_RE = re.compile(
    r"(failed (?:password|login|auth)"
    r"|invalid user"
    r"|authentication failure"
    r"|break-?in attempt"
    r"|possible (?:brute|scan|flood)"
    r"|kernel panic"
    r"|(?<![A-Za-z])oops(?![A-Za-z])"
    r"|(?<![A-Z])BUG:"
    r"|segfault"
    r"|out of memory"
    r"|oom[- ]?kill"
    r"|too many authentication failures"
    r")",
    re.IGNORECASE,
)
_LO_MSG_RE = re.compile(
    r"(\[UFW |SRC=|DST=|DPT=|filterlog\[|DHCPACK|DHCPREQUEST|DHCPDISCOVER"
    r"|named\[|query:|client @|resolved\.)",
    re.IGNORECASE,
)

# Severities that MUST be hi. 'warning' stays mid — programs spam warnings.
_HI_SEVERITIES = {"emerg", "alert", "crit"}
# 'err'/'error' are technically high, but some verbose programs (notably
# pfsense, some Docker images) emit 'err' for routine things. We still route
# them to hi but only if the program isn't on the noisy low list.
_LIKELY_HI_SEVERITIES = {"err", "error"}


def classify_priority(event: dict) -> str:
    """Cheap classification for queue routing. Doesn't need to be perfect:
    misrouting just means a log waits an extra few ms in the wrong queue.

    Priority rules (first hit wins):
      1. severity in {emerg,alert,crit}          → hi  (always)
      2. program in HI_PROGRAMS                   → hi
      3. HI_MSG_RE matches                        → hi
      4. program in LO_PROGRAMS                   → lo
      5. LO_MSG_RE matches                        → lo
      6. severity in {err,error} and not LO       → hi
      7. default                                  → mid
    """
    sev = (event.get("severity") or "info").lower()
    if sev in _HI_SEVERITIES:
        return "hi"
    # Strip brackets/suffixes so "sshd[1234]" → "sshd"
    program = (event.get("program") or "").lower()
    program_base = program.split("[", 1)[0].split(":", 1)[0].strip()
    msg = event.get("message") or ""
    if program_base in _HI_PROGRAMS:
        return "hi"
    if _HI_MSG_RE.search(msg):
        return "hi"
    if program_base in _LO_PROGRAMS:
        return "lo"
    if _LO_MSG_RE.search(msg):
        return "lo"
    if sev in _LIKELY_HI_SEVERITIES:
        return "hi"
    return "mid"

_queues: dict[str, asyncio.Queue] = {}

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
            "source_ip": source_ip,   # UDP sender — may differ from reported hostname
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
            "source_ip": source_ip,   # UDP sender
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
        "source_ip": source_ip,
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
    priority = classify_priority(event)
    q = _queues.get(priority) or _queues["mid"]
    try:
        q.put_nowait(json.dumps(event))
        _kick_writer()
    except asyncio.QueueFull:
        _dropped += 1
        if _dropped % 500 == 0:
            log.warning(f"Queue full ({priority}), dropped {_dropped} events total")


class UDPSyslogProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return
        enqueue(parse_syslog(text, addr))


async def handle_tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """TCP syslog with RFC 6587 auto-detection.
    Supports both octet-counting ('123 <message>') and newline framing."""
    addr = writer.get_extra_info("peername")
    log.debug(f"TCP connection from {addr}")
    octet_mode: bool | None = None
    try:
        while True:
            if octet_mode is None:
                peek = await asyncio.wait_for(reader.read(1), timeout=300)
                if not peek:
                    break
                if peek[0:1].isdigit():
                    octet_mode = True
                    buf = peek
                else:
                    octet_mode = False
                    buf = peek

            if octet_mode:
                len_buf = buf if buf else b""
                while True:
                    ch = await asyncio.wait_for(reader.read(1), timeout=300)
                    if not ch:
                        return
                    if ch == b" ":
                        break
                    if ch.isdigit():
                        len_buf += ch
                    else:
                        len_buf += ch
                        octet_mode = False
                        rest = await asyncio.wait_for(reader.readline(), timeout=300)
                        text = (len_buf + rest).decode("utf-8", errors="replace").strip()
                        if text:
                            enqueue(parse_syslog(text, addr))
                        break
                else:
                    try:
                        msg_len = int(len_buf)
                    except ValueError:
                        continue
                    if msg_len > 65536:
                        continue
                    data = await asyncio.wait_for(reader.readexactly(msg_len), timeout=300)
                    text = data.decode("utf-8", errors="replace").strip()
                    if text:
                        enqueue(parse_syslog(text, addr))
                buf = b""
            else:
                if buf:
                    rest = await asyncio.wait_for(reader.readline(), timeout=300)
                    line = buf + rest
                    buf = b""
                else:
                    line = await asyncio.wait_for(reader.readline(), timeout=300)
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                if text[0].isdigit() and " <" in text[:8]:
                    octet_mode = True
                    buf = text.split(" ", 1)[1].encode() if " " in text else b""
                    continue
                enqueue(parse_syslog(text, addr))
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass
    except Exception as e:
        log.debug(f"TCP client error: {e}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ── GELF (Graylog Extended Log Format) input ─────────────────────────────────
# Docker's GELF driver sends JSON over UDP 12201, optionally gzip-compressed.

import gzip as _gzip
import zlib as _zlib

_GELF_LEVEL_MAP = {0: "emerg", 1: "alert", 2: "crit", 3: "err",
                   4: "warning", 5: "notice", 6: "info", 7: "debug"}


def _parse_gelf(data: bytes, addr: tuple[str, int] | None = None) -> dict | None:
    try:
        if data[:2] == b"\x1f\x8b":
            data = _gzip.decompress(data)
        elif data[:1] == b"\x78":
            data = _zlib.decompress(data)
        obj = json.loads(data)
    except Exception:
        return None
    host = obj.get("host", addr[0] if addr else "unknown")
    level = int(obj.get("level", 6))
    msg = obj.get("short_message") or obj.get("message") or ""
    full = obj.get("full_message") or ""
    ts = obj.get("timestamp")
    if ts:
        try:
            ts_iso = datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
        except Exception:
            ts_iso = datetime.now(timezone.utc).isoformat()
    else:
        ts_iso = datetime.now(timezone.utc).isoformat()
    extra = {k: v for k, v in obj.items()
             if k.startswith("_") and k not in ("_id",)}
    facility = obj.get("facility") or extra.pop("_facility", "gelf")
    program = extra.pop("_container_name", extra.pop("_tag", extra.pop("_app", "")))
    return {
        "timestamp": ts_iso,
        "host": host,
        "hostname": host,
        "severity": _GELF_LEVEL_MAP.get(level, "info"),
        "facility": str(facility),
        "program": program,
        "tag": program,
        "pid": extra.pop("_pid", ""),
        "message": msg if not full else f"{msg}\n{full}",
        "source": "gelf",
        "structured": {"type": "gelf", **extra},
    }


class GELFProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        event = _parse_gelf(data, addr)
        if event:
            enqueue(event)


# ── JSON TCP input ───────────────────────────────────────────────────────────
# Accepts newline-delimited JSON on JSON_PORT. Each line is a JSON object
# with at minimum a "message" field.

def _parse_json_line(line: str, addr: tuple[str, int] | None = None) -> dict | None:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    now_iso = datetime.now(timezone.utc).isoformat()
    source_ip = addr[0] if addr else "unknown"
    return {
        "timestamp": obj.get("timestamp") or obj.get("@timestamp") or obj.get("time") or now_iso,
        "host": obj.get("host") or obj.get("hostname") or source_ip,
        "hostname": obj.get("host") or obj.get("hostname") or source_ip,
        "source_ip": source_ip,
        "severity": obj.get("severity") or obj.get("level") or "info",
        "facility": obj.get("facility") or "json",
        "program": obj.get("program") or obj.get("app") or obj.get("service") or "",
        "tag": obj.get("tag") or "",
        "pid": str(obj.get("pid", "")),
        "message": obj.get("message") or obj.get("msg") or json.dumps(obj),
        "source": "json",
        "structured": {k: v for k, v in obj.items()
                       if k not in ("timestamp", "@timestamp", "time", "host",
                                    "hostname", "severity", "level", "facility",
                                    "program", "app", "service", "tag", "pid",
                                    "message", "msg")},
    }


async def handle_json_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    try:
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=300)
            if not line:
                break
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            event = _parse_json_line(text, addr)
            if event:
                enqueue(event)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass
    except Exception as e:
        log.debug(f"JSON TCP error: {e}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


_REDIS_KEYS = {"hi": RAW_QUEUE_HI, "mid": RAW_QUEUE_MID, "lo": RAW_QUEUE_LO}
_STREAM_KEYS = {"hi": streams.STREAM_HI, "mid": streams.STREAM_MID, "lo": streams.STREAM_LO}
_kick: asyncio.Event | None = None


def _kick_writer():
    if _kick is not None and not _kick.is_set():
        _kick.set()


def _drain_one(priority: str) -> list[str]:
    q = _queues[priority]
    batch: list[str] = []
    while len(batch) < BATCH_SIZE:
        try:
            batch.append(q.get_nowait())
        except asyncio.QueueEmpty:
            break
    return batch


async def batch_writer(redis_client: aioredis.Redis):
    """Drain all 3 priority queues into their Redis lists. Hi drains first
    each tick so a hi event never waits behind a low batch.

    Wakeup model: enqueue() sets _kick; the writer waits on it with a small
    timeout (BATCH_FLUSH_MS) so we still flush partial batches under low load
    without busy-looping when idle."""
    global _kick
    _kick = asyncio.Event()
    total = {"hi": 0, "mid": 0, "lo": 0}
    flush_interval = BATCH_FLUSH_MS / 1000.0
    while True:
        try:
            await asyncio.wait_for(_kick.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            pass
        _kick.clear()
        # Drain hi first, then mid, then lo. Within a priority we drain up to
        # BATCH_SIZE per push, looping until the queue is empty so a burst
        # doesn't get stuck behind the flush_interval.
        for prio in ("hi", "mid", "lo"):
            while True:
                batch = _drain_one(prio)
                if not batch:
                    break
                stream_key = _STREAM_KEYS[prio]
                try:
                    await streams.xadd_batch(redis_client, stream_key, batch)
                    total[prio] += len(batch)
                    if total[prio] // 1000 != (total[prio] - len(batch)) // 1000:
                        log.info(
                            f"syslog batcher [{prio}]: {total[prio]} pushed "
                            f"(qsize hi={_queues['hi'].qsize()} mid={_queues['mid'].qsize()} lo={_queues['lo'].qsize()})"
                        )
                except Exception as e:
                    log.warning(f"Redis batch push failed [{prio}]: {e}, requeueing {len(batch)}")
                    for item in batch:
                        try:
                            _queues[prio].put_nowait(item)
                        except asyncio.QueueFull:
                            break
                    await asyncio.sleep(1)
                    break
        # Small breather to coalesce more events into a single rpush under load.
        if all(_queues[p].empty() for p in ("hi", "mid", "lo")):
            continue
        await asyncio.sleep(flush_interval)


_backpressure_active = False


async def _backpressure_monitor():
    """Log warnings and track state when queues approach capacity."""
    global _backpressure_active
    while True:
        await asyncio.sleep(5)
        total_cap = sum(q.maxsize for q in _queues.values())
        total_used = sum(q.qsize() for q in _queues.values())
        ratio = total_used / max(total_cap, 1)
        if ratio > 0.8 and not _backpressure_active:
            _backpressure_active = True
            log.warning(f"BACKPRESSURE: queues at {ratio:.0%} capacity "
                        f"(hi={_queues['hi'].qsize()} mid={_queues['mid'].qsize()} lo={_queues['lo'].qsize()})")
        elif ratio < 0.5 and _backpressure_active:
            _backpressure_active = False
            log.info("Backpressure cleared")


async def main():
    global _queues
    # Three priority queues. Hi is small (auth/error rarely), lo gets the
    # majority of the budget because firewall floods land there.
    _queues = {
        "hi":  asyncio.Queue(maxsize=max(2000, QUEUE_MAX // 5)),
        "mid": asyncio.Queue(maxsize=max(4000, QUEUE_MAX // 3)),
        "lo":  asyncio.Queue(maxsize=QUEUE_MAX),
    }

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)

    for _ in range(30):
        try:
            await redis_client.ping()
            break
        except Exception:
            log.info("Waiting for Redis...")
            await asyncio.sleep(2)

    await streams.ensure_groups(redis_client)
    await streams.drain_legacy_lists(redis_client)

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

    listeners = [server]
    transports = [transport]
    log.info("Syslog receiver ready (UDP + TCP)")

    if GELF_ENABLED:
        gelf_transport, _ = await loop.create_datagram_endpoint(
            GELFProtocol,
            local_addr=(LISTEN_HOST, GELF_PORT),
        )
        transports.append(gelf_transport)
        log.info(f"GELF UDP receiver ready on :{GELF_PORT}")

    if JSON_ENABLED:
        json_server = await asyncio.start_server(
            handle_json_tcp, LISTEN_HOST, JSON_PORT,
        )
        listeners.append(json_server)
        log.info(f"JSON TCP receiver ready on :{JSON_PORT}")

    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(batch_writer(redis_client))
            for srv in listeners:
                tg.create_task(srv.serve_forever())
            tg.create_task(_backpressure_monitor())
    finally:
        for t in transports:
            t.close()
        for s in listeners:
            s.close()


if __name__ == "__main__":
    asyncio.run(main())
