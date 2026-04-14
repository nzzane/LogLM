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


class UDPSyslogProtocol(asyncio.DatagramProtocol):
    """Handles incoming UDP syslog datagrams."""

    def __init__(self, redis_client: aioredis.Redis):
        self.redis = redis_client
        self._count = 0

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return
        event = parse_syslog(text, addr)
        asyncio.create_task(self._push(event))

    async def _push(self, event: dict):
        try:
            await self.redis.rpush("loglm:raw", json.dumps(event))
            self._count += 1
            if self._count % 1000 == 0:
                log.info(f"UDP: {self._count} messages received")
        except Exception as e:
            log.warning(f"Redis push failed: {e}")


async def handle_tcp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                            redis_client: aioredis.Redis):
    """Handle a single TCP syslog connection (one message per line)."""
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
            event = parse_syslog(text, addr)
            await redis_client.rpush("loglm:raw", json.dumps(event))
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


async def main():
    redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)

    # Wait for Redis
    for _ in range(30):
        try:
            await redis_client.ping()
            break
        except Exception:
            log.info("Waiting for Redis...")
            await asyncio.sleep(2)

    log.info(f"Syslog receiver starting on {LISTEN_HOST}:{LISTEN_PORT} (UDP+TCP)")

    loop = asyncio.get_running_loop()

    # UDP listener
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UDPSyslogProtocol(redis_client),
        local_addr=(LISTEN_HOST, LISTEN_PORT),
    )

    # TCP listener
    server = await asyncio.start_server(
        lambda r, w: handle_tcp_client(r, w, redis_client),
        LISTEN_HOST, LISTEN_PORT,
    )

    log.info("Syslog receiver ready (UDP + TCP)")

    try:
        await asyncio.gather(
            server.serve_forever(),
            asyncio.Future(),  # keep UDP running
        )
    finally:
        transport.close()
        server.close()


if __name__ == "__main__":
    asyncio.run(main())
