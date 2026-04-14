"""
Normalises raw log JSON from various sources into a canonical LogEvent dict.
Handles:
  - rsyslog JSON output
  - nginx combined/error log format (via syslog tag)
  - Unifi/EdgeOS kernel firewall messages
  - SNMP trap handler JSON
  - LibreNMS alert JSON
"""

import re
import json
from datetime import datetime, timezone
from typing import Optional


# Unifi/kernel UFW block parser
_UFW_RE = re.compile(
    r"\[UFW (?P<action>\w+)\].*SRC=(?P<src>[^\s]+).*DST=(?P<dst>[^\s]+)"
    r"(?:.*PROTO=(?P<proto>[^\s]+))?(?:.*DPT=(?P<dpt>[^\s]+))?",
    re.IGNORECASE,
)

# nginx combined log parser (when sent via syslog)
_NGINX_RE = re.compile(
    r'(?P<remote_addr>[^\s]+) - (?P<remote_user>[^\s]+) \[(?P<time_local>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<body_bytes>\d+) '
    r'"(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"',
)

# SSH failed login
_SSH_FAIL_RE = re.compile(
    r"Failed (?P<method>\w+) for (invalid user )?(?P<user>\S+) from (?P<src_ip>[\d.a-f:]+)",
    re.IGNORECASE,
)


def parse(raw: dict) -> dict:
    """
    Takes a raw log dict (from Redis) and returns an enriched canonical event.
    """
    event = {
        "timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "host": raw.get("host", raw.get("hostname", "unknown")),
        "source": raw.get("source", "syslog"),
        "severity": raw.get("severity", "info"),
        "facility": raw.get("facility", "user"),
        "program": raw.get("program", raw.get("tag", "unknown")),
        "pid": raw.get("pid", ""),
        "message": raw.get("message", "").strip(),
        "structured": {},
    }

    msg = event["message"]
    program = event["program"].lower()

    # ── nginx ──────────────────────────────────────────────────────────────────
    if "nginx" in program:
        m = _NGINX_RE.search(msg)
        if m:
            event["source"] = "nginx"
            event["structured"] = {
                "type": "http_access",
                "remote_addr": m.group("remote_addr"),
                "request": m.group("request"),
                "status": int(m.group("status")),
                "bytes": int(m.group("body_bytes")),
                "user_agent": m.group("http_user_agent"),
            }
            # Promote 5xx to warning
            if int(m.group("status")) >= 500:
                event["severity"] = "warning"
            return event

    # ── Unifi/kernel firewall ──────────────────────────────────────────────────
    if "[UFW " in msg or "DROPPED" in msg or "iptables" in msg.lower():
        m = _UFW_RE.search(msg)
        if m:
            event["source"] = "firewall"
            event["structured"] = {
                "type": "firewall_event",
                "action": m.group("action"),
                "src_ip": m.group("src"),
                "dst_ip": m.group("dst"),
                "proto": m.group("proto") or "",
                "dst_port": m.group("dpt") or "",
            }
            event["severity"] = "warning" if m.group("action") in ("BLOCK", "DROP", "DENY") else "info"
            return event

    # ── SSH failures ───────────────────────────────────────────────────────────
    if "sshd" in program:
        m = _SSH_FAIL_RE.search(msg)
        if m:
            event["source"] = "sshd"
            event["structured"] = {
                "type": "auth_failure",
                "method": m.group("method"),
                "user": m.group("user"),
                "src_ip": m.group("src_ip"),
            }
            event["severity"] = "warning"
            return event

    # ── SNMP trap (already structured) ────────────────────────────────────────
    if raw.get("source") == "snmp_trap":
        event["source"] = "snmp"
        event["structured"] = {"type": "snmp_trap", "oids": raw.get("raw_oids", {})}
        return event

    return event
