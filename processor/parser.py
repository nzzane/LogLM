"""
Normalises raw log JSON from various sources into a canonical LogEvent dict.
Handles:
  - rsyslog JSON output
  - nginx combined/error log format (via syslog tag)
  - UFW / iptables / UniFi / EdgeOS / pfSense / OPNsense firewall messages
  - MikroTik firewall log lines
  - SNMP trap handler JSON
  - LibreNMS alert JSON
"""

import ipaddress
import re
import json
from datetime import datetime, timezone
from typing import Optional


# iptables / UFW kv format: SRC=a.b.c.d DST=... SPT=... DPT=... PROTO=... IN=eth0 OUT=eth1 MAC=...
_IPTABLES_KV_RE = re.compile(r"(?P<k>SRC|DST|SPT|DPT|PROTO|IN|OUT|LEN|TTL)=(?P<v>[^\s]+)", re.IGNORECASE)
_UFW_ACTION_RE = re.compile(r"\[UFW (?P<action>BLOCK|ALLOW|AUDIT|LIMIT|DENY|DROP|REJECT)\]", re.IGNORECASE)
_IPTABLES_ACTION_RE = re.compile(r"\b(?P<action>DROPPED|ACCEPT|REJECT|BLOCK|DROP|DENY|LOG|ALLOW)\b", re.IGNORECASE)

# pfSense / OPNsense filterlog CSV format (common fields):
#   rule,subrule,anchor,tracker,interface,reason,action,direction,ipv,...ipsrc,ipdst,spt,dpt,...
# Example: "5,,,0,igb0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,40,1.2.3.4,10.0.0.1,12345,22,..."
_PFSENSE_RE = re.compile(
    r"filterlog\[\d+\]:\s*(?P<csv>[\d,a-fA-F\.:\-_x]+)",
    re.IGNORECASE,
)

# MikroTik firewall: "firewall,info forward: in:ether1 out:ether2, src-mac xx, proto TCP, 1.2.3.4:12345->10.0.0.1:22, NAT"
_MIKROTIK_RE = re.compile(
    r"(?:firewall[,:]\s*\w+\s+)?(?P<action>forward|input|output|drop|accept|reject)[^,]*"
    r"(?:.*?in:(?P<in>\S+))?"
    r"(?:.*?out:(?P<out>\S+))?"
    r"(?:.*?proto\s+(?P<proto>\w+))?"
    r".*?(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s*->\s*"
    r"(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)",
    re.IGNORECASE,
)

# Unifi/kernel UFW block parser (legacy partial match, kept as fallback)
_UFW_RE = re.compile(
    r"\[UFW (?P<action>\w+)\].*SRC=(?P<src>[^\s]+).*DST=(?P<dst>[^\s]+)"
    r"(?:.*PROTO=(?P<proto>[^\s]+))?(?:.*DPT=(?P<dpt>[^\s]+))?",
    re.IGNORECASE,
)

_BLOCK_ACTIONS = {"block", "drop", "dropped", "deny", "denied", "reject", "rejected"}

# Commonly abused / scanned ports — if someone is hitting these from outside,
# the flow is inherently concerning regardless of whether the firewall blocked it.
CONCERNING_PORTS = {
    22: "ssh", 23: "telnet", 445: "smb", 139: "netbios", 3389: "rdp",
    5900: "vnc", 1433: "mssql", 3306: "mysql", 5432: "postgres",
    6379: "redis", 9200: "elasticsearch", 27017: "mongodb", 11211: "memcached",
    21: "ftp", 25: "smtp", 110: "pop3", 143: "imap",
    161: "snmp", 162: "snmp-trap", 137: "netbios-ns", 138: "netbios-dgm",
    5060: "sip", 8080: "http-alt", 8443: "https-alt",
}


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except (ValueError, TypeError):
        return False


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or
                    addr.is_multicast or addr.is_reserved or addr.is_unspecified)
    except (ValueError, TypeError):
        return False


def _classify_flow(src_ip: str, dst_ip: str, dst_port: int | None, action: str) -> dict:
    """Enrich a firewall flow with direction + concerning flags. Shape is
    consumed by both the processor (for severity decisions) and the UI (to
    colour flows + compute dashboard counters)."""
    action_norm = (action or "").lower()
    blocked = any(a in action_norm for a in _BLOCK_ACTIONS)

    direction = "internal"
    if _is_public_ip(src_ip) and _is_private_ip(dst_ip):
        direction = "inbound"
    elif _is_private_ip(src_ip) and _is_public_ip(dst_ip):
        direction = "outbound"
    elif _is_public_ip(src_ip) and _is_public_ip(dst_ip):
        direction = "transit"

    port_name = CONCERNING_PORTS.get(dst_port) if dst_port else None
    concerning_reasons = []
    if direction == "inbound" and port_name:
        concerning_reasons.append(f"inbound_to_{port_name}")
    if direction == "outbound" and port_name in ("ssh", "rdp", "smb", "rpc"):
        concerning_reasons.append(f"outbound_to_{port_name}")
    if blocked and direction == "inbound":
        concerning_reasons.append("blocked_inbound")
    return {
        "direction": direction,
        "blocked": blocked,
        "concerning": bool(concerning_reasons),
        "concerning_reasons": concerning_reasons,
        "port_name": port_name,
    }


def _parse_iptables_kv(msg: str) -> dict | None:
    """UFW / iptables / kernel-firewall kv format. Picks SRC/DST/SPT/DPT/PROTO/IN/OUT."""
    kv = {m.group("k").upper(): m.group("v") for m in _IPTABLES_KV_RE.finditer(msg)}
    if not kv.get("SRC") and not kv.get("DST"):
        return None
    m_ufw = _UFW_ACTION_RE.search(msg)
    if m_ufw:
        action = m_ufw.group("action")
    else:
        m_act = _IPTABLES_ACTION_RE.search(msg)
        action = m_act.group("action") if m_act else "LOG"
    try:
        dpt = int(kv["DPT"]) if kv.get("DPT") else None
    except ValueError:
        dpt = None
    try:
        spt = int(kv["SPT"]) if kv.get("SPT") else None
    except ValueError:
        spt = None
    return {
        "action": action,
        "src_ip": kv.get("SRC", ""),
        "dst_ip": kv.get("DST", ""),
        "src_port": spt,
        "dst_port": dpt,
        "proto": (kv.get("PROTO") or "").lower(),
        "in_iface": kv.get("IN", ""),
        "out_iface": kv.get("OUT", ""),
    }


def _parse_pfsense(msg: str) -> dict | None:
    m = _PFSENSE_RE.search(msg)
    if not m:
        return None
    fields = m.group("csv").split(",")
    # filterlog CSV field positions (v4 TCP/UDP):
    # 0 rulenum, 4 iface, 6 action, 7 dir, 8 ipversion, 16 proto-name,
    # 18 src_ip, 19 dst_ip, 20 src_port, 21 dst_port
    if len(fields) < 22:
        return None
    return {
        "action": fields[6] or "log",
        "src_ip": fields[18],
        "dst_ip": fields[19],
        "src_port": int(fields[20]) if fields[20].isdigit() else None,
        "dst_port": int(fields[21]) if fields[21].isdigit() else None,
        "proto": fields[16].lower() if len(fields) > 16 else "",
        "in_iface": fields[4] if fields[7] == "in" else "",
        "out_iface": fields[4] if fields[7] == "out" else "",
    }


def _parse_mikrotik(msg: str) -> dict | None:
    m = _MIKROTIK_RE.search(msg)
    if not m:
        return None
    try:
        dpt = int(m.group("dst_port"))
        spt = int(m.group("src_port"))
    except (TypeError, ValueError):
        dpt = spt = None
    return {
        "action": m.group("action"),
        "src_ip": m.group("src_ip"),
        "dst_ip": m.group("dst_ip"),
        "src_port": spt,
        "dst_port": dpt,
        "proto": (m.group("proto") or "").lower(),
        "in_iface": m.group("in") or "",
        "out_iface": m.group("out") or "",
    }


def _parse_firewall(msg: str, program: str) -> dict | None:
    """Try each firewall format in turn. Returns enriched structured dict or None."""
    if "filterlog" in program or "filterlog[" in msg:
        parsed = _parse_pfsense(msg)
        if parsed:
            return parsed
    if "mikrotik" in program or "firewall,info" in msg.lower() or "->" in msg and any(
        k in msg.lower() for k in ("forward", "src-mac", "proto tcp", "proto udp")
    ):
        parsed = _parse_mikrotik(msg)
        if parsed:
            return parsed
    # UFW/iptables kv is the broadest fallback.
    parsed = _parse_iptables_kv(msg)
    if parsed:
        return parsed
    # Legacy partial-match UFW (for minimal log formats that don't have full kv).
    m = _UFW_RE.search(msg)
    if m:
        try:
            dpt = int(m.group("dpt")) if m.group("dpt") else None
        except (ValueError, TypeError):
            dpt = None
        return {
            "action": m.group("action"),
            "src_ip": m.group("src"),
            "dst_ip": m.group("dst"),
            "src_port": None,
            "dst_port": dpt,
            "proto": (m.group("proto") or "").lower(),
            "in_iface": "",
            "out_iface": "",
        }
    return None

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

# Generic auth failure (web UIs, appliances, pfsense, synology, TrueNAS, etc.)
_GENERIC_AUTH_FAIL_RE = re.compile(
    r"(?:unsuccessful|failed|invalid|denied|rejected|refused)\s+(?:login|auth(?:entication)?|sign[- ]?in|access)"
    r"(?:.*?user\s+(?P<user>\S+))?"
    r"(?:.*?from\s+(?P<src_ip>[\d.a-f:]+))?",
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

    # ── Firewalls (UFW/iptables/pf/OPNsense/MikroTik) ─────────────────────────
    msg_lower = msg.lower()
    if ("[ufw " in msg_lower or "src=" in msg_lower or "dropped" in msg_lower
            or "iptables" in msg_lower or "filterlog" in program
            or "mikrotik" in program or "firewall,info" in msg_lower):
        parsed = _parse_firewall(msg, program)
        if parsed:
            flags = _classify_flow(
                parsed["src_ip"], parsed["dst_ip"], parsed.get("dst_port"), parsed["action"]
            )
            event["source"] = "firewall"
            event["structured"] = {
                "type": "firewall_event",
                **parsed,
                **flags,
            }
            if flags["blocked"] and flags["direction"] == "inbound":
                event["severity"] = "warning"
            elif flags["concerning"]:
                event["severity"] = "warning"
            else:
                event["severity"] = "info" if not flags["blocked"] else "notice"
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

    # ── Generic auth failure (catch-all for appliances, web UIs, NAS, etc.) ──
    m = _GENERIC_AUTH_FAIL_RE.search(msg)
    if m:
        event["source"] = "auth"
        event["structured"] = {
            "type": "auth_failure",
            "user": m.group("user") or "",
            "src_ip": m.group("src_ip") or "",
            "program": event["program"],
        }
        event["severity"] = "warning"
        return event

    return event
