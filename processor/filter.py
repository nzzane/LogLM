"""
Pre-LLM filtering rules.

Strategy:
  1. ALWAYS keep — security-critical patterns that must reach the LLM.
  2. ALWAYS drop — pure noise with zero diagnostic value.
  3. RATE LIMIT — recurring but occasionally meaningful messages.
     Keep the first occurrence per window, drop repeats.

The filter returns one of three verdicts:
  "keep"  — forward to LLM analysis queue
  "store" — store in Loki for history but skip LLM
  "drop"  — discard entirely
"""

import re
import time
from collections import defaultdict

# ── Patterns that are ALWAYS kept (security / critical) ────────────────────────
ALWAYS_KEEP: list[re.Pattern] = [re.compile(p, re.IGNORECASE) for p in [
    # Authentication events
    r"(failed|invalid|refused|rejected).*(password|login|auth|key)",
    r"(authentication failure|auth fail)",
    r"sudo:.*(incorrect password|authentication failure)",
    r"sshd.*invalid user",
    r"pam.*failure",
    # Firewall / network blocks
    r"\[UFW (BLOCK|DENY|DROP)\]",
    r"kernel.*DROPPED",
    r"(iptables|nftables).*(DROP|REJECT|BLOCK)",
    # Port scans / intrusion
    r"(port.?scan|nmap|masscan)",
    r"possible.*(syn flood|ddos|brute)",
    r"too many (authentication|login|connection) failures",
    r"repeated (login|auth) failures",
    # Privilege escalation
    r"(sudo|su):.*(not in sudoers|command not allowed)",
    r"useradd|userdel|usermod|groupadd|groupmod",
    r"(setuid|setgid|chmod.*(777|4[0-9]{3}))",
    # Service failures / crashes
    r"(segfault|kernel panic|oops|BUG:|call trace)",
    r"(service|unit).*(failed|error|crash)",
    r"systemd.*failed",
    r"out of memory|oom.kill",
    # Certificate / TLS
    r"certificate.*(expired|invalid|error|failed)",
    r"ssl.*(error|fail|handshake)",
    # Config changes
    r"(config|configuration).*(changed|modified|updated|reloaded)",
    r"nginx.*(reload|restart)",
    # Unifi specific
    r"sta.*(deauth|disassoc|block)",
    r"(blocked|allowed).*(client|device)",
    # Container events
    r"container.*(died|killed|oom|error)",
    r"docker.*(error|fail)",
]]

# ── Patterns that are ALWAYS dropped (pure noise) ──────────────────────────────
ALWAYS_DROP: list[re.Pattern] = [re.compile(p, re.IGNORECASE) for p in [
    # Health checks / uptime pings
    r'"GET /health',
    r'"GET /ping',
    r'"HEAD / HTTP',
    r"healthcheck",
    r"keepalive",
    # DHCP routine renewals (same IP renewals are not interesting)
    r"DHCPREQUEST.* from .* via .*: lease .* available",
    r"DHCPACK",
    r"DHCPOFFER",
    # NTP routine sync
    r"ntpd.*(frequency|offset|adjust|sync)",
    r"chronyd.*(tracking|source|offset|freq)",
    # Routine cron noise
    r"CRON\[\d+\]: \(root\) CMD \(/usr/sbin/(logrotate|updatedb|aide)",
    r"cron.*session (opened|closed) for user",
    # PAM session opens for routine services
    r"pam_unix.*session (opened|closed) for user (root|nobody|daemon|www-data|nginx|postgres)",
    # Kernel USB/hardware plug noise (not server-critical)
    r"usb [0-9]+-[0-9]+: new.*USB device",
    r"kernel: \[.*\] EXT4-fs.*mounted",
    # Repeated routine nginx access for static assets
    r'"GET /(favicon\.ico|robots\.txt|\.well-known/|static/)',
    # systemd routine start/stop of well-known units
    r"systemd.*Started Session \d+ of user",
    r"systemd.*Removed slice",
    r"systemd.*Created slice",
    # LibreNMS polling noise
    r"snmpd.*Connection from UDP",
    r"snmpwalk|snmpget",
]]

# ── Rate-limited patterns (keep first per window, drop repeats) ────────────────
RATE_LIMIT_PATTERNS: list[tuple[re.Pattern, int]] = [
    # (pattern, window_seconds)
    (re.compile(r"sshd.*Connection (closed|reset)", re.IGNORECASE), 300),
    (re.compile(r"DHCPREQUEST", re.IGNORECASE), 600),
    (re.compile(r"pam_unix.*session", re.IGNORECASE), 120),
    (re.compile(r"rsync", re.IGNORECASE), 300),
    (re.compile(r"logrotate", re.IGNORECASE), 3600),
    (re.compile(r"No mail\.", re.IGNORECASE), 3600),
]

# ── Severity-based rules ───────────────────────────────────────────────────────
# Severities 0-4 (emerg/alert/crit/err/warning) always kept
# Severity 5 (notice) kept unless noise patterns match
# Severity 6-7 (info/debug) dropped unless ALWAYS_KEEP matches
SEVERITY_KEEP_THRESHOLD = 5  # keep notice and above by default

SEVERITY_MAP = {
    "emerg": 0, "alert": 1, "crit": 2, "err": 3, "error": 3,
    "warning": 4, "warn": 4, "notice": 5, "info": 6, "debug": 7,
}


class RateLimiter:
    def __init__(self):
        # key → last_seen_timestamp
        self._seen: dict[str, float] = defaultdict(float)

    def should_drop(self, key: str, window: int) -> bool:
        now = time.monotonic()
        if now - self._seen[key] < window:
            return True
        self._seen[key] = now
        return False

    def cleanup(self):
        """Remove entries older than 1 hour to prevent unbounded growth."""
        cutoff = time.monotonic() - 3600
        self._seen = {k: v for k, v in self._seen.items() if v > cutoff}


_rate_limiter = RateLimiter()


def classify(event: dict) -> str:
    """
    Returns "keep", "store", or "drop".
    """
    msg = event.get("message", "")
    severity_str = event.get("severity", "info").lower()
    severity_num = SEVERITY_MAP.get(severity_str, 6)

    # 1. ALWAYS_KEEP wins over everything
    for pattern in ALWAYS_KEEP:
        if pattern.search(msg):
            return "keep"

    # 2. ALWAYS_DROP
    for pattern in ALWAYS_DROP:
        if pattern.search(msg):
            return "drop"

    # 3. High severity (emerg–warning) → keep even without explicit pattern
    if severity_num <= 4:
        return "keep"

    # 4. Rate-limited patterns
    for pattern, window in RATE_LIMIT_PATTERNS:
        if pattern.search(msg):
            host = event.get("host", "unknown")
            key = f"{pattern.pattern}:{host}"
            if _rate_limiter.should_drop(key, window):
                return "drop"
            return "store"  # first occurrence in window: store but don't LLM-analyze

    # 5. Notice → store (visible in UI, not LLM)
    if severity_num == 5:
        return "store"

    # 6. Info/debug → drop
    return "drop"
