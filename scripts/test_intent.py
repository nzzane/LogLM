import re as _re

_IGNORE_RE = _re.compile(
    r"(?:ignore|suppress|hide|exclude|filter out?|stop logging|block|mute)\s+"
    r"(?:all\s+)?(?:the\s+)?"
    r"(?P<pattern>[\w][\w\s\-/]{0,60}?)"
    r"(?:\s+(?:errors?|warnings?|messages?|logs?|events?|alerts?))?\s+"
    r"(?:on|from|for|at|coming from)\s+"
    r"(?P<hosts>.{3,120})",
    _re.IGNORECASE,
)

_RULE_VERB_RE = _re.compile(
    r"(?:create|add|make|set up?|configure|apply)\s+(?:a\s+)?(?:filter|rule|custom rule|ignore rule)?\s*"
    r"(?:to|for)\s+(?:ignore|suppress|filter out?|hide|exclude)\s+"
    r"(?:all\s+)?(?P<pattern>[\w][\w\s\-/]{0,60}?)"
    r"(?:\s+(?:errors?|warnings?|messages?|logs?|events?))?\s+"
    r"(?:on|from|for|at)\s+"
    r"(?P<hosts>.{3,120})",
    _re.IGNORECASE,
)

tests = [
    ("can we ignore all interface errors on the APs (U6-LR and U7-Pro)", True),
    ("ignore interface errors on U6-LR and U7-Pro", True),
    ("create the custom filter rule", False),   # should NOT match
    ("suppress snmp errors from unifi-ap-office", True),
    ("block dhcp noise from all routers", True),
    ("can we ignore all interface errors on the AP's (U6-LR and U7-Pro)", True),
]

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'web', 'app'))

_HOSTNAME_RE = _re.compile(r"\b([A-Za-z0-9][A-Za-z0-9\-_.]{1,62})\b")
_HOST_STOPWORDS = frozenset({
    "the", "all", "any", "and", "or", "for", "on", "from", "at", "both",
    "ap", "aps", "router", "routers", "switch", "switches", "device", "devices",
    "host", "hosts", "server", "servers", "network", "interface", "interfaces",
    "these", "those", "this", "that", "with", "using", "via",
})

def _split_hosts(raw):
    tokens = _HOSTNAME_RE.findall(raw)
    return [t for t in tokens if t.lower() not in _HOST_STOPWORDS][:8]

# Test host splitting
host_tests = [
    ("the APs (U6-LR and U7-Pro)", ["U6-LR", "U7-Pro"]),
    ("U6-LR and U7-Pro", ["U6-LR", "U7-Pro"]),
    ("unifi-ap-office, switch-01", ["unifi-ap-office", "switch-01"]),
    ("all routers", []),  # generic terms stripped
]
for raw, expected in host_tests:
    result = _split_hosts(raw)
    ok = "OK " if sorted(result) == sorted(expected) or (not expected and not result) else "FAIL"
    print(f"{ok} split_hosts({repr(raw)}) -> {result}  (expected {expected})")

print()
for msg, expect_match in tests:
    m = _IGNORE_RE.search(msg) or _RULE_VERB_RE.search(msg)
    matched = m is not None
    status = "OK " if matched == expect_match else "FAIL"
    if m:
        print(f"{status} MATCH  pattern={repr(m.group('pattern').strip()[:40])} hosts={repr(m.group('hosts').strip()[:50])}")
    else:
        print(f"{status} no match: {repr(msg[:70])}")
