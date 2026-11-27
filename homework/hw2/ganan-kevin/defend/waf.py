"""B1 negative-model WAF: intentionally narrow regex blocklist.

The filter is enforced by waf_proxy.py when clients use the proxy listener.
It remains a negative model: it blocks known lexical patterns, not all
semantically malicious inputs.
"""
from __future__ import annotations
import re
from dataclasses import dataclass

@dataclass
class WafVerdict:
    blocked: bool
    rule: str | None
    field: str

_SQLI_PATTERNS = [
    re.compile(r"(?i)\bor\b.{0,10}=.{0,10}"),
    re.compile(r"(?i)\bunion\b.{0,10}\bselect\b"),
    re.compile(r"(?i)\bdrop\b.{0,10}\btable\b"),
    re.compile(r"'"),
]
_XSS_PATTERNS = [
    re.compile(r"(?i)<\s*script"),
    re.compile(r"(?i)on\w+\s*="),
    re.compile(r"(?i)javascript\s*:"),
]
_CMDI_PATTERNS = [
    re.compile(r"[;&|`$]"),
    re.compile(r"\(.*\)"),
]

def check(field: str, value: str) -> WafVerdict:
    if not isinstance(value, str):
        value = str(value)
    patterns = {
        "login_username": _SQLI_PATTERNS,
        "search_or_name": _SQLI_PATTERNS + _XSS_PATTERNS,
        "ping_host": _CMDI_PATTERNS,
    }.get(field, [])
    for pattern in patterns:
        if pattern.search(value):
            return WafVerdict(True, pattern.pattern, field)
    return WafVerdict(False, None, field)
