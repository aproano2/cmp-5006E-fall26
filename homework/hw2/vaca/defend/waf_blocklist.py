"""B1 — the negative-security defense: a WAF blocklist for the SQLi sink.

This is the "Medium filter" Part A must bypass and the defense Part B1 measures.
It is a deliberately *reasonable* blocklist — richer than a toy, modelled on the
DVWA-Medium login filter and ModSecurity-CRS SQLi rules:

  * strip/normalize SQL comment terminators,
  * catch the classic numeric/string tautologies (`OR 1=1`, `OR 'a'='a'`),
  * catch `UNION SELECT` across whitespace/comment obfuscation,
  * catch stacked `DROP TABLE`, and a bare `' OR` injection opener.

It enumerates *badness*. That is the whole point of the week-7 thread: a negative
model can be made to cover the payloads you thought of (Part A coverage) but can
never be complete (Part B1 bypass) and is never quiet (Part B1 false positives).

Reported `(matched_rule or None)` so callers can measure coverage, bypass, and FP
the same way.
"""

from __future__ import annotations

import re

# (compiled rule, human name). Case-insensitive; a couple tolerate inline
# comments / whitespace runs the way a mod_security rule would.
WAF_RULES = [
    (re.compile(r"(?i)\bor\b\s*/\*.*?\*/\s*\d+\s*=\s*\d+"), "SQLi OR numeric tautology (comment-obfuscated)"),
    (re.compile(r"(?i)\bor\b\s+\d+\s*=\s*\d+"),            "SQLi OR numeric tautology"),
    (re.compile(r"(?i)\bor\b\s+'[^']*'\s*=\s*'[^']*'"),    "SQLi OR string tautology"),
    (re.compile(r"(?i)union[\s/*]+select"),               "SQLi UNION SELECT"),
    (re.compile(r"(?i)drop[\s/*]+table"),                 "SQLi DROP TABLE"),
    (re.compile(r"(?i)'\s*or\b"),                          "SQLi quote-OR opener"),
    (re.compile(r"(?i)(--|#)\s*$"),                        "SQL comment terminator"),
]


def waf_block(payload: str):
    """Return the name of the first rule that fires, or None if the request
    passes the blocklist."""
    for rx, name in WAF_RULES:
        if rx.search(payload):
            return name
    return None
