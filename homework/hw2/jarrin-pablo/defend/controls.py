"""A small SQLi blocklist and a parameterized-query positive model."""

from __future__ import annotations

import re
import sqlite3


WAF_RULES = [
    (re.compile(r"(?i)\b\d+\s*=\s*\d+\b"), "numeric equality"),
    (re.compile(r"(?i)\b(?:union\b.*\bselect|select\b.*\bunion)\b"),
     "UNION/SELECT words"),
    (re.compile(r"(?i)\bdrop\s+table\b"), "DROP TABLE words"),
]

PART_A_SQLI_PAYLOADS = ["admin' oR 1=1--"]

BYPASSES = [
    ("admin' oR 'a'='a'--", "string tautology instead of numeric equality"),
    ("admin' oR 2>1--", "greater-than comparison instead of equality"),
    ("admin' oR TRUE--", "SQLite boolean literal instead of a comparison"),
]


def waf_block(payload: str) -> str | None:
    """Return the matching blocklist rule, or None when the request passes."""
    for expression, name in WAF_RULES:
        if expression.search(payload):
            return name
    return None


def parameterized_login(username: str, password: str) -> bool:
    """Run a login query where untrusted values can never change SQL syntax."""
    database = sqlite3.connect(":memory:")
    try:
        database.execute("CREATE TABLE users (user TEXT, pw TEXT)")
        database.execute("INSERT INTO users VALUES (?, ?)", ("admin", "s3cr3t"))
        row = database.execute(
            "SELECT user FROM users WHERE user = ? AND pw = ?",
            (username, password),
        ).fetchone()
        return row is not None
    finally:
        database.close()
