"""Experimental defenses using the standard library without modifying the shared target."""
import html
import json
import re

WAF_RULES = (
    (re.compile(r"\bor\b", re.I), "keyword OR"),
    (re.compile(r"select|union|drop", re.I), "SQL keyword substring"),
)


def waf_reason(value):
    return next((name for pattern, name in WAF_RULES if pattern.search(value)), None)


def login(db, user, pw):
    rows = db.execute(
        "SELECT user, secret FROM users WHERE user = ? AND pw = ?", (user, pw)
    ).fetchall()
    return json.dumps({"ok": bool(rows), "rows": rows})


def reflect(name):
    return f"<html><body><h1>Hello, {html.escape(name)}!</h1></body></html>"


def ping(host):
    # This lab preserves the simulation: it never invokes a shell.
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
        return 400, json.dumps({"error": "invalid host"})
    return 200, json.dumps({"argv": ["ping", "-c", "1", host],
                            "injection_detected": False, "simulated": True})
