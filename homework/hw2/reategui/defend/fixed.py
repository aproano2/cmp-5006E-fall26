"""Structural fixes for all three copied teaching sinks (Part B2)."""

import html
import ipaddress
import json
import re

from lab_target import original


def fixed_login(user: str, pw: str) -> str:
    rows = original.DB.execute(
        "SELECT user, secret FROM users WHERE user = ? AND pw = ?", (user, pw)
    ).fetchall()
    return json.dumps({"ok": bool(rows), "rows": rows if rows else []})


def fixed_reflect(name: str) -> str:
    return f"<html><body><h1>Hello, {html.escape(name, quote=True)}!</h1></body></html>"


def fixed_ping(host: str) -> str:
    # A real implementation would pass this argv to subprocess.run(shell=False).
    # We preserve the target's no-execution policy and expose argv for inspection.
    allowed = False
    try:
        ipaddress.ip_address(host)
        allowed = True
    except ValueError:
        if re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host):
            allowed = all(0 < len(label) <= 63 and not label.startswith("-")
                          and not label.endswith("-") for label in host.split("."))
    return json.dumps({"accepted": allowed,
                       "argv": ["ping", "-c", "1", host] if allowed else None,
                       "injection_detected": False})
