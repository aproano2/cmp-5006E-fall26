"""B2 — the positive (structural) fix for all three sinks.

A positive model gives a GUARANTEE independent of any specific attack string:
it changes the shape of the operation so that untrusted input can never be
anything other than data. Contrast this with B1 (the blocklist), whose
guarantee is "we block the payloads we thought of" -- a negative, enumerable
claim that a creative attacker can always try to step around.

Each fix below targets exactly the vulnerable sink in `vulnweb_app.py`,
with the axis-2 guarantee it gives stated in its docstring.
"""
from __future__ import annotations

import html
import json
import re
import sqlite3


# ---------------------------------------------------------------------------
# B2.1 -- SQL injection fix (do_login)
# ---------------------------------------------------------------------------
def do_login_fixed(db: sqlite3.Connection, user: str, pw: str) -> str:
    """Parameterized query -- user/pw are bound as DATA, never concatenated
    into the SQL text.

    GUARANTEE (axis 2): no value of `user` or `pw` can alter the query's
    structure -- the WHERE clause's shape is fixed at prepare time, before any
    untrusted value is bound -- PROVIDED the DB driver's parameter binding is
    used correctly (never f-string'd back into the query by a future edit)
    and this remains the only code path that builds this query.
    """
    query = "SELECT user, secret FROM users WHERE user = ? AND pw = ?"
    try:
        rows = db.execute(query, (user, pw)).fetchall()
    except sqlite3.Error as e:
        return json.dumps({"error": f"sql error: {e}"})
    if rows:
        return json.dumps({"ok": True, "rows": rows})
    return json.dumps({"ok": False})


# ---------------------------------------------------------------------------
# B2.2 -- XSS fix (do_reflect) -- this is literally `do_reflect_safe`,
# already present in vulnweb_app.py as the course's own reference fix.
# ---------------------------------------------------------------------------
def do_reflect_fixed(name: str) -> str:
    """Output-encode before placing untrusted data into an HTML context.

    GUARANTEE (axis 2): no value of `name` can introduce a new HTML tag or
    attribute boundary -- `html.escape` maps every character with special
    meaning in HTML ( < > & " ' ) to its inert entity -- PROVIDED the output
    is rendered as HTML text content (not re-parsed as HTML/JS a second time,
    e.g. via `innerHTML` with escaping undone, and not placed inside an
    unquoted HTML attribute, which needs a different escaping rule).
    """
    return f"<html><body><h1>Hello, {html.escape(name)}!</h1></body></html>"


# ---------------------------------------------------------------------------
# B2.3 -- command-injection fix (do_ping) -- allowlist the input shape
# ---------------------------------------------------------------------------
# Valid hostnames/IPv4 literals only: letters, digits, dots, hyphens.
# Deliberately EXCLUDES every shell metacharacter in vulnweb_app.py's own
# detector (`[;&|`$()]`), so anything that would have tripped that detector
# is rejected before it ever reaches a command string.
_HOST_ALLOWLIST = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,253}[A-Za-z0-9])?$")


def do_ping_fixed(host: str) -> str:
    """Allowlist the input SHAPE, rather than blocklisting bad characters.

    GUARANTEE (axis 2): the command string this builds contains only
    characters from [A-Za-z0-9.-], so it cannot contain a shell metacharacter
    -- for ANY input, not just the ones we thought to blocklist -- PROVIDED
    this validation runs on every call path that reaches `do_ping_fixed`
    (an allowlist that can be bypassed by calling a different, unvalidated
    entry point gives no guarantee at all; the condition is about coverage,
    not just correctness of the regex).

    Even with a valid host, this implementation still only SIMULATES running
    the command (matching the teaching copy in `vulnweb_app.py`) -- the real
    production fix would also avoid a shell entirely (e.g. subprocess with a
    list of args, no shell=True), which the allowlist here is a stand-in for
    the discussion of, not a replacement for.
    """
    if not _HOST_ALLOWLIST.match(host):
        return json.dumps({
            "would_run": None,
            "injection_detected": False,
            "rejected": True,
            "note": f"host {host!r} does not match the hostname/IP allowlist; refused",
        })
    command = f"ping -c 1 {host}"
    return json.dumps({
        "would_run": command,
        "injection_detected": False,
        "rejected": False,
        "note": "host matched the allowlist; no shell metacharacter is possible here",
    })
