"""vuln-web — a small, deliberately vulnerable web app (CMP-5006 week 6).

Two jobs at once, on purpose:

  1. You ATTACK the running app (SQLi, reflected XSS, command injection),
     confirming each finding with a seclab.attack oracle.
  2. You SCAN THIS SAME SOURCE with a classical scanner and with an LLM, then
     compare (seclab.scan). Because the target and the scan-subject are the same
     readable file, you can check every tool's finding against the truth by eye.

Stdlib only (sqlite3 + http.server), so the container is tiny and the whole app
fits on one screen. Every vulnerability is intentional and commented `# VULN`.

    GET  /health
    GET  /?name=<x>            reflected XSS sink
    POST /login {user,pw}      SQL injection sink (auth bypass)
    POST /ping  {host}         command-injection sink (os.system-style)
    GET  /safe?name=<x>        the FIXED version of the XSS sink (a true negative)

The command-injection sink does NOT actually run a shell — it simulates the
vulnerability by echoing what WOULD have been executed, so the lab is safe to run
anywhere while still being detectable and confirmable. That simulation is itself
a lesson: the bug is the unsanitized string reaching a command context, whether or
not this teaching copy pulls the trigger.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# A canary row so an oracle can CONFIRM a SQLi auth-bypass extracted real data,
# not just that the response changed.
CANARY_SECRET = "FLAG-sqli-9f2c-admin-session"


def make_db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE users (id INTEGER, user TEXT, pw TEXT, secret TEXT)")
    db.execute("INSERT INTO users VALUES (1,'admin','s3cr3t',?)", (CANARY_SECRET,))
    db.execute("INSERT INTO users VALUES (2,'alice','password','ordinary-row')")
    db.commit()
    return db


DB = make_db()


# ---------------------------------------------------------------------------
# The vulnerable handlers. Read these — you scan this exact code in Task 2.
# ---------------------------------------------------------------------------
def do_login(user: str, pw: str) -> str:
    # VULN: SQL injection. String-formatted query, no parameterization. The whole
    # point of the SQLi lab. Fixed version would be:
    #   DB.execute("SELECT ... WHERE user=? AND pw=?", (user, pw))
    query = (f"SELECT user, secret FROM users "
             f"WHERE user = '{user}' AND pw = '{pw}'")
    try:
        rows = DB.execute(query).fetchall()
    except sqlite3.Error as e:
        return json.dumps({"error": f"sql error: {e}", "query": query})
    if rows:
        # Leaks the secret on success — so ' OR '1'='1 dumps the admin canary.
        return json.dumps({"ok": True, "rows": rows})
    return json.dumps({"ok": False})


def do_reflect(name: str) -> str:
    # VULN: reflected XSS. User input placed into HTML with no encoding.
    # Fixed version is /safe, which html.escape()s the input.
    return f"<html><body><h1>Hello, {name}!</h1></body></html>"


def do_reflect_safe(name: str) -> str:
    import html
    return f"<html><body><h1>Hello, {html.escape(name)}!</h1></body></html>"


def do_ping(host: str) -> str:
    # VULN: command injection. The host string is concatenated into a command.
    # We SIMULATE execution (echo the command) so the lab is safe to run, but the
    # bug — untrusted data reaching a command context — is real and detectable.
    command = f"ping -c 1 {host}"
    # A real app would do os.system(command). We parse it to reveal the injection:
    injected = bool(re.search(r"[;&|`$()]", host))
    return json.dumps({
        "would_run": command,
        "injection_detected": injected,
        "note": ("extra command(s) smuggled in via a shell metacharacter"
                 if injected else "no shell metacharacters in host"),
    })


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _form(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode() if n else ""
        try:
            return json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return {k: v[0] for k, v in parse_qs(raw).items()}

    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/health":
            return self._send(200, json.dumps({"status": "ok"}))
        if u.path == "/":
            return self._send(200, do_reflect(q.get("name", [""])[0]), "text/html")
        if u.path == "/safe":
            return self._send(200, do_reflect_safe(q.get("name", [""])[0]), "text/html")
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        u = urlparse(self.path)
        form = self._form()
        if u.path == "/login":
            return self._send(200, do_login(form.get("user", ""), form.get("pw", "")))
        if u.path == "/ping":
            return self._send(200, do_ping(form.get("host", "")))
        return self._send(404, json.dumps({"error": "not found"}))


def main():
    port = int(os.environ.get("PORT", "8000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"vuln-web on :{port}", file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
