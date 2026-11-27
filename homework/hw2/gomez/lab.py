"""Local HTTP harness for the copied course target; binds only to loopback.

The distributed vuln-web source has no Medium mode. This explicit teaching layer
is therefore ours, not a claim about the instructor's original implementation.
"""

from __future__ import annotations

import json
import re
import threading
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen
from urllib.parse import quote
import sys

ROOT = Path(__file__).resolve().parent
from lab_target import original  # noqa: E402

from defend.fixed import fixed_login, fixed_ping, fixed_reflect  # noqa: E402
from defend.waf import waf_block  # noqa: E402


class LabHandler(original.Handler):
    medium = True
    waf = False
    fixed = False

    def do_GET(self):
        parsed = urlparse(self.path)
        name = parse_qs(parsed.query).get("name", [""])[0]
        if parsed.path == "/health":
            return self._send(200, json.dumps({"status": "ok"}))
        if parsed.path == "/safe":
            return self._send(200, original.do_reflect_safe(name), "text/html")
        if parsed.path == "/":
            # The deliberately narrow Medium rule rejects one spelling only.
            if self.medium and "<script" in name:
                return self._send(403, json.dumps({"blocked": "medium-xss"}))
            body = fixed_reflect(name) if self.fixed else original.do_reflect(name)
            return self._send(200, body, "text/html")
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        parsed = urlparse(self.path)
        form = self._form()
        if parsed.path == "/login":
            user, pw = str(form.get("user", "")), str(form.get("pw", ""))
            # Whitespace-delimited OR is a realistic but incomplete negative rule.
            if self.medium and re.search(r"\sOR\s", user, re.I):
                return self._send(403, json.dumps({"blocked": "medium-sqli"}))
            if self.waf:
                reason = waf_block(user)
                if reason:
                    return self._send(403, json.dumps({"blocked": reason}))
            body = fixed_login(user, pw) if self.fixed else original.do_login(user, pw)
            return self._send(200, body)
        if parsed.path == "/ping":
            host = str(form.get("host", ""))
            if self.medium and ";" in host:
                return self._send(403, json.dumps({"blocked": "medium-cmdi"}))
            body = fixed_ping(host) if self.fixed else original.do_ping(host)
            return self._send(200, body)
        return self._send(404, json.dumps({"error": "not found"}))


@contextmanager
def serve(*, medium=True, waf=False, fixed=False):
    original.DB = original.make_db()
    handler = type("ConfiguredHandler", (LabHandler,),
                   {"medium": medium, "waf": waf, "fixed": fixed})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def get(base: str, path: str, name: str) -> tuple[int, str]:
    with urlopen(base + path + "?name=" + quote(name), timeout=5) as response:
        return response.status, response.read().decode("utf-8")


def post(base: str, path: str, field: str, value: str) -> tuple[int, str]:
    data = {field: value}
    if path == "/login":
        data["pw"] = "x"
    request = Request(base + path, data=json.dumps(data).encode("utf-8"),
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=5) as response:
        return response.status, response.read().decode("utf-8")


def safe_request(fn, *args):
    """Return (status, body), including expected HTTP 403 blocks."""
    from urllib.error import HTTPError
    try:
        return fn(*args)
    except HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")
