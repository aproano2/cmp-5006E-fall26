"""Shared plumbing for HW2: run vuln-web in-process and talk to it.

Every server binds to 127.0.0.1 on a free port (course scope: local sandbox only).
The target is the course's own labs/vuln-web/app/vulnweb_app.py, imported, not copied.
"""
import csv
import json
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent             # homework/hw2/soto
ROOT = HERE.parents[2]                             # repo root (contains seclab/)
RESULTS = HERE / "results"
for p in (ROOT, ROOT / "labs" / "vuln-web" / "app"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import vulnweb_app as app                          # noqa: E402  the real target
from seclab.attack import Payload, run_payloads    # noqa: E402,F401

CANARY = app.CANARY_SECRET


def serve(handler_cls=app.Handler):
    """Start `handler_cls` on 127.0.0.1:<free port>. Returns (base_url, shutdown)."""
    app.DB = app.make_db()                         # fresh DB -> deterministic canary
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.1)
    return f"http://127.0.0.1:{srv.server_address[1]}", srv.shutdown


def post(base, path, obj):
    req = urllib.request.Request(base + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode()
    except urllib.error.HTTPError as e:            # e.g. 403 from the WAF
        return e.read().decode()


def get(base, path):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return r.read().decode()


# --- senders: payload text -> raw response body --------------------------------
def login_sender(base, field="user"):
    """SQLi sink. The payload goes in `field`; the other field is a fixed wrong
    password / the known username 'admin', so a leak means the password check
    was bypassed, not passed."""
    def send(p):
        body = {"user": p, "pw": "x"} if field == "user" else {"user": "admin", "pw": p}
        return post(base, "/login", body)
    return send


def reflect_sender(base, path="/"):
    return lambda p: get(base, f"{path}?name=" + urllib.parse.quote(p))


def ping_sender(base):
    return lambda p: post(base, "/ping", {"host": p})


# --- oracles: (payload, response) -> (confirmed, evidence) ---------------------
# Each checks a security-relevant EFFECT, never the payload echoed back.
def sqli_oracle(payload, resp):
    """Confirmed iff the admin canary leaked even though the password was wrong."""
    hit = CANARY in resp
    return hit, (f"canary {CANARY} leaked" if hit else "")


SCRIPT_TAG = re.compile(r"<script[\s>]", re.I)


def xss_oracle(payload, resp):
    """Confirmed iff an unescaped, executable <script> element is in the HTML.
    Case-insensitive because HTML tag names are (<SCRIPT> runs too)."""
    m = SCRIPT_TAG.search(resp)
    hit = bool(m) and "&lt;" not in resp
    return hit, (f"live {m.group(0)!r} tag in response" if hit else "")


def cmdi_oracle(payload, resp):
    """Confirmed iff a shell metacharacter survived into the command line AND the
    smuggled command text is in `would_run` (it reached the command context)."""
    d = json.loads(resp)
    hit = d.get("injection_detected") is True and "whoami" in d.get("would_run", "")
    return hit, (f"would_run={d.get('would_run')!r}" if hit else "")


def write_csv(name, rows):
    RESULTS.mkdir(exist_ok=True)
    path = RESULTS / name
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"  -> wrote {path.relative_to(HERE)} ({len(rows)} rows)")
