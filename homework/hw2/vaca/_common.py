"""Shared harness for Homework 2 (Web Attack & Defend) — Benjamín Vaca.

One job: make the course's `vuln-web` app importable and runnable in-process on
127.0.0.1, and expose the `seclab` package, from any of the submission's
subfolders (attack/ defend/ duel/). Everything local — see
`../../../resources/ethics-and-scope.md`.

`vuln-web` is the week-6 target; all of Homework 2's provided fixtures
(`duel-2-web/ground_truth.json`, `benign_traffic.json`, `verify_fixtures.py`) and
the week-7 WAF studio are keyed to its three sinks `do_login` / `do_reflect` /
`do_ping`, so it is the single target for every part of this submission.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

# --- locate the repo root (the dir that contains `seclab/`) ------------------
ROOT = Path(__file__).resolve()
while ROOT != ROOT.parent and not (ROOT / "seclab").is_dir():
    ROOT = ROOT.parent

APP_DIR = ROOT / "labs" / "vuln-web" / "app"
HW2_DIR = ROOT / "homework" / "hw2"
DUEL_FIXTURES = HW2_DIR / "duel-2-web"

for p in (str(ROOT), str(APP_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import vulnweb_app as vulnweb  # noqa: E402  (the target under test)

# The exact source a static scanner / LLM reads in the Part C duel — the same
# file we attack dynamically, so every finding is checkable by eye.
SOURCE_FILE = APP_DIR / "vulnweb_app.py"
SOURCE = SOURCE_FILE.read_text()

_srv = None
_base = None
_lock = threading.Lock()


def start_vulnweb() -> str:
    """Start vuln-web on a free loopback port in a daemon thread (idempotent).

    A fresh in-memory DB is created so the SQLi canary row is deterministic.
    Returns the base URL (always http://127.0.0.1:<port>).
    """
    global _srv, _base
    with _lock:
        if _srv is None:
            vulnweb.DB = vulnweb.make_db()
            _srv = ThreadingHTTPServer(("127.0.0.1", 0), vulnweb.Handler)
            port = _srv.server_address[1]
            threading.Thread(target=_srv.serve_forever, daemon=True).start()
            time.sleep(0.15)
            _base = f"http://127.0.0.1:{port}"
    return _base


def canary() -> str:
    """The admin secret a SOUND SQLi oracle looks for (a leak, not a reflection)."""
    return vulnweb.CANARY_SECRET


# --- raw senders: payload -> response body -----------------------------------
def login_send(user: str, pw: str = "x") -> str:
    base = start_vulnweb()
    req = urllib.request.Request(
        base + "/login", data=json.dumps({"user": user, "pw": pw}).encode(),
        headers={"Content-Type": "application/json"})
    return urllib.request.urlopen(req, timeout=5).read().decode()


def reflect_send(name: str, safe: bool = False) -> str:
    base = start_vulnweb()
    path = "/safe" if safe else "/"
    return urllib.request.urlopen(
        base + path + "?name=" + urllib.parse.quote(name), timeout=5).read().decode()


def ping_send(host: str) -> str:
    base = start_vulnweb()
    req = urllib.request.Request(
        base + "/ping", data=json.dumps({"host": host}).encode(),
        headers={"Content-Type": "application/json"})
    return urllib.request.urlopen(req, timeout=5).read().decode()
