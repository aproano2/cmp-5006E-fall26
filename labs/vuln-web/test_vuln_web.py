"""Tests for the vuln-web app, via seclab.attack oracles.

    pytest labs/vuln-web/test_app.py -q

Pins the INTENDED behaviour: the three sinks are exploitable, the /safe endpoint
is a true negative, and benign input never confirms. A lab target that stops being
exploitable teaches nothing, so these fail loudly if an edit breaks the bugs.
Runs in-process; no Docker needed.
"""

import sys
import threading
import time
import json
import urllib.request
import urllib.parse
from pathlib import Path
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, str(Path(__file__).parent / "app"))
import vulnweb_app as vulnweb          # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from seclab.attack import Payload, run_payloads, contains_oracle    # noqa: E402

PORT = 8961
BASE = f"http://127.0.0.1:{PORT}"


@pytest.fixture(scope="module", autouse=True)
def server():
    # Fresh DB per test run so the canary row is deterministic.
    vulnweb.DB = vulnweb.make_db()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), vulnweb.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    yield
    srv.shutdown()


def post(path, obj):
    req = urllib.request.Request(BASE + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.read().decode()


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=5) as r:
        return r.read().decode()


def test_sqli_auth_bypass_leaks_canary():
    findings = run_payloads(
        [Payload("admin' OR '1'='1", family="sqli"),
         Payload("admin'--", family="sqli")],
        send=lambda p: post("/login", {"user": p, "pw": "x"}),
        oracle=contains_oracle("FLAG-sqli-"))
    assert all(f.confirmed for f in findings), "SQLi sink must be exploitable"


def test_benign_login_does_not_leak():
    findings = run_payloads(
        [Payload("admin", family="benign")],
        send=lambda p: post("/login", {"user": p, "pw": "wrong"}),
        oracle=contains_oracle("FLAG-sqli-"))
    assert not findings[0].confirmed          # wrong password -> no leak


def test_reflected_xss_unescaped_on_vuln_endpoint():
    body = get("/?name=" + urllib.parse.quote("<script>alert(1)</script>"))
    assert "<script>" in body and "&lt;script&gt;" not in body


def test_safe_endpoint_encodes_xss_true_negative():
    body = get("/safe?name=" + urllib.parse.quote("<script>alert(1)</script>"))
    assert "<script>" not in body and "&lt;script&gt;" in body


def test_command_injection_detected():
    r = json.loads(post("/ping", {"host": "127.0.0.1; whoami"}))
    assert r["injection_detected"] is True
    benign = json.loads(post("/ping", {"host": "127.0.0.1"}))
    assert benign["injection_detected"] is False


def test_source_matches_ground_truth_the_scanner_target():
    """The week-6 duel scans app.py against a hand-built ground-truth set. Pin the
    three sinks by name so a refactor that renames a handler also updates the
    lesson's ground truth (or fails here first)."""
    src = (Path(__file__).parent / "app" / "vulnweb_app.py").read_text()
    for fn in ("do_login", "do_reflect", "do_ping"):
        assert f"def {fn}" in src
    assert "def do_reflect_safe" in src        # the true-negative endpoint
