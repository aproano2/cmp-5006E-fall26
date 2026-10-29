"""Instructor self-check for the Duel 2 fixtures.

Confirms two things by running the actual vuln-web app in-process:
  1. Every ground-truth finding is a REAL, oracle-confirmed vulnerability.
  2. Every benign_traffic entry is genuinely benign (triggers no security effect)
     — so a WAF that blocks one is a true false positive, not a real catch.

    python verify_fixtures.py        # exits 0 if fixtures are sound

This does NOT test any student's WAF — it validates the fixtures themselves, so the
duel is graded against honest reference data.
"""
import json
import sys
import threading
import time
import urllib.request
import urllib.parse
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "labs" / "vuln-web" / "app"))
import vulnweb_app as app          # noqa: E402

HERE = Path(__file__).parent
PORT = 8973
BASE = f"http://127.0.0.1:{PORT}"


def start():
    app.DB = app.make_db()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    return srv


def post(path, obj):
    r = urllib.request.Request(BASE + path, data=json.dumps(obj).encode(),
                               headers={"Content-Type": "application/json"})
    return urllib.request.urlopen(r, timeout=5).read().decode()


def get(path):
    return urllib.request.urlopen(BASE + path, timeout=5).read().decode()


CANARY = app.CANARY_SECRET


def confirm_ground_truth():
    """Land each ground-truth vuln with a real payload + oracle."""
    results = {}
    # sqli @ do_login — canary leak proves it
    r = post("/login", {"user": "admin' OR '1'='1", "pw": "x"})
    results["sqli/do_login"] = CANARY in r
    # xss @ do_reflect — unescaped <script> reflected
    r = get("/?name=" + urllib.parse.quote("<script>alert(1)</script>"))
    results["xss/do_reflect"] = "<script>" in r and "&lt;script&gt;" not in r
    # cmdi @ do_ping — shell metachar reaches the command
    r = json.loads(post("/ping", {"host": "127.0.0.1; whoami"}))
    results["cmdi/do_ping"] = r.get("injection_detected") is True
    # true negative @ do_reflect_safe — must NOT be exploitable
    r = get("/safe?name=" + urllib.parse.quote("<script>alert(1)</script>"))
    results["safe/do_reflect_safe (must be clean)"] = "<script>" not in r
    return results


def confirm_benign():
    """Every benign entry must trigger NO security effect on its sink."""
    corpus = json.loads((HERE / "benign_traffic.json").read_text())
    problems = []
    # login usernames: none should leak the canary
    for u in corpus["login_username"]:
        if CANARY in post("/login", {"user": u, "pw": "x"}):
            problems.append(f"login_username leaked canary: {u!r}")
    # search/name: none should produce an unescaped <script> via the vuln endpoint
    for s in corpus["search_or_name"]:
        body = get("/?name=" + urllib.parse.quote(s))
        if "<script>" in body and "&lt;" not in body:
            problems.append(f"search_or_name produced live script: {s!r}")
    # ping hosts: none should be flagged as command injection
    for h in corpus["ping_host"]:
        if json.loads(post("/ping", {"host": h})).get("injection_detected"):
            problems.append(f"ping_host flagged as injection: {h!r}")
    return problems


def main():
    srv = start()
    try:
        gt = confirm_ground_truth()
        print("Ground-truth findings (each must be TRUE, safe endpoint clean):")
        for k, v in gt.items():
            print(f"  [{'OK ' if v else 'FAIL'}] {k}")
        benign_problems = confirm_benign()
        print("\nBenign corpus (must be empty):")
        if benign_problems:
            for p in benign_problems:
                print(f"  [FAIL] {p}")
        else:
            print("  [OK ] all benign entries trigger no security effect")
        ok = all(gt.values()) and not benign_problems
        print("\n" + ("FIXTURES SOUND." if ok else "FIXTURE PROBLEM — fix before use."))
        return 0 if ok else 1
    finally:
        srv.shutdown()


if __name__ == "__main__":
    sys.exit(main())
