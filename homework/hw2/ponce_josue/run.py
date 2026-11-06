"""Run Parts A and B over local HTTP and save responses and verifiable results."""
import csv
import hashlib
import json
import platform
import sys
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener
from http.server import ThreadingHTTPServer

from target import ROOT, app, handler
from defend.controls import waf_reason

sys.path.insert(0, str(ROOT))
from seclab.attack import Payload, run_payloads

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "benign_traffic.json"
ATTACKS = [
    Payload("admin' or 1=1--", "canary leak with wrong password", "sqli", "lowercase or"),
    Payload("<ScRiPt>alert(1)</ScRiPt>", "unescaped script", "xss", "mixed case tags"),
    Payload("127.0.0.1 | printf CMDI_OK", "shell pipeline in simulated command", "cmdi", "pipe instead of semicolon"),
]
CONTROLS = [
    Payload("admin' OR 1=1--", family="sqli"),
    Payload("<script>alert(1)</script>", family="xss"),
    Payload("127.0.0.1; printf CMDI_OK", family="cmdi"),
]
BYPASSES = [
    Payload("admin'--", "canary leak with wrong password", "sqli", "comment out password check"),
    Payload("admin' and pw glob '*'--", "canary leak with wrong password", "sqli", "GLOB predicate, no OR keyword"),
    Payload("admin' and 2 between 1 and 3--", "canary leak with wrong password", "sqli", "BETWEEN predicate, no OR keyword"),
]
OPENER = build_opener(ProxyHandler({}))


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.found = False

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.found = True


def oracle(payload, response):
    status, body = response
    if status != 200:
        return False, ""
    if payload.family == "sqli":
        obj = json.loads(body)
        # Do not look for the canary in error messages or the reflected query.
        ok = obj.get("ok") is True and ["admin", app.CANARY_SECRET] in obj.get("rows", [])
        return ok, "admin canary returned in rows despite pw=x" if ok else ""
    if payload.family == "xss":
        parser = Scripts()
        parser.feed(body)
        ok = parser.found and "alert(1)" in body
        return ok, "HTML parser finds unescaped script element (no browser execution tested)" if ok else ""
    obj = json.loads(body)
    ok = obj.get("injection_detected") is True and any(
        marker in obj.get("would_run", "")
        for marker in ("| printf CMDI_OK", "; printf CMDI_OK")
    )
    return ok, "injected command reaches simulated shell command; no OS command executed" if ok else ""


def request(base, family, text=None, *, user=None, pw="x"):
    if family == "xss":
        req = Request(base + "/?" + urlencode({"name": text}))
    else:
        path, data = (("/login", {"user": text if user is None else user, "pw": pw})
                      if family == "sqli" else ("/ping", {"host": text}))
        req = Request(base + path, data=json.dumps(data).encode(),
                      headers={"Content-Type": "application/json"})
    try:
        with OPENER.open(req, timeout=5) as response:
            return response.status, response.read().decode()
    except HTTPError as response:
        return response.code, response.read().decode()


@contextmanager
def target(mode):
    app.DB = app.make_db()
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(mode))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        app.DB.close()


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main():
    attack_rows, responses, benign_rows, functional = [], [], [], []
    for mode in ("original", "waf", "positive"):
        with target(mode) as base:
            sets = [("A_control", CONTROLS), ("A", ATTACKS), ("B1_bypass", BYPASSES)]
            for group, payloads in sets:
                for payload in payloads:
                    def send(text):
                        response = request(base, payload.family, text)
                        responses.append({"mode": mode, "group": group,
                                          "family": payload.family, "payload": text,
                                          "status": response[0], "body": response[1]})
                        return response
                    finding = run_payloads([payload], send=send, oracle=oracle, trials=3)[0]
                    if finding.error:
                        raise RuntimeError(finding.error)
                    expected = mode != "positive"
                    if mode == "waf" and group in ("A", "A_control") and payload.family == "sqli":
                        expected = False
                    if finding.successes != (3 if expected else 0):
                        raise AssertionError((mode, group, payload, finding))
                    attack_rows.append({"mode": mode, "group": group, "family": payload.family,
                                        "payload": payload.text, "note": payload.note,
                                        "trials": finding.trials, "successes": finding.successes,
                                        "confirmed": finding.confirmed, "evidence": finding.evidence})
            # Check valid and invalid logins, including injection in the password field.
            for user, pw, expected in (("admin", "s3cr3t", True), ("alice", "password", True),
                                       ("admin", "wrong", False)):
                status, body = request(base, "sqli", user=user, pw=pw)
                assert status == 200 and json.loads(body)["ok"] is expected
                functional.append({"mode": mode, "case": f"login {user} expected={expected}", "passed": True})
            if mode == "positive":
                for payload in [p for p in CONTROLS + ATTACKS + BYPASSES if p.family == "sqli"]:
                    status, body = request(base, "sqli", user="admin", pw=payload.text)
                    assert status == 200 and json.loads(body)["ok"] is False
                assert request(base, "cmdi", "localhost")[0] == 200
                assert "Hello, Alice!" in request(base, "xss", "Alice")[1]
            corpus = json.loads(CORPUS.read_text())
            for field, values in corpus.items():
                if field.startswith("_"):
                    continue
                family = {"login_username": "sqli", "search_or_name": "xss", "ping_host": "cmdi"}[field]
                for value in values:
                    status, body = request(base, family, value)
                    assert status in (200, 403), (field, value, status)
                    assert not oracle(Payload(value, family=family), (status, body))[0]
                    benign_rows.append({"mode": mode, "field": field, "input": value,
                                        "status": status, "blocked": status == 403,
                                        "rule": waf_reason(value) if mode == "waf" and family == "sqli" else ""})
    for name in ("attack", "defend"):
        (HERE / name).mkdir(exist_ok=True)
    write_csv(HERE / "attack/results.csv", attack_rows)
    write_csv(HERE / "defend/benign_results.csv", benign_rows)
    write_csv(HERE / "defend/functional_results.csv", functional)
    (HERE / "attack/responses.json").write_text(json.dumps(responses, indent=2, ensure_ascii=False) + "\n")
    stats = {}
    for mode in ("original", "waf", "positive"):
        stats[mode] = {}
        for scope in ("login_username", "all"):
            rows = [r for r in benign_rows if r["mode"] == mode and (scope == "all" or r["field"] == scope)]
            blocked = sum(r["blocked"] for r in rows)
            stats[mode][scope] = {"blocked": blocked, "total": len(rows), "fp_rate": blocked / len(rows)}
    metadata = {"run_utc": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
                "original": "unmodified labs/vuln-web/app/vulnweb_app.py Handler", "false_positives": stats,
                "sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in (Path(app.__file__), CORPUS, HERE / "target.py", HERE / "defend/controls.py", HERE / "run.py")}}
    (HERE / "defend/summary.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps(stats, indent=2))
    print("PASS: A, WAF bypasses, positive fixes, benign corpus and login controls")


if __name__ == "__main__":
    main()
