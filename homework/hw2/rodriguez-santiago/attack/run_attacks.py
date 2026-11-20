"""Run the three Homework 2 attacks against the local vuln-web target.

The course target has no security-level switch, so this script models a small
"Medium" pre-filter before sending the bypass payload to the real local app.
Every finding is confirmed with a security-effect oracle from seclab.attack.
"""

from __future__ import annotations

import csv
import json
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
APP_DIR = ROOT / "labs" / "vuln-web" / "app"
for path in (ROOT, APP_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import vulnweb_app as app  # noqa: E402
from seclab.attack import Payload, contains_oracle, run_payloads  # noqa: E402

HERE = Path(__file__).resolve().parent


ATTACK_CASES = [
    {
        "vulnerability": "SQL injection",
        "family": "sqli",
        "owasp": "A03:2021 Injection",
        "baseline": "admin' OR 1=1--",
        "bypass": "admin' oR 1=1--",
        "medium_rule": "case-sensitive ' OR ' check",
        "bypass_method": "mixed-case SQL keyword",
        "oracle": "admin canary appears in the response",
    },
    {
        "vulnerability": "Reflected XSS",
        "family": "xss",
        "owasp": "A03:2021 Injection",
        "baseline": "<script>alert('HW2-XSS')</script>",
        "bypass": "<ScRiPt>alert('HW2-XSS')</ScRiPt>",
        "medium_rule": "case-sensitive <script> check",
        "bypass_method": "mixed-case HTML tag",
        "oracle": "script element survives without HTML encoding",
    },
    {
        "vulnerability": "Command injection",
        "family": "cmdi",
        "owasp": "A03:2021 Injection",
        "baseline": "127.0.0.1; whoami",
        "bypass": "127.0.0.1 && whoami",
        "medium_rule": "semicolon-only shell check",
        "bypass_method": "alternate shell operator (&&)",
        "oracle": "target reports that a shell metacharacter reached the command",
    },
]


def medium_block(family: str, payload: str) -> str | None:
    """Return the modeled Medium rule that blocks a payload, or None."""
    if family == "sqli" and " OR " in payload:
        return "case-sensitive OR"
    if family == "xss" and "<script>" in payload:
        return "case-sensitive script tag"
    if family == "cmdi" and ";" in payload:
        return "semicolon"
    return None


def start_target():
    """Start a fresh vuln-web instance on localhost and return URL + shutdown."""
    app.DB = app.make_db()
    server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)
    return f"http://127.0.0.1:{server.server_address[1]}", server.shutdown


def post(base_url: str, path: str, body: dict) -> str:
    request = urllib.request.Request(
        base_url + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    return urllib.request.urlopen(request, timeout=5).read().decode()


def login_send(base_url: str, payload: str) -> str:
    return post(base_url, "/login", {"user": payload, "pw": "wrong"})


def reflect_send(base_url: str, payload: str) -> str:
    url = base_url + "/?name=" + urllib.parse.quote(payload)
    return urllib.request.urlopen(url, timeout=5).read().decode()


def ping_send(base_url: str, payload: str) -> str:
    return post(base_url, "/ping", {"host": payload})


def xss_oracle(payload: Payload, response: str) -> tuple[bool, str]:
    script_tag = re.search(r"<\s*script\b", response, flags=re.IGNORECASE)
    confirmed = payload.text in response and script_tag is not None
    evidence = "unescaped script element returned in HTML" if confirmed else ""
    return confirmed, evidence


def cmdi_oracle(payload: Payload, response: str) -> tuple[bool, str]:
    data = json.loads(response)
    confirmed = data.get("injection_detected") is True
    evidence = data.get("would_run", "") if confirmed else ""
    return confirmed, evidence


def run_attacks(write_csv: bool = True) -> list[dict]:
    base_url, shutdown = start_target()
    rows = []
    try:
        for case in ATTACK_CASES:
            baseline_block = medium_block(case["family"], case["baseline"])
            bypass_block = medium_block(case["family"], case["bypass"])
            if baseline_block is None or bypass_block is not None:
                raise AssertionError("Medium-filter demonstration is not valid")

            payload = Payload(
                case["bypass"],
                intent=case["bypass_method"],
                family=case["family"],
            )
            if case["family"] == "sqli":
                send = lambda text: login_send(base_url, text)
                oracle = contains_oracle(app.CANARY_SECRET)
            elif case["family"] == "xss":
                send = lambda text: reflect_send(base_url, text)
                oracle = xss_oracle
            else:
                send = lambda text: ping_send(base_url, text)
                oracle = cmdi_oracle

            finding = run_payloads(
                [payload], send=send, oracle=oracle, trials=2
            )[0]
            rows.append({
                **case,
                "baseline_blocked": True,
                "bypass_passed_filter": bypass_block is None,
                "confirmed": finding.confirmed,
                "successes": finding.successes,
                "trials": finding.trials,
                "evidence": finding.evidence,
            })
    finally:
        shutdown()

    if write_csv:
        fields = list(rows[0].keys())
        with (HERE / "attack_results.csv").open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
    return rows


def main() -> int:
    rows = run_attacks()
    print("Part A - oracle-confirmed attacks")
    for row in rows:
        status = "CONFIRMED" if row["confirmed"] else "FAILED"
        print(
            f"  {row['family']:<5} {status:<9} "
            f"{row['successes']}/{row['trials']}  {row['bypass_method']}"
        )
    return 0 if all(row["confirmed"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
