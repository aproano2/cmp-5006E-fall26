"""Part B: measure SQLi WAF, confirmed bypasses, false positives and fixes."""

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[2]  

sys.path.insert(0, str(ROOT))      
sys.path.insert(0, str(REPO_ROOT))  

from attack.run import CMDI, SQLI, XSS, cmdi_oracle, sqli_oracle, xss_oracle  # noqa: E402
from lab import get, post, safe_request, serve  # noqa: E402
from defend.waf import waf_block  # noqa: E402
from seclab.attack import Payload, run_payloads  # noqa: E402

# Same intent as SQLI: get the admin canary with password "x".
BYPASSES = ["admin'--", "admin'/*", "admin' AND 1=1--"]


def main():
    rows = []
    with serve(medium=True, waf=True) as base:
        for label, payload in [("part_a_sqli", SQLI)] + [
            (f"bypass_{i}", p) for i, p in enumerate(BYPASSES, 1)
        ]:
            finding = run_payloads([Payload(payload, "admin canary leak", "sqli")],
                                   send=lambda text: safe_request(post, base, "/login", "user", text),
                                   oracle=sqli_oracle, trials=3)[0]
            status, _ = safe_request(post, base, "/login", "user", payload)
            rows.append({"stage": "waf", "case": label, "payload": payload,
                         "blocked_by_waf": bool(waf_block(payload)), "http_status": status,
                         "oracle_successes": finding.successes, "trials": finding.trials})
            print(f"{label}: WAF {waf_block(payload)!r}; HTTP {status}; oracle {finding.successes}/3")
            assert finding.successes == (0 if label == "part_a_sqli" else 3)
    benign = json.loads((REPO_ROOT / "homework" / "hw2" / "duel-2-web" / "benign_traffic.json").read_text(encoding="utf-8"))
    benign_rows = []
    for field in ("login_username", "search_or_name", "ping_host"):
        for value in benign[field]:
            # The SQLi WAF is deployed only on /login user, so other endpoints pass.
            rule = waf_block(value) if field == "login_username" else None
            benign_rows.append({"field": field, "input": value,
                                "blocked": bool(rule), "rule": rule or ""})
    blocked = sum(row["blocked"] for row in benign_rows)
    login_rows = [row for row in benign_rows if row["field"] == "login_username"]
    login_blocked = sum(row["blocked"] for row in login_rows)
    print(f"False positives: {login_blocked}/{len(login_rows)} login usernames; "
          f"{blocked}/{len(benign_rows)} all supplied benign requests")
    assert login_blocked >= 1

    # Fixes run without either negative filter; failures are structural.
    with serve(medium=False, waf=False, fixed=True) as base:
        for label, payload in [("part_a_sqli", SQLI)] + [
            (f"bypass_{i}", p) for i, p in enumerate(BYPASSES, 1)
        ]:
            finding = run_payloads([Payload(payload, "admin canary leak", "sqli")],
                                   send=lambda text: safe_request(post, base, "/login", "user", text),
                                   oracle=sqli_oracle, trials=3)[0]
            status, _ = safe_request(post, base, "/login", "user", payload)
            rows.append({"stage": "fixed", "case": label, "payload": payload,
                         "blocked_by_waf": False, "http_status": status,
                         "oracle_successes": finding.successes, "trials": finding.trials})
            assert finding.successes == 0
        for label, payload, sender, oracle in [
            ("part_a_xss", XSS, lambda text: safe_request(get, base, "/", text), xss_oracle),
            ("part_a_cmdi", CMDI,
             lambda text: safe_request(post, base, "/ping", "host", text), cmdi_oracle),
        ]:
            finding = run_payloads([Payload(payload, "fixed sink", label)],
                                   send=sender, oracle=oracle, trials=3)[0]
            rows.append({"stage": "fixed", "case": label, "payload": payload,
                         "blocked_by_waf": False, "http_status": 200,
                         "oracle_successes": finding.successes, "trials": finding.trials})
            assert finding.successes == 0
        # The common post() helper intentionally supplies pw=x, so call the
        # positive function directly for a valid-credential control.
        from defend.fixed import fixed_login
        assert json.loads(fixed_login("admin", "s3cr3t"))["ok"] is True
        assert json.loads(fixed_login("admin", "x"))["ok"] is False

    for name, data in [("results.csv", rows), ("benign_results.csv", benign_rows)]:
        out = ROOT / "defend" / name
        with out.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=list(data[0]))
            writer.writeheader()
            writer.writerows(data)
        print(f"Saved {out}")


if __name__ == "__main__":
    main()
