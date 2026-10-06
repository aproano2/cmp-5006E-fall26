"""Provided tests for the week-6 studio.

    python3 test_studio.py

Runs LAPTOP-ONLY: the vuln-web app is imported and served in-process on 127.0.0.1
(no Docker), and the LLM arm is scored from a canned review string (no Ollama).
Passes ⇒ your three findings are oracle-confirmed and your duel is wired correctly;
you are ready for the Control Scorecard (Task 3).

The GUARANTEE test — ``test_scanner_misses_sqli_and_neither_finds_bac`` — is the
point of the week. It watches the classical scanner's completeness FAIL (its
line-oriented rule misses a 2-line SQL query) and shows that NEITHER arm cleanly
finds Broken Access Control (the app has none; the LLM only guesses). That is
OWASP-2021 #1 arriving as data: the most important vulnerability class is the one
automated tools are worst at, because it is about intent, not syntax.
"""

import sys

# webharness starts the in-process server on first get/post; importing it is safe.
from webharness import regex_scanner, RAW_LLM_REVIEW, SOURCE, load_ground_truth
from seclab.scan import compare_scanners
import starter as s


def _by_family(findings, family):
    return [f for f in findings if f.payload.family == family]


def test_sqli_confirmed_by_canary_oracle():
    # A confirmed SQLi is data you EXTRACTED (the canary), not "the page changed".
    findings = s.confirm_sqli()
    attacks = [f for f in findings if f.payload.family == "sqli"]
    assert attacks, "confirm_sqli must include sqli-family payloads"
    assert all(f.confirmed for f in attacks), (
        "every SQLi payload must leak the FLAG-sqli- canary (oracle-confirmed)")
    print(f"  ok  SQLi: {len(attacks)}/{len(attacks)} payloads leaked the canary "
          "(confirmed by an extraction oracle, not a vibe)")


def test_benign_login_does_not_confirm():
    # Oracle discipline (axis 3): a real user with the wrong password must NOT
    # confirm. If it does, the oracle is matching something other than a leak.
    benign = _by_family(s.confirm_sqli(), "benign")
    assert benign, "include a benign control (family='benign') in confirm_sqli"
    assert not any(f.confirmed for f in benign), (
        "benign login confirmed a 'breach' — your oracle produces false positives")
    print("  ok  benign login did NOT confirm — the oracle is not crying wolf")


def test_reflected_but_escaped_is_not_a_confirmed_xss():
    # THE oracle-discipline test. Same payload, two endpoints: the vulnerable / must
    # confirm (unescaped <script> survives) and the fixed /safe must NOT — an
    # html.escape'd reflection is reflection, not XSS. A reflected string alone is
    # never a confirmed finding.
    vuln_f, safe_f = s.confirm_xss()
    assert vuln_f.confirmed, "reflected XSS on / must confirm (unescaped <script>)"
    assert not safe_f.confirmed, (
        "/safe html.escape()s the input — a reflected-but-encoded string is NOT a "
        "confirmed XSS. If this 'confirms', your oracle checks reflection, not "
        "execution.")
    print("  ok  XSS confirmed on / and correctly REJECTED on /safe — reflection "
          "is not execution (axis 3)")


def test_cmdi_confirmed_and_benign_control_clean():
    findings = s.confirm_cmdi()
    attacks = _by_family(findings, "cmdi")
    benign = _by_family(findings, "benign")
    assert attacks and all(f.confirmed for f in attacks), (
        "cmdi payloads with a shell metacharacter must confirm")
    assert benign and not any(f.confirmed for f in benign), (
        "a plain host (no metacharacters) must NOT confirm")
    print("  ok  cmdi confirmed on metacharacter payloads, clean on the benign host")


def test_llm_arm_parses_into_scanresults():
    # The LLM arm must become structured ScanResults so it is scored like the
    # scanner. The canned review names 5 findings (3 real sinks + 2 suspicious).
    llm = s.parse_llm_review(RAW_LLM_REVIEW)
    keys = {r.key() for r in llm}
    for real in [("sqli", "do_login"), ("xss", "do_reflect"), ("cmdi", "do_ping")]:
        assert real in keys, f"LLM arm should have parsed {real}"
    assert ("broken-access-control", "do_login") in keys, (
        "parse the model FAITHFULLY — do not silently drop its BAC claim")
    print(f"  ok  parsed {len(llm)} LLM findings into ScanResults "
          "(faithfully, including the dubious ones)")


def test_scanner_misses_sqli_and_neither_finds_bac():
    """GUARANTEE TEST — watch the automation fail exactly where OWASP #1 lives.

    (a) The classical scanner's completeness FAILS: its line-oriented SQLi rule
        misses the 2-line query, so recall < 100% and sqli is in its 'missed' set.
    (b) NEITHER arm cleanly finds Broken Access Control: the scanner has no rule
        for it, and the LLM's BAC 'finding' is a FALSE POSITIVE (the app has no
        auth code). Access control needs app context a pattern/LLM guess can't
        supply — which is why #1 is #1.
    """
    gt = load_ground_truth()
    cmp = compare_scanners(
        {"regex-scanner": regex_scanner(SOURCE),
         "llm": s.parse_llm_review(RAW_LLM_REVIEW)},
        gt)

    scanner = cmp["regex-scanner"]
    assert scanner["recall"] < 1.0, (
        "the scanner was expected to MISS the SQLi (2-line query vs 1-line rule)")
    assert ("sqli", "do_login") in scanner["missed"], (
        "the specific miss is the SQLi sink — that is the lesson")

    llm = cmp["llm"]
    bac = ("broken-access-control", "do_login")
    assert bac not in gt, "sanity: BAC is NOT in the honest ground truth"
    assert bac in llm["false_positives"], (
        "the LLM's BAC claim must score as a false positive (hallucinated bug)")
    # And the scanner never even reported BAC, so neither arm found it truthfully.
    scanner_keys = {r.key() for r in regex_scanner(SOURCE)}
    assert bac not in scanner_keys, "sanity: the scanner has no BAC rule"
    print("  ok  scanner MISSED the SQLi and NEITHER arm found Broken Access "
          "Control — automation is worst at OWASP-2021 #1 (intent, not syntax)")


TESTS = [
    test_sqli_confirmed_by_canary_oracle,
    test_benign_login_does_not_confirm,
    test_reflected_but_escaped_is_not_a_confirmed_xss,
    test_cmdi_confirmed_and_benign_control_clean,
    test_llm_arm_parses_into_scanresults,
    test_scanner_misses_sqli_and_neither_finds_bac,
]


def main():
    failed = 0
    for t in TESTS:
        try:
            t()
        except NotImplementedError:
            print(f"  --  {t.__name__}: TODO not implemented yet")
            failed += 1
        except AssertionError as e:
            print(f"  FAIL {t.__name__}: {e}")
            failed += 1
    if failed:
        print(f"\n{failed}/{len(TESTS)} failed")
        sys.exit(1)
    print(f"\nall {len(TESTS)} tests pass")


if __name__ == "__main__":
    main()
