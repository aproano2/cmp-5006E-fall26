"""Week 7 studio — REFERENCE SOLUTION (instructor-only).

A filled-in copy of ``starter.py``: identical function names and signatures, so
the *provided* ``test_waf.py`` passes when this module is imported in place of
``starter``. Verify with ``studios/_verify_solutions.py``.

The week's one lesson, measured: a WAF blocklist (negative security) loses on
BOTH blades at once — it is bypassable (axis 4: ``measure_bypasses`` = 3/4) AND
noisy (axis 5: ``measure_false_positives`` flags legit traffic). There is no rule
setting that is both complete and quiet, because "bad" is open-ended and overlaps
benign English. Parameterization (positive security) gives 0/N injections for ANY
input — not "blocked by a rule" but STRUCTURALLY unable to inject. That is the
guarantee (axis 2) a blocklist could never state. ``bypass_leaks_canary`` anchors
axis 4 on the real vuln-web app with a sound oracle (the canary token).

DO NOT ship to students — excluded via ``studios/.gitignore``. The teaching
walkthrough is ``solution.ipynb`` (imports this file rather than re-pasting it).
"""
from waf import (
    waf_block, parameterized_login, KNOWN_ATTACKS, BYPASSES, anomaly,
    load_benign, start_vulnweb, send_login, vulnweb_canary,
)


# ---- Task 1: coverage on KNOWN attacks (the trap) ---------------------------

def measure_coverage(payloads: list[str]) -> tuple[int, int]:
    """Run each payload through ``waf_block``; return ``(blocked, total)``.

    On ``KNOWN_ATTACKS`` this is 4/4 — which looks like security but only measures
    the payloads you already thought of.
    """
    blocked = sum(1 for p in payloads if waf_block(p) is not None)
    return blocked, len(payloads)


# ---- Task 2: bypass it, axis 4 ----------------------------------------------

def measure_bypasses(bypasses: list[tuple[str, str]]) -> tuple[int, int]:
    """Return ``(through, total)`` where ``through`` counts payloads the WAF
    FAILED to block. On ``BYPASSES`` this is 3/4 — each is a five-minute
    same-intent mutation, and the blocklist can never be complete."""
    through = sum(1 for payload, _why in bypasses if waf_block(payload) is None)
    return through, len(bypasses)


# ---- Task 3: false positives, axis 5 ----------------------------------------

def measure_false_positives(benign: list[str]) -> list[tuple[str, str]]:
    """Run each LEGITIMATE input through the WAF; return ``(input, rule_name)``
    for the ones it wrongly blocks. Each entry is a real user turned away — and a
    WAF that blocks users gets disabled, at which point its coverage is zero."""
    out: list[tuple[str, str]] = []
    for inp in benign:
        rule = waf_block(inp)
        if rule is not None:
            out.append((inp, rule))
    return out


# ---- Task 4: fix it properly — the positive-model guarantee -----------------

def count_injection_successes(payloads: list[str]) -> tuple[int, int]:
    """Send every payload as the *username* to ``parameterized_login`` (with a
    wrong password); return ``(succeeded, total)``. The answer is 0/N: input is
    compared as a literal value, never concatenated into a query, so no input can
    alter the query's meaning — the guarantee (axis 2) the WAF could never state.
    """
    succeeded = sum(1 for p in payloads if parameterized_login(p, "wrong") is True)
    return succeeded, len(payloads)


# ---- Task 5: confirm the bypass on the REAL app (seclab oracle) -------------

def bypass_leaks_canary(base_url: str) -> bool:
    """Put the WAF in front of the real ``vuln-web`` /login sink: a payload the
    WAF PASSES reaches the vulnerable query and leaks the admin canary.

    Sound oracle: the canary token ``vulnweb_canary()`` appears in the response
    (not the payload echoed back). Return True as soon as one WAF-passed bypass
    leaks the canary.
    """
    canary = vulnweb_canary()
    for payload, _why in BYPASSES:
        if waf_block(payload) is not None:
            continue                       # the WAF stopped it — never sent
        response = send_login(base_url, payload)
        if canary in response:             # oracle: a security-relevant EFFECT
            return True
    return False


if __name__ == "__main__":
    for name, fn, arg in [
        ("coverage (known attacks)", measure_coverage, KNOWN_ATTACKS),
        ("bypasses through (axis 4)", measure_bypasses, BYPASSES),
        ("injections vs parameterization", count_injection_successes,
         KNOWN_ATTACKS + [p for p, _ in BYPASSES]),
    ]:
        print(f"  {name:<34} {fn(arg)}")
    fps = measure_false_positives(load_benign())
    print(f"  false positives (axis 5)           {len(fps)} legit inputs blocked")
    for inp, rule in fps:
        print(f"      [{rule}] {inp!r}")

    flagged = [p for p, _ in BYPASSES if not waf_block(p) and anomaly(p)]
    print(f"  bypassed-but-anomalous (for review) {len(flagged)} — a sensor, not a wall")

    base, shutdown = start_vulnweb()
    try:
        print("  bypass leaks canary on real app     ", bypass_leaks_canary(base))
    finally:
        shutdown()
