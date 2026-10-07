"""Week 7 studio — starter (measure a blocklist, then beat it with a boundary).

Fill in the five functions below. Then run ``python3 test_waf.py``.
All provided tests must pass, INCLUDING the guarantee-fail test that watches the
WAF lose on BOTH blades at once — bypassed (axis 4) AND false-positive on legit
traffic (axis 5) — while parameterization gives 0/N injections, a guarantee that
holds for ANY input.

Nothing you write breaks SQLite or HTTP. The blocklist loses because it
enumerates *badness*; parameterization wins because it enumerates the good path
structurally. Defend at the boundary, not with a pattern list.

Every engine piece (``waf_block``, ``parameterized_login``, the attack/bypass
sets, the benign loader, the in-process ``vuln-web`` bridge) is GIVEN in
``waf.py`` — you only wire the measurements and confirm the guarantee.
"""
from waf import (
    waf_block, parameterized_login, KNOWN_ATTACKS, BYPASSES, anomaly,
    load_benign, start_vulnweb, send_login, vulnweb_canary,
)


# ---- Task 1: coverage on KNOWN attacks (the trap) ---------------------------

def measure_coverage(payloads: list[str]) -> tuple[int, int]:
    """Run each payload through ``waf_block``; return ``(blocked, total)``.

    On ``KNOWN_ATTACKS`` this is 4/4 — which *looks* like security but only
    measures the payloads you already thought of. Coverage on known attacks
    tells you nothing about what you didn't enumerate.
    """
    # TODO: count how many payloads waf_block() catches.
    raise NotImplementedError


# ---- Task 2: bypass it, axis 4 ----------------------------------------------

def measure_bypasses(bypasses: list[tuple[str, str]]) -> tuple[int, int]:
    """Each item is ``(payload, why)`` — a same-intent mutation. Return
    ``(through, total)`` where ``through`` counts payloads the WAF FAILED to
    block. On ``BYPASSES`` this is 3/4: every bypass is a five-minute mutation,
    and the blocklist can never be complete because 'bad' is open-ended.
    """
    # TODO: count how many (payload, _why) pairs waf_block() lets PASS.
    raise NotImplementedError


# ---- Task 3: false positives, axis 5 ----------------------------------------

def measure_false_positives(benign: list[str]) -> list[tuple[str, str]]:
    """Run each LEGITIMATE input through the WAF; return the list of
    ``(input, rule_name)`` for the ones it wrongly blocks. Every entry is a real
    user turned away — a support ticket, an analyst-hour, and eventually a WAF
    that gets disabled (at which point its coverage is zero).

    Use ``load_benign()`` for the corpus. At least one legit "drop table ..."
    phrase will trip the DROP TABLE rule — name it in your scorecard.
    """
    # TODO: return [(inp, rule) for each benign inp that waf_block() flags].
    raise NotImplementedError


# ---- Task 4: fix it properly — the positive-model guarantee -----------------

def count_injection_successes(payloads: list[str]) -> tuple[int, int]:
    """Send every payload as the *username* to ``parameterized_login`` (with a
    wrong password) and return ``(succeeded, total)`` — how many actually logged
    in. Because input is compared as a literal value (never concatenated into a
    query), the answer is 0/N: no injection can alter the query's meaning, for
    ANY input. That is the guarantee (axis 2) the WAF could never state.
    """
    # TODO: count payloads for which parameterized_login(p, "wrong") is True.
    raise NotImplementedError


# ---- Task 5: confirm the bypass on the REAL app (seclab oracle) -------------

def bypass_leaks_canary(base_url: str) -> bool:
    """Put the WAF in front of the real ``vuln-web`` /login sink and prove the
    axis-4 lesson end-to-end: a payload the WAF PASSES reaches the vulnerable
    query and leaks the admin canary.

    For each ``(payload, _why)`` in ``BYPASSES``:
      * if ``waf_block(payload)`` fires, the WAF stopped it — skip (never sent).
      * otherwise ``send_login(base_url, payload)`` and confirm with a SOUND
        oracle: the canary token ``vulnweb_canary()`` appears in the response
        (not the payload echoed back — that would only prove reflection).

    Return True as soon as one WAF-passed bypass leaks the canary. This is the
    same discipline as ``seclab.attack``: a finding is confirmed by an oracle
    checking a security-relevant EFFECT, reproducibly — not by "it looked right."
    """
    # TODO: for WAF-passed bypasses, send to /login and check for the canary.
    raise NotImplementedError


if __name__ == "__main__":
    for name, fn, arg in [
        ("coverage (known attacks)", measure_coverage, KNOWN_ATTACKS),
        ("bypasses through (axis 4)", measure_bypasses, BYPASSES),
        ("injections vs parameterization", count_injection_successes,
         KNOWN_ATTACKS + [p for p, _ in BYPASSES]),
    ]:
        try:
            print(f"  {name:<34} {fn(arg)}")
        except NotImplementedError:
            print(f"  {name:<34} not implemented yet")
    try:
        fps = measure_false_positives(load_benign())
        print(f"  false positives (axis 5)           {len(fps)} legit inputs blocked")
        for inp, rule in fps:
            print(f"      [{rule}] {inp!r}")
    except NotImplementedError:
        print("  false positives (axis 5)           not implemented yet")

    # Detection preview (Task 5): which bypasses would a behaviour rule still flag?
    flagged = [p for p, _ in BYPASSES if not waf_block(p) and anomaly(p)]
    print(f"  bypassed-but-anomalous (for review) {len(flagged)} — a sensor, not a wall")

    # Lab-anchored confirmation on the real vuln-web app, in-process.
    base, shutdown = start_vulnweb()
    try:
        print(f"  bypass leaks canary on real app     ", end="")
        try:
            print(bypass_leaks_canary(base))
        except NotImplementedError:
            print("not implemented yet")
    finally:
        shutdown()
