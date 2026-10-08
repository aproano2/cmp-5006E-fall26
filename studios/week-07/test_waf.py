"""Provided tests for the week-7 studio.

Run: ``python3 test_waf.py``. Passes ⇒ your measurements are correct and you are
ready to write the Control Scorecard. Laptop-only: pure Python plus the week-6
``vuln-web`` app run IN-PROCESS (stdlib http.server, no Docker, 127.0.0.1 only).

The GUARANTEE-FAIL test — ``test_blocklist_loses_on_both_blades`` — is the point
of the week. It watches the WAF's implied promise ("we filter attacks") collapse
on BOTH blades at once: a mutated payload gets through (axis 4) AND a legitimate
request is wrongly blocked (axis 5). Loosen the rules to cut the false positives
and the bypasses multiply; tighten them and more users suffer. There is no good
setting, because you are enumerating badness.

The companion test — ``test_parameterization_guarantee_holds`` — shows the
positive model give 0/N injections for ANY input: not "blocked by a rule" but
STRUCTURALLY unable to inject. A guarantee you can watch a blocklist fail while a
boundary holds is a guarantee you actually understand.

Oracle discipline (``seclab.attack``): the lab-anchored test confirms a real
canary leak, not a reflected string.
"""
import sys

from waf import (KNOWN_ATTACKS, BYPASSES, load_benign, start_vulnweb,
                 vulnweb_canary)
import starter as s


def test_coverage_on_known_attacks_looks_perfect():
    # 4/4 on the payloads you thought of — the trap. It measures your
    # enumeration of the past, not your safety against the future.
    blocked, total = s.measure_coverage(KNOWN_ATTACKS)
    assert (blocked, total) == (4, 4), (
        f"expected 4/4 coverage on the known week-6 attacks, got {blocked}/{total}"
    )
    print(f"  ok  WAF coverage on KNOWN attacks {blocked}/{total} — 'looks great' (the trap)")


def test_blocklist_is_bypassed_axis_4():
    # Same intent, new surface: 3/4 mutations evade the rules. A defense you
    # haven't bypassed is unevaluated.
    through, total = s.measure_bypasses(BYPASSES)
    assert through >= 1, "no bypass got through — the blocklist looks complete (it isn't)"
    assert through == 3, (
        f"expected 3/4 same-intent bypasses to evade the rules, got {through}/{total}"
    )
    print(f"  ok  {through}/{total} bypasses evaded the WAF (axis 4) — same attack, new surface")


def test_blocklist_false_positives_axis_5():
    # A rule broad enough to catch variants also blocks legit traffic. Every FP
    # is a real user turned away. Reuses the Duel-2 benign corpus (26 inputs).
    fps = s.measure_false_positives(load_benign())
    assert len(fps) >= 1, (
        "the WAF blocked NO legitimate traffic — either the corpus regressed or "
        "measure_false_positives is not flagging blocked benign inputs"
    )
    blocked_inputs = {inp for inp, _rule in fps}
    assert "drop table tennis lessons for beginners" in blocked_inputs, (
        "expected the legit phrase 'drop table tennis lessons for beginners' to "
        f"trip the DROP TABLE rule; blocked instead: {sorted(blocked_inputs)}"
    )
    print(f"  ok  WAF false-positived on {len(fps)}/{len(load_benign())} legit inputs "
          "(axis 5) — real users blocked")


def test_blocklist_loses_on_both_blades():
    """GUARANTEE-FAIL TEST — the negative-security promise collapses.

    The WAF is BOTH bypassable (axis 4) AND noisy (axis 5), simultaneously.
    There is no rule setting that is complete and quiet, because the space of
    malicious input is open-ended and overlaps benign text.
    """
    through, _ = s.measure_bypasses(BYPASSES)
    fps = s.measure_false_positives(load_benign())
    assert through > 0 and len(fps) > 0, (
        f"the blocklist must fail on BOTH blades: bypasses through={through}, "
        f"false positives={len(fps)} — both should be > 0"
    )
    print(f"  ok  blocklist LOST on both blades — {through} bypasses through AND "
          f"{len(fps)} false positives, at once (negative security's defining weakness)")


def test_parameterization_guarantee_holds():
    """The positive model: 0/N injections succeed, for ANY input."""
    all_payloads = list(KNOWN_ATTACKS) + [p for p, _ in BYPASSES]
    succeeded, total = s.count_injection_successes(all_payloads)
    assert total == 8, f"expected 8 payloads (4 attacks + 4 bypasses), got {total}"
    assert succeeded == 0, (
        f"{succeeded}/{total} injections altered behaviour under parameterization — "
        "the positive model must give 0: input is data, never code"
    )
    print(f"  ok  parameterization defeated {total}/{total} injections structurally "
          "(0 succeeded) — a guarantee the WAF could never state (axis 2)")


def test_bypass_leaks_canary_on_real_app():
    """Lab-anchored, in-process, oracle-confirmed. A WAF-passed bypass reaches
    the real vuln-web /login sink and leaks the admin canary — axis 4 for real,
    confirmed by a sound oracle (the canary token), not a reflected string."""
    base, shutdown = start_vulnweb()
    try:
        leaked = s.bypass_leaks_canary(base)
        assert leaked is True, (
            "no WAF-passed bypass leaked the canary on the real app — the oracle "
            f"never saw {vulnweb_canary()!r}. Check that you SKIP WAF-blocked "
            "payloads and confirm with the canary, not the echoed payload."
        )
        print("  ok  a WAF-passed bypass leaked the real canary via /login "
              "(seclab-style oracle) — the WAF is a sensor, not a wall")
    finally:
        shutdown()


TESTS = [
    test_coverage_on_known_attacks_looks_perfect,
    test_blocklist_is_bypassed_axis_4,
    test_blocklist_false_positives_axis_5,
    test_blocklist_loses_on_both_blades,
    test_parameterization_guarantee_holds,
    test_bypass_leaks_canary_on_real_app,
]


def main():
    failed = 0
    for t in TESTS:
        try:
            t()
        except NotImplementedError:
            print(f"  --  {t.__name__}: not implemented yet")
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
