"""Provided tests for the week-8 studio.

Run: ``python3 test_supplychain.py``. Passes => your three attacks and three
pins are correct and you are ready to write the Control Scorecard (Task 4).

Two of these are GUARANTEE tests — they watch a *name*-based trust decision get
exploited before the pin closes it:

  * ``test_dependency_confusion_public_wins_until_pinned`` — the naive resolver
    installs the ATTACKER'S public package under your internal name; the
    lockfile+hash+source pin then refuses it and accepts only the vetted artifact.
  * ``test_alg_none_forgery_accepted_until_algorithm_pinned`` — the header-
    trusting verifier ACCEPTS an unsigned ``role: admin`` token (privilege
    escalation with no key); the server-side algorithm pin then rejects it.

A test that expects the naive path to *succeed* for the attacker is not a
mistake: watching a name-based guarantee break once is how you know it was never
a guarantee at all.
"""
import sys

from data import (SBOM_EXPECTED, AFFECTED_EXPECTED, KNOWN_BAD, dep_graph,
                  LEGIT_PAYLOAD)
from supplychain import make_token, verify_insecure
import starter as s


def test_dependency_confusion_public_wins_until_pinned():
    """GUARANTEE TEST — name-based resolution trusts the wrong artifact.

    The naive resolver picks the highest version regardless of source, so the
    attacker's public 9.9.9 beats your internal 1.4.2: their code installs under
    your trusted name. The pin then makes the name irrelevant — only the exact
    vetted artifact (right source AND hash) installs.
    """
    source, version = s.resolve_highest_version("acme-auth")
    assert (source, version) == ("public", "9.9.9"), (
        f"naive resolver should pick the attacker's public 9.9.9, got {source} {version}"
    )
    # The pin: attacker's public artifact is refused, vetted internal is accepted.
    ok_attacker, _ = s.resolve_pinned("acme-auth", "evil99ff", "public")
    ok_vetted, _ = s.resolve_pinned("acme-auth", "aa11bb22cc", "internal")
    assert not ok_attacker, "pinned resolver must REFUSE the attacker's public artifact"
    assert ok_vetted, "pinned resolver must ACCEPT the exact vetted internal artifact"
    print("  ok  dependency confusion: public 9.9.9 won until the lockfile pin refused it")


def test_sbom_finds_transitive_cve():
    # The SBOM must include xz-utils even though nobody chose it directly
    # (acme-auth pulled it in). The CVE query is then instant.
    sbom = s.build_sbom("our-app", dep_graph)
    assert sbom == SBOM_EXPECTED, f"SBOM mismatch: got {sbom}"
    assert "xz-utils" in sbom, "the transitive xz-utils dependency must appear in the SBOM"
    affected = s.cve_affected(sbom, KNOWN_BAD)
    assert affected == AFFECTED_EXPECTED, (
        f"CVE query should report {AFFECTED_EXPECTED}, got {affected}"
    )
    print("  ok  SBOM surfaced the transitive xz-utils dep and answered the CVE query instantly")


def test_alg_none_forgery_accepted_until_algorithm_pinned():
    """GUARANTEE TEST — watch the header-trusting verifier's guarantee collapse.

    ``verify_insecure`` promises "only a token signed under our key is valid."
    The attacker sets ``alg=none``, claims ``role: admin``, sends NO signature —
    and the verifier accepts it. Privilege escalation with no signing key. The
    guarantee fails.
    """
    forged = s.forge_alg_none_admin()
    claims = verify_insecure(forged)                   # the naive verifier ACCEPTS it
    assert claims is not None, "the forged alg=none token should be accepted by verify_insecure"
    assert claims.get("role") == "admin", (
        f"alg=none forgery should escalate to admin, got role={claims.get('role')!r}"
    )
    print("  ok  alg=none guarantee COLLAPSED — unsigned admin token accepted, no key needed")


def test_algorithm_pinning_rejects_forgery():
    # The fix: pin the algorithm server-side. The forgery is rejected; a real
    # HS256-signed token still verifies. Trust the artifact under YOUR key, not
    # the token's self-description.
    forged = s.forge_alg_none_admin()
    assert s.verify_secure(forged) is None, (
        "algorithm-pinned verifier must REJECT the alg=none forgery"
    )
    legit = make_token(LEGIT_PAYLOAD)
    assert s.verify_secure(legit) == LEGIT_PAYLOAD, (
        "algorithm-pinned verifier must still ACCEPT a legitimately signed token"
    )
    print("  ok  algorithm pinning rejected the forgery, accepted the real token")


TESTS = [
    test_dependency_confusion_public_wins_until_pinned,
    test_sbom_finds_transitive_cve,
    test_alg_none_forgery_accepted_until_algorithm_pinned,
    test_algorithm_pinning_rejects_forgery,
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
