"""Provided tests for the week-4 studio. Run: ``python3 test_rsa.py``.

Passes  => your attacks are real and your fix works; you're ready for the
scorecard (Task 4) and for Duel 1 next week. Prints one line per test.

The two *guarantee* tests are the point of the week:

  * ``test_shared_factor_recovers_both_keys`` — RSA's guarantee ("infeasible to
    factor n") holds for each key ALONE but collapses across a population: two
    keys sharing a prime both fall to a single GCD. Watching an
    "each-key-is-fine" guarantee fail at population scale is the lesson.
  * ``test_constant_time_defeats_timing_attack`` — the same attack that recovers
    a secret through an early-exit compare recovers NOTHING through a
    constant-time compare. The algorithm didn't change; the *condition* did.
"""
import math
import os
import sys

import rsa_lab as lab
import starter as s


# ---- RSA sanity + the reduction ---------------------------------------------

def test_rsa_roundtrip_and_reduction():
    # Textbook RSA with tiny primes: encrypt/decrypt round-trips, and d is only
    # obtainable via the factorization (phi needs p, q).
    pub, priv = lab.rsa_keygen(61, 53, e=17)
    c = lab.encrypt(42, pub)
    assert lab.decrypt(c, priv) == 42, "RSA round-trip failed"
    # The reduction, concretely: knowing a factor yields d.
    n, e = pub
    d = lab.factor_from_shared(n, 61, e=17)
    assert lab.decrypt(c, (n, d)) == 42, "recovering d from a known factor failed"
    print("  ok  RSA round-trips; d recoverable once n is factored")


# ---- Task 2: shared-factor (batch-GCD) — the guarantee fails at scale --------

def test_shared_factor_recovers_both_keys():
    corpus = lab.load_keys()
    recovered = s.batch_gcd_recover(corpus)
    truth = corpus["_ground_truth"]["vulnerable_indices"]
    # BOTH keys in the sharing pair must be recovered — not just one.
    assert set(recovered) == set(truth), (
        f"expected private keys for indices {sorted(truth)}, "
        f"got {sorted(recovered)}"
    )
    # Each recovered d must actually work: encrypt then decrypt round-trips.
    for i, d in recovered.items():
        n = corpus["keys"][i]["n"]
        e = corpus["keys"][i]["e"]
        c = lab.encrypt(1234567890, (n, e))
        assert lab.decrypt(c, (n, d)) == 1234567890, (
            f"recovered d for key {i} does not decrypt"
        )
    print(f"  ok  batch-GCD recovered BOTH shared-factor keys {sorted(recovered)} "
          f"(each was 'fine' alone)")


def test_safe_keys_not_recovered():
    # A key that shares no factor with any other must NOT be recoverable this way.
    corpus = lab.load_keys()
    recovered = s.batch_gcd_recover(corpus)
    safe = [i for i in range(len(corpus["keys"]))
            if i not in corpus["_ground_truth"]["vulnerable_indices"]]
    for i in safe:
        assert i not in recovered, (
            f"key {i} shares no factor yet was 'recovered' — the scan is wrong"
        )
    # And pairwise-GCD ground truth confirms exactly one sharing pair exists.
    ns = [k["n"] for k in corpus["keys"]]
    pairs = [(i, j) for i in range(len(ns)) for j in range(i + 1, len(ns))
             if math.gcd(ns[i], ns[j]) != 1]
    assert len(pairs) == 1, f"corpus should have exactly one sharing pair, got {pairs}"
    print(f"  ok  {len(safe)} isolated keys stay safe (gcd=1 with everyone)")


# ---- Task 3: timing side channel + the constant-time fix ---------------------

# Small, fixed secret keeps the timing attack fast (~1-2s) and reproducible.
_SECRET = bytes([0xA5, 0x3C])


def test_timing_attack_recovers_secret():
    # Early-exit compare LEAKS: the attack recovers the secret with no read access.
    oracle = lab.make_oracle(_SECRET, compare=lab.insecure_equal)
    got = s.timing_attack(len(_SECRET), oracle, rounds=41)
    assert got == _SECRET, (
        f"timing attack failed: secret={_SECRET.hex()} recovered={got.hex()}. "
        "Timing is noisy — median over more trials makes the signal stable."
    )
    print(f"  ok  early-exit compare leaked: recovered {got.hex()} by timing alone")


def test_constant_time_defeats_timing_attack():
    # SAME attack, constant-time oracle: no timing signal => cannot recover.
    oracle = lab.make_oracle(_SECRET, compare=s.constant_time_equal)
    got = s.timing_attack(len(_SECRET), oracle, rounds=41)
    assert got != _SECRET, (
        "the timing attack recovered the secret through constant_time_equal — "
        "your 'fix' still leaks (did you early-exit?)"
    )
    print("  ok  constant-time compare leaked nothing: same attack recovered "
          f"{got.hex()} != {_SECRET.hex()}")


def test_constant_time_equal_is_correct():
    # The fix must still be a correct equality test.
    assert s.constant_time_equal(b"abcd", b"abcd") is True
    assert s.constant_time_equal(b"abcd", b"abce") is False
    assert s.constant_time_equal(b"abc", b"abcd") is False
    print("  ok  constant_time_equal is a correct equality test")


TESTS = [
    test_rsa_roundtrip_and_reduction,
    test_shared_factor_recovers_both_keys,
    test_safe_keys_not_recovered,
    test_timing_attack_recovers_secret,
    test_constant_time_defeats_timing_attack,
    test_constant_time_equal_is_correct,
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
