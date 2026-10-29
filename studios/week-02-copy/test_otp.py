"""Provided tests for the week-2 studio.

Run: ``python3 test_otp.py``. Passes => your entropy/unicity reasoning, your
one-time pad, and your two-time-pad break are all defensible. Prints one line per
test.

The guarantee test is in two halves and is the point of the week:

  * ``test_otp_perfect_secrecy_when_key_used_once`` — the SAME ciphertext decrypts
    to two DIFFERENT meaningful messages under two keys, so it favours neither.
    That is perfect secrecy, and no amount of compute breaks it.
  * ``test_two_time_pad_leaks_and_crib_drag_recovers`` — reuse the key ONCE and
    c1 XOR c2 = p1 XOR p2; crib-dragging then recovers both plaintexts in full.

A provable guarantee, destroyed by one broken condition. Watch it fail.
"""
import math
import sys

from otp import xor, entropy_bits, load_ciphertext_pair
import starter as s


# Ground truth for the two-time-pad exercise (the analyst does NOT get these; the
# test uses them only to verify the recovery). Same messages as the notebook,
# truncated to the common length n = 72.
P1 = b"the launch code is four seven two the target is the north bridge tonight"[:72]
P2 = b"please water my plants and feed the cat while i am away for the weekend ok"[:72]


def test_entropy_ranks_substitution_above_des():
    # Engine sanity + the week's hook: substitution has MORE key entropy than DES,
    # yet week 1 broke it in a second. Entropy is necessary, not sufficient.
    h_sub = entropy_bits(math.factorial(26))
    h_des = entropy_bits(2 ** 56)
    assert 88.0 < h_sub < 89.0, f"substitution entropy off: {h_sub}"
    assert abs(h_des - 56.0) < 1e-9, f"DES entropy off: {h_des}"
    assert h_sub > h_des
    print(f"  ok  substitution {h_sub:.1f} bits > DES {h_des:.0f} bits (yet broke first)")


def test_unicity_distance_explains_week1():
    # U = H(K)/D ~= 28 chars for substitution. Week 1's message was far past it.
    H_K, U = s.unicity_for_substitution()
    assert 88.0 < H_K < 89.0, f"H(K) off: {H_K}"
    assert 27.0 < U < 28.5, f"unicity distance off: expected ~27.6, got {U}"
    print(f"  ok  unicity U = {U:.1f} chars (why week 1's long message pinned the key)")


def test_otp_perfect_secrecy_when_key_used_once():
    """GUARANTEE (half 1): the OTP used once is unbreakable.

    One ciphertext, two keys, two DIFFERENT meaningful decryptions => the
    ciphertext cannot favour the real message over any other.
    """
    msg = b"ATTACK AT DAWN"
    decoy = b"RETREAT NOW!!!"          # same length, opposite meaning
    assert len(msg) == len(decoy)
    key = bytes((i * 37 + 11) % 256 for i in range(len(msg)))   # some real key
    ct = xor(msg, key)
    assert xor(ct, key) == msg                                  # decrypts correctly

    # The attacker's problem: a key exists making ct decrypt to the decoy too.
    key2 = s.key_that_decrypts_to(ct, decoy)
    assert xor(ct, key2) == decoy, "decoy key must decrypt the SAME ciphertext to decoy"
    assert key2 != key, "the two keys must differ (else nothing is demonstrated)"
    # Same ciphertext, two meaningful plaintexts => reveals nothing about which.
    print("  ok  OTP used once: one ciphertext -> two meaningful messages (unbreakable)")


def test_two_time_pad_leaks_and_crib_drag_recovers():
    """GUARANTEE (half 2): reuse the key and the whole thing collapses."""
    c1, c2 = load_ciphertext_pair()
    x = xor(c1, c2)

    # The key cancels: c1 XOR c2 == p1 XOR p2. The attacker never needed the key.
    assert x == xor(P1, P2), "c1 XOR c2 must equal p1 XOR p2 (key cancels)"

    # Crib-dragging: a correct crib surfaces the OTHER message's text.
    please_hits = dict(s.crib_drag(x, b"please"))
    assert 0 in please_hits, "crib 'please' should hit position 0 (start of p2)"
    assert please_hits[0] == P1[0:6], (
        f"at pos 0, dragging 'please' should reveal p1[0:6]={P1[0:6]!r}, "
        f"got {please_hits[0]!r}")
    target_hits = dict(s.crib_drag(x, b"target"))
    assert target_hits, "crib 'target' should surface at least one readable fragment"

    # Full recovery: with one plaintext as a crib, the other falls out entirely.
    assert s.recover_other_plaintext(c1, c2, P1) == P2, "p2 not recovered from p1"
    assert s.recover_other_plaintext(c2, c1, P2) == P1, "p1 not recovered from p2"
    print("  ok  two-time pad LEAKS p1 XOR p2; crib-drag recovers both plaintexts")


TESTS = [
    test_entropy_ranks_substitution_above_des,
    test_unicity_distance_explains_week1,
    test_otp_perfect_secrecy_when_key_used_once,
    test_two_time_pad_leaks_and_crib_drag_recovers,
]


def main():
    failed = 0
    for t in TESTS:
        try:
            t()
        except NotImplementedError:
            print(f"  --  {t.__name__}: not implemented yet (fill in starter.py)")
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
