"""Provided tests for the week-1 studio.

Run: ``python3 test_cipher.py``. Passes => your attack is defensible. Prints one
line per test.

The *guarantee* test — ``test_english_assumption_collapses_confidentiality`` — is
the point of the week. A substitution cipher's confidentiality "guarantee" is
real ONLY under an assumption the designer rarely states out loud: that the
plaintext has no exploitable structure. The test watches that guarantee COLLAPSE
the instant the plaintext is English — recovered without the key, from public
knowledge alone. Its companion, ``test_cipher_holds_on_non_english_plaintext``,
shows the other side: strip the assumption (uniform-random plaintext) and the very
same attack recovers almost nothing. The cipher is exactly as strong as the
assumption is true. Name the assumption and you have named the attack (Kerckhoffs).
"""
import sys

from cipher import (apply_guess, decrypt, encrypt, load_ciphertexts, make_key,
                    recovery_rate)
import starter as s

BANK = load_ciphertexts()
CRACK_SEED = BANK["crack_seed"]

RECOVER_THRESHOLD = 0.90     # "broken": >= 90% of characters recovered w/o the key
HOLD_THRESHOLD = 0.40        # "holds":  < 40% recovered on non-English plaintext


def test_cipher_roundtrip():
    # Given engine sanity: decrypt(encrypt(x)) == x for any key. No attack here.
    for seed in (1, 7, 12):
        key = make_key(seed)
        msg = "ATTACK AT DAWN, THE FLAWS ARE NOT KNOWN."
        assert decrypt(encrypt(msg, key), key) == msg.upper(), f"roundtrip failed @seed {seed}"
    print("  ok  encrypt/decrypt round-trips on 3 keys")


def test_frequency_guess_is_a_valid_mapping():
    # The first pass must assign distinct plaintext letters to distinct symbols.
    ct = BANK["english"][0]["ciphertext"]
    guess = s.frequency_guess_key(ct)
    vals = list(guess.values())
    assert len(vals) == len(set(vals)), "frequency guess maps two symbols to the same letter"
    assert all(v in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" for v in vals), "non-letter in guess"
    print(f"  ok  frequency_guess_key is a valid 1-to-1 mapping ({len(vals)} symbols)")


def test_english_assumption_collapses_confidentiality():
    """THE GUARANTEE TEST. The cipher's confidentiality holds only while the
    plaintext looks like noise. Make it English and the guarantee falls: the
    attack recovers the plaintext WITHOUT ever touching the key, on all 12 keys."""
    recovered_on = 0
    for item in BANK["english"]:
        ct, pt = item["ciphertext"], item["plaintext"]
        key = s.crack(ct, seed=CRACK_SEED)           # attack: ciphertext only
        rate = recovery_rate(apply_guess(ct, key), pt)
        assert rate >= RECOVER_THRESHOLD, (
            f"only {rate:.0%} recovered on key_seed={item['key_seed']} "
            f"(need >= {RECOVER_THRESHOLD:.0%}). The guarantee was supposed to fail "
            "here — English leaks — so the ATTACK should win."
        )
        recovered_on += 1
    print(f"  ok  confidentiality collapsed on {recovered_on}/{len(BANK['english'])} "
          "English ciphertexts — recovered without the key (that is the lesson)")


def test_cipher_holds_on_non_english_plaintext():
    """The other face of the same coin. Strip the English assumption — encrypt a
    uniform-random plaintext — and the identical attack recovers almost nothing.
    The cipher is only as weak as its plaintext's structure."""
    item = BANK["non_english"]
    ct, pt = item["ciphertext"], item["plaintext"]
    key = s.crack(ct, seed=CRACK_SEED)
    rate = recovery_rate(apply_guess(ct, key), pt)
    assert rate < HOLD_THRESHOLD, (
        f"attack recovered {rate:.0%} of a NON-English plaintext (expected "
        f"< {HOLD_THRESHOLD:.0%}). Frequency analysis should have nothing to bite on."
    )
    print(f"  ok  non-English plaintext held: only {rate:.0%} recovered — "
          "the assumption is what breaks the cipher, not the algorithm")


TESTS = [
    test_cipher_roundtrip,
    test_frequency_guess_is_a_valid_mapping,
    test_english_assumption_collapses_confidentiality,
    test_cipher_holds_on_non_english_plaintext,
]


def main():
    failed = 0
    for t in TESTS:
        try:
            t()
        except NotImplementedError:
            print(f"  --  {t.__name__}: attack not implemented yet (fill starter.py)")
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
