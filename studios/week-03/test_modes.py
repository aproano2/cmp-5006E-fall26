"""Provided tests for the week-3 studio.

Run: ``python3 test_modes.py``. Passes ⇒ your three exploits are correct and you
are ready to write the Control Scorecard (Task 4).

The GUARANTEE test — ``test_length_extension_breaks_bad_mac_guarantee`` — is the
point of the week. It watches the ``H(secret‖msg)`` MAC's promise ("only the
key-holder can produce a valid tag") COLLAPSE: the forgery succeeds without the
secret. The companion test then shows HMAC rejecting the same attack. A
guarantee you can watch fail once is a guarantee you actually understand.
"""
import os
import sys
import hmac

from modes import ctr_keystream, cbc_encrypt, distinct_blocks, xor
from mdhash import bad_mac, good_mac
from data import (IMAGE, ECB_DISTINCT_EXPECTED, CBC_DISTINCT_EXPECTED,
                  M1, M2, MAC_SECRET, MAC_MSG, MAC_EXTENSION)
import starter as s


def test_ecb_leaks_structure_cbc_hides_it():
    # ECB preserves the plaintext block structure 1:1 (2 flat regions -> 2
    # distinct ciphertext blocks); CBC chaining destroys it (96 distinct).
    key = os.urandom(16)
    ecb_distinct = s.ecb_leak_count(IMAGE, key)
    assert ecb_distinct == ECB_DISTINCT_EXPECTED, (
        f"ECB should leak {ECB_DISTINCT_EXPECTED} distinct blocks, got {ecb_distinct}"
    )
    cbc_distinct = distinct_blocks(cbc_encrypt(IMAGE, key, os.urandom(3)))
    assert cbc_distinct == CBC_DISTINCT_EXPECTED, (
        f"CBC should hide structure ({CBC_DISTINCT_EXPECTED} distinct), got {cbc_distinct}"
    )
    print(f"  ok  ECB leaks {ecb_distinct} blocks, CBC hides ({cbc_distinct}) — "
          "the MODE decided, not the cipher")


def test_ctr_nonce_reuse_recovers_plaintext():
    # Same key, SAME nonce for both messages -> shared keystream -> two-time pad.
    key, nonce = os.urandom(16), os.urandom(8)
    ks = ctr_keystream(key, nonce, max(len(M1), len(M2)))
    c1, c2 = xor(M1, ks), xor(M2, ks)
    # Sanity: the keystream cancels, exactly as in week 2.
    assert xor(c1, c2) == xor(M1, M2)
    recovered = s.recover_second_plaintext(c1, c2, M1)
    assert recovered == M2, (
        f"CTR nonce reuse should recover m2; got {recovered!r} != {M2!r}"
    )
    print("  ok  CTR nonce reuse recovered m2 = week-2 two-time pad on a modern mode")


def test_length_extension_breaks_bad_mac_guarantee():
    """GUARANTEE TEST — watch H(secret‖msg)'s authenticity guarantee collapse.

    The construction claims only the secret-holder can produce a valid tag. The
    attacker, knowing only (msg, tag, len(secret)), forges a tag for
    attacker-chosen extended data. The forge SUCCEEDS — the guarantee fails.
    """
    tag = bad_mac(MAC_SECRET, MAC_MSG)             # attacker observes (msg, tag)
    forged_msg, forged_tag = s.forge_extension(
        MAC_MSG, tag, len(MAC_SECRET), MAC_EXTENSION)
    # The server, holding the secret, computes the SAME tag for forged_msg.
    server_tag = bad_mac(MAC_SECRET, forged_msg)
    assert forged_tag == server_tag, (
        "length-extension forge failed to match the server's tag — check the "
        "glue padding and the resumed IV"
    )
    assert MAC_EXTENSION in forged_msg, "forged message must carry the attacker's data"
    print("  ok  H(secret‖msg) guarantee COLLAPSED — valid tag forged without the key")


def test_hmac_rejects_the_same_forgery():
    # HMAC exposes no resumable inner state, so the extension attack has no path.
    # A naive "extend" (tag over msg+extension with no key) does not validate.
    forged_guess = good_mac(b"", MAC_MSG + MAC_EXTENSION)
    real_tag = good_mac(MAC_SECRET, MAC_MSG + MAC_EXTENSION)
    assert not hmac.compare_digest(forged_guess, real_tag), (
        "HMAC unexpectedly accepted a keyless forgery"
    )
    print("  ok  HMAC rejected the forgery — better construction, not a better hash")


TESTS = [
    test_ecb_leaks_structure_cbc_hides_it,
    test_ctr_nonce_reuse_recovers_plaintext,
    test_length_extension_breaks_bad_mac_guarantee,
    test_hmac_rejects_the_same_forgery,
]


def main():
    failed = 0
    for t in TESTS:
        try:
            t()
        except NotImplementedError:
            print(f"  --  {t.__name__}: exploit not implemented yet")
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
