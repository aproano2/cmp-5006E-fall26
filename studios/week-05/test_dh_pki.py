"""Provided tests for the week-5 studio.

Run: ``python3 test_dh_pki.py``. Passes => your DH, MITM, and trust-store work is
defensible. Prints one line per test.

Two of these are *guarantee* tests — they assert that a protocol guarantee
COLLAPSES under the right condition. That is the point of the week:

  * ``test_mitm_breaks_unauthenticated_dh``   — unauthenticated DH is MITM'd.
  * ``test_trust_store_poisoning_accepts_forgery`` — a forged chain, rejected at
    the anchor, is accepted once the trust store is poisoned.

A test that expects a guarantee to *fail* is not a mistake; watching it fail once
is how you know the guarantee was conditional all along.
"""
import sys

from dh_pki import DH_P, DH_G, validate, load_fixtures
import starter as s

FX = load_fixtures()

# Fixed private exponents so the run is deterministic (any ints work for DH).
A_PRIV = 0x1a2b3c4d5e6f7788
B_PRIV = 0x99aabbccddeeff00
M_PRIV = 0xdeadbeefcafef00d      # Mallory


def test_dh_direct_agreement_is_secret_and_shared():
    # Honest DH: Alice and Bob run it against EACH OTHER and land on one secret.
    A = s.dh_public(A_PRIV)
    B = s.dh_public(B_PRIV)
    ka = s.dh_shared(B, A_PRIV)          # Alice: Bob's public ^ Alice's private
    kb = s.dh_shared(A, B_PRIV)          # Bob:   Alice's public ^ Bob's private
    assert ka == kb, "honest DH: Alice and Bob did not derive the same secret"
    assert ka == pow(DH_G, A_PRIV * B_PRIV, DH_P), "shared secret != g^(ab) mod p"
    print("  ok  honest DH: Alice and Bob agree on g^(ab) mod p")


def test_mitm_breaks_unauthenticated_dh():
    """GUARANTEE TEST. Unauthenticated DH gives secrecy on each leg and zero
    authentication — an active attacker holds a key with each side."""
    mk = s.mitm_keys(A_PRIV, B_PRIV, M_PRIV)
    assert mk["alice"] == mk["mallory_alice"], "Mallory does not share Alice's key"
    assert mk["bob"] == mk["mallory_bob"], "Mallory does not share Bob's key"
    # The guarantee failing: Alice and Bob do NOT share a key with each other.
    assert mk["alice_equals_bob"] is False, (
        "Alice and Bob ended up sharing a key — then there was no MITM to watch. "
        "Mallory must inject her own public value toward BOTH sides."
    )
    assert mk["alice"] != mk["bob"], "Alice's and Bob's secrets should differ under MITM"
    print("  ok  MITM: Mallory holds a key with each side; Alice<->Bob share nothing")


def test_legitimate_chain_validates():
    ok, reason = validate(FX["chain"], FX["trust_store"])
    assert ok, f"legitimate chain rejected: {reason}"
    print("  ok  legitimate leaf<-intermediate<-root chain validates")


def test_self_signed_forgery_rejected_at_anchor():
    ok, reason = validate([FX["self_signed_forgery"]], FX["trust_store"])
    assert not ok, "self-signed forgery was accepted — it must not be"
    assert "trusted root" in reason, f"rejected for the wrong reason: {reason}"
    print("  ok  self-signed forgery rejected at the trust anchor")


def test_rogue_ca_chain_rejected_at_anchor():
    chain = [FX["rogue_leaf"], FX["rogue_ca"]]
    ok, reason = validate(chain, FX["trust_store"])
    assert not ok, "rogue-CA chain was accepted — it must not be"
    # Same failure as the self-signed forgery: doesn't terminate in a trusted root.
    assert "trusted root" in reason, f"rejected for the wrong reason: {reason}"
    print("  ok  rogue-CA chain rejected at the SAME check (untrusted anchor)")


def test_trust_store_poisoning_accepts_forgery():
    """GUARANTEE TEST. The forged chain is rejected under a clean store, then
    ACCEPTED once the rogue root is installed — the DigiNotar failure mode."""
    chain = [FX["rogue_leaf"], FX["rogue_ca"]]
    ok_before, _ = validate(chain, FX["trust_store"])
    assert not ok_before, "rogue chain must be rejected under the clean store"

    poisoned = s.poison_trust_store(FX["trust_store"], FX["rogue_ca"])
    assert FX["rogue_ca"]["pub"] not in FX["trust_store"], (
        "poison_trust_store mutated the caller's store — return a NEW set"
    )
    ok_after, reason = validate(chain, poisoned)
    assert ok_after, f"poisoned store still rejects the rogue chain: {reason}"
    print("  ok  trust-store poisoning: rejected clean, ACCEPTED once rogue root trusted")


TESTS = [
    test_dh_direct_agreement_is_secret_and_shared,
    test_mitm_breaks_unauthenticated_dh,
    test_legitimate_chain_validates,
    test_self_signed_forgery_rejected_at_anchor,
    test_rogue_ca_chain_rejected_at_anchor,
    test_trust_store_poisoning_accepts_forgery,
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
