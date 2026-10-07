"""Week 5 studio — REFERENCE SOLUTION (instructor-only).

A filled-in copy of ``starter.py``: identical function names and signatures, so
the *provided* ``test_dh_pki.py`` passes when this module is imported in place of
``starter``. Verify with ``studios/_verify_solutions.py`` (which aliases this file
to the name ``starter`` and runs the unmodified test).

The whole week is one lesson in two guarantees collapsing:

  * ``mitm_keys`` — DH gives *secrecy on each leg* and *zero authentication*. If
    Mallory injects her own public value toward BOTH sides, she shares a key with
    each of Alice and Bob, and Alice and Bob share nothing. The math never broke;
    the missing property (endpoint authentication) was never there.
  * ``poison_trust_store`` — a forged chain is REJECTED under a clean store and
    ACCEPTED the instant the rogue root is trusted. The signatures never failed;
    the trust anchor did (the DigiNotar failure mode in miniature).

DO NOT ship to students — excluded via ``studios/.gitignore``. The teaching
walkthrough is ``solution.ipynb`` (imports this file rather than re-pasting it).
"""
from dh_pki import DH_P, DH_G, make_cert, validate, verify, load_fixtures


# ---- Task 1: Diffie-Hellman + the man-in-the-middle -------------------------

def dh_public(private, g=DH_G, p=DH_P):
    """Alice/Bob's public value: g^private mod p, sent over the wire."""
    return pow(g, private, p)


def dh_shared(their_public, my_private, p=DH_P):
    """The shared secret each side computes: their_public^my_private mod p.

    If both sides did this against *each other's* public value, they land on the
    same g^(ab) mod p. DH's guarantee: an eavesdropper who saw only the two
    public values cannot compute it (discrete-log assumption).
    """
    return pow(their_public, my_private, p)


def mitm_keys(a, b, m, g=DH_G, p=DH_P):
    """Mallory sits on the wire between Alice (private ``a``) and Bob (private
    ``b``) and injects her own public value (from private ``m``) toward BOTH.

    Alice never sees Bob's public value — she sees Mallory's, and vice versa.
    """
    A = dh_public(a, g, p)
    B = dh_public(b, g, p)
    M = dh_public(m, g, p)

    # Alice sees M (she thinks it's Bob); Mallory sees A. Same secret: g^(am).
    alice = dh_shared(M, a, p)
    mallory_alice = dh_shared(A, m, p)

    # Bob sees M (he thinks it's Alice); Mallory sees B. Same secret: g^(bm).
    bob = dh_shared(M, b, p)
    mallory_bob = dh_shared(B, m, p)

    return {
        "alice": alice,
        "mallory_alice": mallory_alice,
        "bob": bob,
        "mallory_bob": mallory_bob,
        # Alice and Bob never derived a common key — that is the guarantee failing.
        "alice_equals_bob": alice == bob,
    }


# ---- Task 3: the trust-store attack -----------------------------------------

def poison_trust_store(trust_store, rogue_root):
    """Malware (or a coerced admin) installs ``rogue_root`` into the browser's
    trust store. Return a NEW trust store (a set of public keys) that also trusts
    the rogue root's public key — WITHOUT mutating the caller's store.

    After this, any chain terminating in the rogue root validates — the DigiNotar
    failure mode in miniature.
    """
    return set(trust_store) | {rogue_root["pub"]}


# ---- Task 2 uses the GIVEN validator; nothing to implement there ------------
# Load the notebook's chain + forgeries with ``load_fixtures()`` and call
# ``validate(chain, trust_store)``. Both forgeries fail at the SAME check — the
# chain doesn't terminate in a trusted root. See README.md §"Task 2".


if __name__ == "__main__":
    import os
    fx = load_fixtures()
    a = int.from_bytes(os.urandom(32), "big")
    b = int.from_bytes(os.urandom(32), "big")
    A, B = dh_public(a), dh_public(b)
    print("honest DH agrees:", dh_shared(B, a) == dh_shared(A, b))
    mk = mitm_keys(a, b, int.from_bytes(os.urandom(32), "big"))
    print("Mallory<->Alice share:", mk["alice"] == mk["mallory_alice"])
    print("Mallory<->Bob   share:", mk["bob"] == mk["mallory_bob"])
    print("Alice<->Bob     share:", mk["alice_equals_bob"], "(should be False)")

    clean = fx["trust_store"]
    chain = [fx["rogue_leaf"], fx["rogue_ca"]]
    print("rogue chain, clean store :", validate(chain, clean))
    poisoned = poison_trust_store(clean, fx["rogue_ca"])
    print("rogue chain, poisoned    :", validate(chain, poisoned))
