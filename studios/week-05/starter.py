"""Week 5 studio — starter (Diffie-Hellman, MITM, and the trust-store attack).

Fill in the four functions below, then run ``python3 test_dh_pki.py``. All
required tests must pass, INCLUDING the two *guarantee* tests that watch a
protocol guarantee collapse:

  * ``test_mitm_breaks_unauthenticated_dh`` — unauthenticated DH is MITM'd:
    Mallory ends up sharing a key with each side, and Alice and Bob share
    nothing. Secrecy held on every leg; authentication was never there.
  * ``test_trust_store_poisoning_accepts_forgery`` — a forged chain is REJECTED
    at the trust anchor, then ACCEPTED the instant the rogue root is added to
    the store. The math never broke; the trust anchor did.

The RSA/cert machinery (``make_cert``, ``validate``, ``verify``) and the DH group
(``DH_P``, ``DH_G``) are GIVEN in ``dh_pki.py`` — do not reimplement them.
"""
from dh_pki import DH_P, DH_G, make_cert, validate, verify, load_fixtures


# ---- Task 1: Diffie-Hellman + the man-in-the-middle -------------------------

def dh_public(private, g=DH_G, p=DH_P):
    """Alice/Bob's public value: g^private mod p, sent over the wire."""
    # TODO: return pow(g, private, p)
    raise NotImplementedError


def dh_shared(their_public, my_private, p=DH_P):
    """The shared secret each side computes: their_public^my_private mod p.

    If both sides did this against *each other's* public value, they land on the
    same g^(ab) mod p. DH's guarantee: an eavesdropper who saw only the two
    public values cannot compute it (discrete-log assumption).
    """
    # TODO: return pow(their_public, my_private, p)
    raise NotImplementedError


def mitm_keys(a, b, m, g=DH_G, p=DH_P):
    """Mallory sits on the wire between Alice (private ``a``) and Bob (private
    ``b``) and injects her own public value (from private ``m``) toward BOTH.

    Alice never sees Bob's public value — she sees Mallory's, and vice versa.
    Return a dict recording the four half-secrets and whether Alice and Bob
    actually agree:

        {
          "alice":         Alice's secret  (thinks it's shared with Bob),
          "mallory_alice": Mallory's matching secret with Alice,
          "bob":           Bob's secret    (thinks it's shared with Alice),
          "mallory_bob":   Mallory's matching secret with Bob,
          "alice_equals_bob": bool,   # do Alice and Bob share a key? (they do NOT)
        }

    Use ``dh_public`` and ``dh_shared`` — do not call ``pow`` directly here.
    """
    # TODO:
    #   A = dh_public(a); B = dh_public(b); M = dh_public(m)
    #   Alice, seeing M (she thinks it's Bob), computes dh_shared(M, a)
    #   Mallory, seeing A, computes dh_shared(A, m)  -> same key as Alice
    #   Bob,   seeing M (he thinks it's Alice), computes dh_shared(M, b)
    #   Mallory, seeing B, computes dh_shared(B, m)  -> same key as Bob
    #   alice_equals_bob = (Alice's key == Bob's key)
    raise NotImplementedError


# ---- Task 3: the trust-store attack -----------------------------------------

def poison_trust_store(trust_store, rogue_root):
    """Malware (or a coerced admin) installs ``rogue_root`` — a cert — into the
    browser's trust store. Return a NEW trust store (a set of public keys) that
    also trusts the rogue root's public key.

    Do not mutate the caller's ``trust_store``; return a fresh set. After this,
    any chain terminating in the rogue root validates — the DigiNotar failure
    mode in miniature.
    """
    # TODO: return a new set = trust_store plus rogue_root["pub"]
    raise NotImplementedError


# ---- Task 2 uses the GIVEN validator; nothing to implement there ------------
# Load the notebook's chain + forgeries with ``load_fixtures()`` and call
# ``validate(chain, trust_store)``. Both forgeries fail at the SAME check — the
# chain doesn't terminate in a trusted root. See README.md §"Task 2".


if __name__ == "__main__":
    # Quick smoke test once you've filled things in.
    import os
    fx = load_fixtures()
    try:
        a = int.from_bytes(os.urandom(32), "big")
        b = int.from_bytes(os.urandom(32), "big")
        # Honest DH: Alice and Bob against each other.
        A, B = dh_public(a), dh_public(b)
        print("honest DH agrees:", dh_shared(B, a) == dh_shared(A, b))
        # MITM:
        mk = mitm_keys(a, b, int.from_bytes(os.urandom(32), "big"))
        print("Mallory<->Alice share:", mk["alice"] == mk["mallory_alice"])
        print("Mallory<->Bob   share:", mk["bob"] == mk["mallory_bob"])
        print("Alice<->Bob     share:", mk["alice_equals_bob"], "(should be False)")
    except NotImplementedError:
        print("DH functions not implemented yet")
    try:
        clean = fx["trust_store"]
        chain = [fx["rogue_leaf"], fx["rogue_ca"]]
        print("rogue chain, clean store :", validate(chain, clean))
        poisoned = poison_trust_store(clean, fx["rogue_ca"])
        print("rogue chain, poisoned    :", validate(chain, poisoned))
    except NotImplementedError:
        print("poison_trust_store not implemented yet")
