"""Week 2 studio — starter (entropy, the one-time pad, and the two-time-pad break).

Fill in the four functions below, then run ``python3 test_otp.py``. All provided
tests must pass — INCLUDING the guarantee test, which asserts two things at once:

  * the OTP used ONCE is unbreakable (the SAME ciphertext decrypts to two
    different meaningful messages under two different keys — so it favours
    neither), and
  * the OTP key used TWICE collapses completely (c1 XOR c2 = p1 XOR p2, and
    crib-dragging recovers both plaintexts).

A provable guarantee (perfect secrecy) destroyed by one broken condition (use the
key once) is the whole payload of the week. Watch it happen.

The engine (XOR, entropy, unicity, the crib-drag printability test) is provided in
``otp.py`` — do not reimplement it; call it.
"""
from otp import (xor, entropy_bits, unicity_distance, printable_word,
                 ENGLISH_REDUNDANCY, SCHEMES)
import math


# ---- Task 1: entropy & unicity ----------------------------------------------

def unicity_for_substitution():
    """Return (H_K, U) for the 26! substitution cipher.

    H_K is the key entropy in bits (use ``entropy_bits`` on the size of the
    keyspace, 26!). U is the unicity distance in characters (use
    ``unicity_distance`` with the English redundancy ``ENGLISH_REDUNDANCY``).

    You should get H_K ~= 88.4 bits and U ~= 27.6 characters — which is EXACTLY
    why week 1's attack worked: the message was hundreds of characters, far past
    U, so the key was uniquely pinned. Below ~28 chars the break is ambiguous.
    """
    # TODO: N = 26!  ;  H_K = entropy_bits(N)  ;  U = unicity_distance(H_K)
    raise NotImplementedError


# ---- Task 2: one-time pad — perfect secrecy, made concrete ------------------

def key_that_decrypts_to(ciphertext, decoy_plaintext):
    """Return the key under which ``ciphertext`` decrypts to ``decoy_plaintext``.

    This is the concrete face of perfect secrecy: for ANY plaintext of the right
    length there EXISTS a key making the ciphertext decrypt to it, so the
    ciphertext cannot betray the real message. The key is simply
    ``ciphertext XOR decoy_plaintext``.
    """
    # TODO: return xor(ciphertext, decoy_plaintext)
    raise NotImplementedError


# ---- Task 3: the two-time-pad break -----------------------------------------

def crib_drag(x, crib):
    """Slide ``crib`` (bytes) across ``x = c1 XOR c2`` (which equals p1 XOR p2).

    At each position i, XOR the crib against x[i:i+len(crib)]. Where the crib sits
    at its true location in one message, the OTHER message's text appears; return
    those readable hits as a list of ``(position, revealed_fragment_bytes)``, using
    ``printable_word`` to decide what counts as readable (lowercase + spaces).
    Noise elsewhere; real fragments at the true spots.
    """
    # TODO: for i in range(len(x) - len(crib)): frag = xor(x[i:i+len(crib)], crib)
    #       keep (i, frag) when printable_word(frag)
    raise NotImplementedError


def recover_other_plaintext(c1, c2, p1_known):
    """Given both ciphertexts and a full guess for p1, recover p2.

    The key never mattered — it cancels. Recover the keystream from the known
    plaintext (keystream = c1 XOR p1_known), then apply it to c2.
    Return the recovered p2 (bytes), truncated to len(p1_known).
    """
    # TODO: keystream = xor(c1, p1_known)  ;  return xor(c2, keystream)
    raise NotImplementedError


if __name__ == "__main__":
    # Smoke test: print what you've filled in so far.
    print(__doc__.splitlines()[0], "\n")
    try:
        H_K, U = unicity_for_substitution()
        print(f"  substitution: H(K) = {H_K:.1f} bits, unicity U = {U:.1f} chars")
    except NotImplementedError:
        print("  Task 1 (unicity) not implemented yet")

    try:
        from otp import load_ciphertext_pair
        c1, c2 = load_ciphertext_pair()
        x = xor(c1, c2)
        for crib in (b"please", b"target"):
            hits = crib_drag(x, crib)
            print(f"  crib {crib!r}: hits at {[i for i, _ in hits]}")
    except NotImplementedError:
        print("  Task 3 (crib-drag) not implemented yet")
