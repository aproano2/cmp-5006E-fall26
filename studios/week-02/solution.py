"""Week 2 studio — REFERENCE SOLUTION (instructor-only).

A filled-in copy of ``starter.py``: identical function names and signatures, so
the *provided* ``test_otp.py`` passes when this module is imported in place of
``starter``. Verify with ``studios/_verify_solutions.py`` (which aliases this file
to the name ``starter`` and runs the unmodified test).

The four tasks, and why each is trivial *arithmetic* wrapped around a deep idea:

  * ``unicity_for_substitution`` — H(K)=log2(26!) ~= 88.4 bits, U=H(K)/D ~= 27.6
    chars. This is the number that *retroactively justifies* week 1: the message
    was hundreds of chars, far past U, so exactly one key fit. Below ~28 chars the
    break is ambiguous. Entropy alone did not save substitution; redundancy sank it.
  * ``key_that_decrypts_to`` — the constructive core of Shannon's perfect-secrecy
    proof: for ANY decoy of the right length a key EXISTS (key = ct XOR decoy) that
    makes the SAME ciphertext decrypt to it. The ciphertext therefore favours no
    plaintext — unbreakable against unbounded compute.
  * ``crib_drag`` / ``recover_other_plaintext`` — the misuse that collapses all of
    the above. Reuse the key and c1 XOR c2 = p1 XOR p2; the key cancels and never
    mattered. A guessed common word slid across that XOR surfaces the *other*
    message's text; one full plaintext recovers the keystream and hence the other.

DO NOT ship to students — excluded via ``studios/.gitignore``. The teaching
walkthrough is ``solution.ipynb`` (imports this file rather than re-pasting it).
"""
from otp import (xor, entropy_bits, unicity_distance, printable_word,
                 ENGLISH_REDUNDANCY, SCHEMES)
import math


# ---- Task 1: entropy & unicity ----------------------------------------------

def unicity_for_substitution():
    """Return (H_K, U) for the 26! substitution cipher.

    H_K is the key entropy in bits (``entropy_bits`` on the keyspace size 26!). U
    is the unicity distance in characters (``unicity_distance`` with the English
    redundancy). H_K ~= 88.4 bits and U ~= 27.6 chars — EXACTLY why week 1's attack
    worked: the message was hundreds of chars, far past U, so the key was uniquely
    pinned. Below ~28 chars the break is ambiguous.
    """
    N = math.factorial(26)
    H_K = entropy_bits(N)
    U = unicity_distance(H_K)
    return H_K, U


# ---- Task 2: one-time pad — perfect secrecy, made concrete ------------------

def key_that_decrypts_to(ciphertext, decoy_plaintext):
    """Return the key under which ``ciphertext`` decrypts to ``decoy_plaintext``.

    The concrete face of perfect secrecy: for ANY plaintext of the right length a
    key EXISTS making the ciphertext decrypt to it, so the ciphertext cannot betray
    the real message. That key is simply ``ciphertext XOR decoy_plaintext``.
    """
    return xor(ciphertext, decoy_plaintext)


# ---- Task 3: the two-time-pad break -----------------------------------------

def crib_drag(x, crib):
    """Slide ``crib`` (bytes) across ``x = c1 XOR c2`` (which equals p1 XOR p2).

    At each position i, XOR the crib against x[i:i+len(crib)]. Where the crib sits
    at its true location in one message, the OTHER message's text appears; return
    those readable hits as a list of ``(position, revealed_fragment_bytes)``, using
    ``printable_word`` to decide what counts as readable (lowercase + spaces).
    """
    hits = []
    for i in range(len(x) - len(crib) + 1):
        frag = xor(x[i:i + len(crib)], crib)
        if printable_word(frag):
            hits.append((i, frag))
    return hits


def recover_other_plaintext(c1, c2, p1_known):
    """Given both ciphertexts and a full guess for p1, recover p2.

    The key never mattered — it cancels. Recover the keystream from the known
    plaintext (keystream = c1 XOR p1_known), then apply it to c2. Return the
    recovered p2 (bytes), truncated to len(p1_known).
    """
    keystream = xor(c1, p1_known)
    return xor(c2[:len(p1_known)], keystream)


if __name__ == "__main__":
    print(__doc__.splitlines()[0], "\n")
    H_K, U = unicity_for_substitution()
    print(f"  substitution: H(K) = {H_K:.1f} bits, unicity U = {U:.1f} chars")
    from otp import load_ciphertext_pair
    c1, c2 = load_ciphertext_pair()
    x = xor(c1, c2)
    for crib in (b"please", b"target"):
        hits = crib_drag(x, crib)
        print(f"  crib {crib!r}: hits at {[i for i, _ in hits]}")
