"""Week 4 studio — REFERENCE SOLUTION (instructor-only).

A filled-in copy of ``starter.py``: identical function names and signatures, so
the *provided* ``test_rsa.py`` passes when this module is imported in place of
``starter``. Verify with ``studios/_verify_solutions.py`` (which aliases this file
to the name ``starter`` and runs the unmodified test).

Two attacks on RSA's *conditions* (never on the math) plus the fix:

  * ``batch_gcd_recover`` — the *Ps and Qs* attack (Heninger et al. 2012). Each
    modulus is fine IN ISOLATION ("infeasible to factor n"), but a weak RNG made
    two keys share a prime, and gcd(n_i, n_j) reveals it instantly — no factoring.
    A pairwise-GCD scan finds the one sharing pair and ``factor_from_shared`` turns
    the shared prime into d for BOTH keys. The guarantee holds per key and fails
    across the population. Naive scan is O(k^2) GCDs; the real internet-wide attack
    uses a product/remainder tree for near-linear time over millions of keys.
  * ``timing_attack`` — even with perfect keys, ``insecure_equal`` early-exits at
    the first mismatch, so its DURATION leaks how long a prefix matched. Position by
    position, we time all 256 candidate bytes (interleaved via ``time_guesses`` so
    CPU drift can't bias one) and keep the SLOWEST: the correct byte matches one
    extra position, i.e. one more AMPLIFY loop, before the early exit.
  * ``constant_time_equal`` — the fix. Examine EVERY byte (OR-accumulate the XOR
    differences), never early-exit, so duration carries no secret information. The
    identical attack then recovers nothing. The algorithm didn't change; the
    *condition* (constant time) did. (In real code: ``hmac.compare_digest``.)

Timing is noisy on purpose here; the tests use ~41 interleaved rounds so the
one-byte signal dominates jitter. DO NOT lower the round count to speed things up.

DO NOT ship to students — excluded via ``studios/.gitignore``. The teaching
walkthrough is ``solution.ipynb`` (imports this file rather than re-pasting it).
"""
import math

from rsa_lab import factor_from_shared, insecure_equal, make_oracle, time_guesses


# ---- Task 2: shared-factor (batch-GCD) recovery -----------------------------

def batch_gcd_recover(corpus):
    """Find every public key whose modulus shares a prime with another key, and
    recover its private exponent d.

    Return a dict ``{index: d}`` with one entry per vulnerable key. A key that
    shares no factor with any other must NOT appear.

    For each pair (i, j), ``math.gcd(n_i, n_j)`` is either 1 (safe) or the shared
    prime (both fall); ``factor_from_shared`` turns that prime into d.
    """
    keys = corpus["keys"]
    recovered = {}
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            n_i, n_j = keys[i]["n"], keys[j]["n"]
            g = math.gcd(n_i, n_j)
            if g != 1:
                # Both moduli fall: the shared prime divides both.
                recovered[i] = factor_from_shared(n_i, g, e=keys[i]["e"])
                recovered[j] = factor_from_shared(n_j, g, e=keys[j]["e"])
    return recovered


# ---- Task 3: timing side-channel attack -------------------------------------

def timing_attack(secret_len, oracle, rounds=41):
    """Recover the hidden secret one byte at a time by TIMING the oracle.

    For each position, try all 256 byte values with the already-known prefix; the
    correct byte makes the early-exit compare match one MORE position before
    returning, so it is *slower*. ``time_guesses`` interleaves the 256 candidates
    so CPU drift can't bias one; keep the slowest byte per position.
    """
    recovered = bytearray()
    for pos in range(secret_len):
        # Pad so every guess has the full secret length (the oracle rejects a
        # length mismatch before timing can say anything). Trailing bytes stay
        # constant across candidates, so only the byte at `pos` moves the signal.
        pad = bytes(secret_len - pos - 1)
        guesses = [bytes(recovered) + bytes([b]) + pad for b in range(256)]
        med = time_guesses(oracle, guesses, rounds)
        best = max(range(256), key=lambda b: med[b])
        recovered.append(best)
    return bytes(recovered)


# ---- Task 3 (fix): constant-time comparison ---------------------------------

def constant_time_equal(a, b):
    """The fix. Examine EVERY byte regardless of mismatches, so the duration does
    not depend on the secret. (In real code, call ``hmac.compare_digest``.)"""
    if len(a) != len(b):
        return False
    acc = 0
    for x, y in zip(a, b):
        acc |= x ^ y
    return acc == 0


if __name__ == "__main__":
    import os
    from rsa_lab import load_keys

    recovered = batch_gcd_recover(load_keys())
    print(f"batch-GCD recovered private keys for indices: {sorted(recovered)}")

    secret = os.urandom(2)
    got = timing_attack(len(secret), make_oracle(secret))
    print(f"timing attack: secret={secret.hex()} recovered={got.hex()} "
          f"match={got == secret}")
