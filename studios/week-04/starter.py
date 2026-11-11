"""Week 4 studio — starter (attacks on RSA's *conditions*, not its math).

Fill in the three functions below. Then run ``python3 test_rsa.py``.
All required tests must pass, INCLUDING the guarantee tests:

  * ``test_shared_factor_recovers_both_keys`` — the two keys that share a prime
    are BOTH recovered by a batch-GCD scan. Each key is fine *in isolation*; the
    guarantee ("infeasible to factor n") fails across a *population*. Watching
    that failure is the point of the week.
  * ``test_timing_leak_vs_constant_time`` — your timing attack recovers a secret
    through the early-exit compare, and a constant-time compare defeats it.

You never factor a strong modulus. You attack the *conditions* RSA depends on:
good independent entropy, and constant-time secret handling.
"""
import math

from rsa_lab import factor_from_shared, insecure_equal, make_oracle, time_guesses


# ---- Task 2: shared-factor (batch-GCD) recovery -----------------------------

def batch_gcd_recover(corpus):
    """Find every public key whose modulus shares a prime with another key, and
    recover its private exponent d.

    ``corpus`` is the dict from ``rsa_lab.load_keys()``; the public keys are in
    ``corpus["keys"]`` as [{"n":..., "e":...}, ...].

    Return a dict ``{index: d}`` with one entry per vulnerable key. A key that
    shares no factor with any other key must NOT appear.

    Hint: for each pair (i, j), ``math.gcd(n_i, n_j)`` is either 1 (safe) or the
    shared prime (both fall). Given the shared prime, ``factor_from_shared`` in
    rsa_lab turns it into d.
    """
    keys = corpus["keys"]
    recovered = {}
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            n_i, n_j = keys[i]["n"], keys[j]["n"]
            shared = math.gcd(n_i, n_j)
            if shared != 1:
                recovered[i] = factor_from_shared(n_i, shared, keys[i]["e"])
                recovered[j] = factor_from_shared(n_j, shared, keys[j]["e"])
    return recovered


# ---- Task 3: timing side-channel attack -------------------------------------

def timing_attack(secret_len, oracle, rounds=41):
    """Recover the hidden secret one byte at a time by TIMING the oracle.

    ``oracle`` is a callable ``oracle(guess_bytes) -> bool`` built by
    ``rsa_lab.make_oracle(secret)``. You may call it and time it, but you may not
    read the secret. Return the recovered ``bytes``.

    Strategy: for each position, try all 256 byte values with the already-known
    prefix; the correct byte makes the early-exit compare match one MORE position
    before returning, so it is *slower*. Time all 256 candidates together with
    ``time_guesses(oracle, guesses, rounds)`` (it interleaves them so drift can't
    bias one candidate), then keep the slowest byte.
    """
    recovered = bytearray()
    for pos in range(secret_len):
        padding = bytes(secret_len - pos - 1)
        guesses = [bytes(recovered) + bytes([b]) + padding for b in range(256)]
        medians = time_guesses(oracle, guesses, rounds)
        best_byte = max(range(256), key=lambda b: medians[b])
        recovered.append(best_byte)
    return bytes(recovered)


# ---- Task 3 (fix): constant-time comparison ---------------------------------

def constant_time_equal(a, b):
    """The fix. Examine EVERY byte regardless of mismatches, so the duration does
    not depend on the secret. (In real code, call ``hmac.compare_digest``.)"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


if __name__ == "__main__":
    import os
    from rsa_lab import load_keys

    # Task 2 smoke test.
    try:
        recovered = batch_gcd_recover(load_keys())
        print(f"batch-GCD recovered private keys for indices: "
              f"{sorted(recovered)}")
    except NotImplementedError:
        print("batch_gcd_recover: not implemented yet")

    # Task 3 smoke test.
    secret = os.urandom(2)
    try:
        got = timing_attack(len(secret), make_oracle(secret))
        print(f"timing attack: secret={secret.hex()} recovered={got.hex()} "
              f"match={got == secret}")
    except NotImplementedError:
        print("timing_attack: not implemented yet")
