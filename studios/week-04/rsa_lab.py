"""Week 4 studio — the shared crypto engine (GIVEN to you; do not modify).

This is the RSA + attack scaffolding from the Session-A notebook
(``notebooks/week-04-asymmetric-sidechannels.ipynb``), unchanged. Week 4 is
about the *attacks* — bad entropy (shared factors) and timing leaks — not about
re-implementing RSA. So keygen/encrypt/decrypt, prime generation, and the
timing oracle are provided here. You write the attacks and the fix in
``starter.py``.

Pure Python, no ``seclab`` import, no lab target, no Docker (crypto week).

Contents:
    egcd / modinv               number theory (extended Euclid, modular inverse)
    gen_prime                   Fermat-test prime generation (demo only)
    rsa_keygen / encrypt / decrypt   textbook RSA
    factor_from_shared          given a shared prime, derive the private key
    load_keys                   the public-key corpus (keys.json)
    insecure_equal              early-exit compare — LEAKS timing (the target)
    make_oracle / median_time   build + time a comparison oracle for the attack
"""
import json
import math
import random
import statistics
import time
from pathlib import Path

# ---- number theory (verbatim from the notebook) ----------------------------

def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("no inverse")
    return x % m


# ---- RSA by hand (verbatim from the notebook) -------------------------------

def gen_prime(bits, rng):
    """Fermat test, fine for a demo (NOT production keygen)."""
    while True:
        x = rng.getrandbits(bits) | 1 | (1 << (bits - 1))
        if all(x % sp for sp in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31)) \
                and pow(2, x - 1, x) == 1:
            return x


def rsa_keygen(p, q, e=65537):
    """Return (public, private) = ((n, e), (n, d)). d needs phi; phi needs the
    factorization — that is the whole reduction."""
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return (n, e), (n, d)


def encrypt(m, public):
    n, e = public
    return pow(m, e, n)


def decrypt(c, private):
    n, d = private
    return pow(c, d, n)


def factor_from_shared(n, shared, e=65537):
    """Once a shared prime is known, factoring n is division: the other prime is
    n // shared. From (p, q) recover phi and the private exponent d."""
    other = n // shared
    assert shared * other == n, "shared is not actually a factor of n"
    phi = (shared - 1) * (other - 1)
    return modinv(e, phi)          # the private exponent d


# ---- the public-key corpus --------------------------------------------------

def load_keys(path=None):
    """Load the provided public-key corpus. Returns the parsed dict; the list of
    public keys is under ``["keys"]`` as [{"n":..., "e":...}, ...].

    Exactly one pair of moduli shares a prime (a weak-RNG simulation). Any single
    key looks fine — the flaw is only visible across the population."""
    path = Path(path or Path(__file__).with_name("keys.json"))
    return json.loads(path.read_text())


# ---- timing side channel (verbatim from the notebook) -----------------------

AMPLIFY = 12000         # per-byte busy-work so per-position timing is measurable
# The notebook uses 3000; the studio raises it so the median-over-trials signal
# is stable under nbclient/CI noise (the correct byte matches one extra position,
# i.e. exactly one more AMPLIFY loop — make that delta dominate jitter).


def insecure_equal(a, b):
    """Early-exit compare: returns at the first mismatch. Timing leaks prefix
    length — this is the vulnerability you attack in Task 3."""
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
        for _ in range(AMPLIFY):    # amplify per-byte work so timing is measurable
            pass
    return True


def make_oracle(secret, compare=insecure_equal):
    """An oracle the attacker can *call* but not read: it compares its argument
    against the hidden ``secret`` using ``compare`` and returns only True/False.
    The timing of the call is the side channel."""
    def oracle(guess):
        return compare(secret, guess)
    return oracle


def median_time(oracle, guess, trials=41):
    """Median wall-clock time of ``oracle(guess)`` over ``trials`` repeats.
    Timing is noisy; the median over repeats is what makes the signal stable.

    (Kept from the notebook. For a full candidate scan prefer ``time_guesses``,
    which interleaves candidates so a slow window can't bias one of them.)"""
    samples = []
    for _ in range(trials):
        t0 = time.perf_counter()
        oracle(guess)
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples)


def time_guesses(oracle, guesses, rounds=41):
    """Robustly time a *batch* of guesses. Returns a list of median times, one
    per guess (same order as ``guesses``).

    Why not just call ``median_time`` 256 times in a row? Timing is noisy, and
    worse, the noise is not independent: CPU frequency scaling and scheduler
    preemption drift over the seconds it takes to scan 256 candidates, so the
    candidates measured *last* look systematically slower. That drift can drown
    the ~one-byte signal. The fix is to INTERLEAVE: each round times every
    candidate once, round-robin, so any slow window hits all candidates about
    equally and cancels out in the per-candidate median. ~41 rounds is enough
    for a stable signal here."""
    samples = [[] for _ in guesses]
    for _ in range(rounds):
        for i, g in enumerate(guesses):
            t0 = time.perf_counter()
            oracle(g)
            samples[i].append(time.perf_counter() - t0)
    return [statistics.median(s) for s in samples]


if __name__ == "__main__":
    # RSA by hand with tiny primes — every number is inspectable.
    (n, e), (n2, d) = rsa_keygen(61, 53, e=17)
    print(f"public key : (n={n}, e={e})")
    print(f"private key: (d={d})   [derived from the secret factorization]")
    m = 42
    c = encrypt(m, (n, e))
    print(f"encrypt(42) = {c}   decrypt = {decrypt(c, (n, d))}")

    # The shared-factor corpus.
    corpus = load_keys()
    print(f"\ncorpus: {len(corpus['keys'])} public keys, e={corpus['e']}")
