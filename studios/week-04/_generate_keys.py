"""Key-corpus generator for the week-4 studio. Run once at build time; commits
``keys.json`` alongside. Deterministic (SEED=1, the same seed as the notebook).

The first three primes drawn (``shared``, ``p1``, ``p2``) reproduce the
notebook's shared-factor demo EXACTLY, so ``n1 = shared*p1`` and
``n2 = shared*p2`` here equal the two moduli printed in
``notebooks/week-04-asymmetric-sidechannels.ipynb``. The rest of the corpus is
independent keys drawn from the continuing RNG stream (no shared factors).

The point of the studio is that any ONE key looks fine; the flaw is only visible
across the *population* (pairwise GCD). So the corpus hides the vulnerable pair
among safe keys — students must find it with a batch-GCD scan.
"""
import json
import math
import random
from pathlib import Path

SEED = 1
E = 65537
PRIME_BITS = 64
N_SAFE = 6          # independent (non-sharing) keys mixed in with the bad pair


def gen_prime(bits, rng):
    """Fermat-test prime generation — identical to the notebook. Fine for a demo,
    NOT production keygen."""
    while True:
        x = rng.getrandbits(bits) | 1 | (1 << (bits - 1))
        if all(x % sp for sp in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31)) \
                and pow(2, x - 1, x) == 1:
            return x


def _usable(pa, pb):
    """e must be invertible mod phi for a private key to exist."""
    phi = (pa - 1) * (pb - 1)
    return math.gcd(E, phi) == 1


def main():
    rng = random.Random(SEED)

    # --- the vulnerable pair: reproduces the notebook's values exactly ----------
    shared = gen_prime(PRIME_BITS, rng)     # a prime reused because entropy was low
    p1 = gen_prime(PRIME_BITS, rng)
    p2 = gen_prime(PRIME_BITS, rng)
    n1 = shared * p1                        # victim A
    n2 = shared * p2                        # victim B — looks unrelated

    # --- independent, safe keys from the continuing RNG stream ------------------
    safe = []
    while len(safe) < N_SAFE:
        pa = gen_prime(PRIME_BITS, rng)
        pb = gen_prime(PRIME_BITS, rng)
        if pa == pb or not _usable(pa, pb):
            continue
        safe.append(pa * pb)

    # Interleave so the bad pair is not adjacent: bad, safe, safe, safe, bad, ...
    moduli = [n1, safe[0], safe[1], safe[2], n2, safe[3], safe[4], safe[5]]

    # Sanity: exactly one sharing pair in the whole corpus.
    shares = [(i, j) for i in range(len(moduli)) for j in range(i + 1, len(moduli))
              if math.gcd(moduli[i], moduli[j]) != 1]
    assert shares == [(0, 4)], f"expected one sharing pair (0,4), got {shares}"

    out = {
        "seed": SEED,
        "e": E,
        "prime_bits": PRIME_BITS,
        "note": ("Public keys only. Exactly one pair shares a prime (weak-RNG "
                 "simulation). Any single key looks fine; the flaw is a "
                 "population-level property. Do not peek at _ground_truth from "
                 "starter.py — recover it."),
        "keys": [{"n": n, "e": E} for n in moduli],
        "_ground_truth": {
            "vulnerable_indices": [0, 4],
            "shared_prime": shared,
        },
    }
    dest = Path(__file__).with_name("keys.json")
    dest.write_text(json.dumps(out, indent=2))
    print(f"wrote {dest} — {len(moduli)} public keys, "
          f"vulnerable pair at indices {out['_ground_truth']['vulnerable_indices']}")


if __name__ == "__main__":
    main()
