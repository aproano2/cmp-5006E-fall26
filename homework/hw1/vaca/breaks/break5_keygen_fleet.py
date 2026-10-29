#!/usr/bin/env python3
"""Break #5 (Tier 2) -- shared-prime RSA recovered by batch GCD.

ASSUMPTION the designer made:
    "Each device generates its own RSA key, so the moduli are independent and
    factoring any one is hard." RSA's hardness assumes the two primes are drawn
    with real entropy. A device fleet that seeds its PRNG from a low-entropy
    boot state can draw the SAME prime on two devices.

THE FLAW:
    If n_i = p*q_i and n_j = p*q_j share the prime p, then gcd(n_i, n_j) = p --
    computable in milliseconds from the PUBLIC moduli alone. One GCD factors
    both keys; from p and n the private exponent follows.

PRIMITIVE BREAK or MISUSE?
    MISUSE. RSA and 65537 are fine; factoring a single well-generated modulus is
    hard. The deployment supplied correlated randomness, so the moduli are not
    independent and a cross-key GCD defeats them. (This is the real-world
    Heninger et al. / Lenstra et al. 2012 "Mining your Ps and Qs" result.)

METHOD / CONFIRMATION:
    Take all four public moduli, GCD every pair, and find the pair with a
    non-trivial common factor. That factor p splits both moduli: q = n / p.
    Compute phi = (p-1)(q-1) and d = e^{-1} mod phi. CONFIRM by a full
    encrypt/decrypt round trip, m -> m^e -> (m^e)^d == m, using only public data
    plus the recovered d. No private value was provided.

RELIABILITY:
    Deterministic; exact integer arithmetic, no probability involved.
"""

from __future__ import annotations

import math

from _common import targets

E = 65537


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def inv(a: int, m: int) -> int:
    return egcd(a, m)[1] % m


def main() -> None:
    devices = targets.keygen_fleet()  # PUBLIC moduli + exponents only
    moduli = {name: d["n"] for name, d in devices.items()}

    print("=== Break #5: shared-prime RSA (batch GCD) ===")
    for name, n in moduli.items():
        print(f"  {name}: n = {n}")

    names = list(moduli)
    shared = None
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            g = math.gcd(moduli[names[i]], moduli[names[j]])
            if g > 1:
                shared = (names[i], names[j], g)
                break
        if shared:
            break
    assert shared, "no shared prime found"
    a, b, p = shared
    print(f"\ngcd({a}, {b}) = {p}  <-- shared prime (non-trivial common factor)")

    # Recover the private key for the first device of the colliding pair.
    n = moduli[a]
    q = n // p
    assert p * q == n
    phi = (p - 1) * (q - 1)
    d = inv(E, phi)

    print(f"\nRECOVERED ARTIFACT (private key for {a}):")
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  d = {d}")

    # Confirm: round-trip a message through the public key and recovered private key.
    m = 1234567890 % n
    c = pow(m, E, n)
    back = pow(c, d, n)
    print(f"\n  round-trip check: dec(enc({m})) = {back}  -> {'OK' if back == m else 'FAIL'}")
    assert back == m
    print(f"\n[confirmed] recovered {a}'s private exponent by one GCD over the "
          f"public moduli; it correctly decrypts. {b} is factored by the same p.")


if __name__ == "__main__":
    main()
