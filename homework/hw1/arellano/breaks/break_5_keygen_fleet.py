#!/usr/bin/env python3
"""Break #5 - shared RSA prime across a low-entropy device fleet (batch-GCD).

Assumption the designer made: "each device generates an independent RSA keypair, so
the moduli are unrelated." False when devices boot with low entropy: two of them
drew the same prime. RSA's hardness assumes n is hard to factor - but gcd(n_i, n_j)
is trivial, and if it is > 1 it hands you a shared prime, factoring BOTH moduli.
The primitive (factoring) is not broken; the key generation is.

With the public moduli only, we take pairwise GCDs (the fleet-scale version is a
product-tree batch-GCD), factor the colliding pair, and reconstruct a private key.

Confirmation: a decrypt/sign round trip under the recovered private exponent.
"""
import math

from _targets import targets

E = 65537


def egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def inv(a: int, m: int) -> int:
    return egcd(a, m)[1] % m


def main() -> None:
    dev = targets.keygen_fleet()                 # public moduli/exponents only
    ns = {k: v["n"] for k, v in dev.items()}
    print("== Break #5: shared-prime batch-GCD ==\n")
    for k, n in ns.items():
        print(f"  {k}: n has {n.bit_length()} bits")

    # Pairwise GCD (batch-GCD for a real fleet). Find the colliding pair.
    names = list(ns)
    victim = shared = None
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            g = math.gcd(ns[names[i]], ns[names[j]])
            if g > 1:
                victim, co_victim, shared = names[i], names[j], g
                print(f"\ngcd({names[i]}, {names[j]}) > 1  ->  shared prime found")
                print(f"  shared p = {shared}")
                break
        if shared:
            break
    assert shared, "no shared prime"

    # Factor the victim modulus and rebuild its private key.
    n = ns[victim]
    p = shared
    q = n // p
    assert p * q == n
    phi = (p - 1) * (q - 1)
    d = inv(E, phi)
    print(f"\nRecovered private key for {victim}:")
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  d = {d}")

    # Confirm: decrypt a ciphertext and verify a signature round trip.
    m = 42
    c = pow(m, E, n)
    dec = pow(c, d, n)
    sig = pow(m, d, n)
    ver = pow(sig, E, n)
    ok = dec == m and ver == m and co_victim is not None
    print(f"\n  decrypt((42^e))    -> {dec}")
    print(f"  verify(sign(42))   -> {ver}")
    print(f"\n[{'CONFIRMED' if ok else 'FAILED'}] private key recovered from public "
          f"moduli alone; {co_victim} is factored the same way.")


if __name__ == "__main__":
    main()
