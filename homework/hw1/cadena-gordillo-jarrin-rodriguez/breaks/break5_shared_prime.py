#!/usr/bin/env python3
"""Break #5 — keygen_fleet  (Tier 2, integrity/key misuse)

ASSUMPTION: "RSA-2048 is unbreakable because factoring is hard" — forgetting the
guarantee is conditional on p, q being drawn from GOOD entropy, INDEPENDENTLY;
a low-entropy fleet reuses a prime across devices.

CLASS: misuse (RSA math is fine; the RNG/entropy condition is the error).

BREAK: you never factor a strong modulus. If two public moduli share a prime,
gcd(n_i, n_j) returns it INSTANTLY. From the shared prime p we get q = n/p,
phi = (p-1)(q-1), and the private exponent d = e^{-1} mod phi. ORACLE: an
encrypt/decrypt roundtrip under the recovered d. (This is Heninger et al. 2012,
'Mining Your Ps and Qs'.) No private data is given.
"""
import _pathfix  # noqa
import math
from duel1_targets import keygen_fleet

def egcd(a, b):
    if b == 0: return a, 1, 0
    g, x, y = egcd(b, a % b); return g, y, x - (a // b) * y
def inv(a, m): return egcd(a, m)[1] % m

dev = keygen_fleet()                               # public moduli + exponents only
ns = {k: v["n"] for k, v in dev.items()}
e = 65537
print("public moduli (these look independent):")
for k, n in ns.items(): print(f"  {k}: n={n}")

# pairwise GCD — O(k^2); for a real fleet use batch-GCD for near-linear scaling.
found = None
keys = list(ns)
for i in range(len(keys)):
    for j in range(i + 1, len(keys)):
        g = math.gcd(ns[keys[i]], ns[keys[j]])
        if g > 1:
            found = (keys[i], keys[j], g)
assert found, "no shared prime found"
a, b, p = found
n = ns[a]; q = n // p
phi = (p - 1) * (q - 1); d = inv(e, phi)

print(f"\nshared prime between {a} and {b}:\n  p = {p}")
print(f"\nRECOVERED ARTIFACT (private key of {a}):")
print(f"  p = {p}\n  q = {q}\n  d = {d}")
m = 0xC0FFEE
assert pow(pow(m, e, n), d, n) == m
print(f"\n  roundtrip (m^e)^d mod n == m : {pow(pow(m, e, n), d, n) == m}")
print("\nCONFIRMED: private key recovered by one GCD — no hard factoring.")
print("Cost: pairwise is O(k^2) GCDs; batch-GCD is ~O(k log^2 k) for large fleets.")
