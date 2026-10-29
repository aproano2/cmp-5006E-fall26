"""Break #5 -- keygen_fleet : RSA keypairs generated on a low-entropy device fleet.

Assumption broken: "each device calls a cryptographically-approved prime generator,
so each key is independent." False IF the entropy source is shared/weak at boot --
a well-documented real-world failure class (Heninger et al. 2012, "Mining Your Ps
and Qs"; also the 2008 Debian OpenSSL PRNG incident). Two devices here produced the
SAME prime factor. This is a MISUSE of RSA (bad randomness), not a break of RSA
itself -- RSA's hardness assumption (factoring n=pq) is untouched; the *generation*
process violated RSA's precondition that p, q be independently random.

We are given ONLY the public (n, e) pairs for 4 devices -- never p, q, or d.
"""
import math

from _common import load_targets

T = load_targets()
devices = T.keygen_fleet()
print("[1] public moduli:")
for k, v in devices.items():
    print(f"  {k}: n={v['n']} ({v['n'].bit_length()} bits), e={v['e']}")

# ---- batch-GCD: for ANY two RSA moduli that share a prime factor, gcd(n_i, n_j)
# directly reveals that factor. This scales to "batch" GCD across many keys in
# practice; here we just do the pairwise O(n^2) version since there are only 4. ----
keys = list(devices)
shared = None
for i in range(len(keys)):
    for j in range(i + 1, len(keys)):
        g = math.gcd(devices[keys[i]]["n"], devices[keys[j]]["n"])
        if g > 1:
            shared = (keys[i], keys[j], g)
            print(f"\n[2] gcd({keys[i]}.n, {keys[j]}.n) = {g}  -- SHARED PRIME FOUND")

assert shared, "no shared prime found -- break failed"
di, dj, p = shared
n = devices[di]["n"]
q = n // p
assert p * q == n
print(f"[3] factored {di}.n = p * q:\n    p = {p}\n    q = {q}")

# ---- recover the private exponent -----------------------------------------------
def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y

e = devices[di]["e"]
phi = (p - 1) * (q - 1)
g, x, _ = egcd(e, phi)
assert g == 1, "e not invertible mod phi(n) -- unexpected"
d = x % phi
print(f"[4] recovered private exponent d for {di} (phi(n) known from p,q)")

# ---- confirm: encrypt a message with the PUBLIC key, decrypt with the recovered
# PRIVATE key, and recover it. This is the oracle-confirmed artifact. -------------
m = 1337
c = pow(m, e, n)
m2 = pow(c, d, n)
print(f"[5] confirm: pow(pow({m}, e, n), d, n) = {m2}  (expected {m})")
assert m2 == m
print(f"\nCONFIRMED: recovered a full RSA private key for {di} from public moduli "
      f"alone (batch-GCD), and verified decryption. {dj} shares the same exposure.")
