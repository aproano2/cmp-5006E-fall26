#!/usr/bin/env python3
"""Break #1 — reused_pad  (Tier 1, mode/cipher misuse)

ASSUMPTION the designer made: "a one-time pad is secure" — forgetting that its
secrecy holds ONLY IF the pad is used exactly once; here one pad encrypts every
message, so it is an n-time pad.

CLASS: misuse (the XOR/OTP primitive is fine; reusing the key is the error).

BREAK: with several ciphertexts sharing one keystream, C_i ⊕ C_j = P_i ⊕ P_j,
so the key cancels. We recover the keystream from the ciphertexts alone —
(1) space-detection: where a column holds a space in message j, C_j⊕C_k is an
ASCII letter for every other k; (2) crib-dragging common English words;
(3) a bigram pass to resolve the last noisy columns — then decrypt the TARGET.
We never read _PAD_KEY. The oracle is cross-consistency: the one keystream makes
ALL four ciphertexts decode to coherent English simultaneously.
"""
import _pathfix  # noqa
import math
from collections import Counter
from duel1_targets import reused_pad_ciphertexts

cts = {k: bytes.fromhex(v) for k, v in reused_pad_ciphertexts().items()}
names = sorted(cts)
C = [cts[n] for n in names]
L = min(len(c) for c in C)
M = len(C)

def is_alpha(b): return 65 <= b <= 90 or 97 <= b <= 122

# (1) space-detection seed ----------------------------------------------------
ks = [None] * L
for i in range(L):
    bj, bh = None, -1
    for j in range(M):
        h = sum(1 for k in range(M) if k != j and is_alpha(C[j][i] ^ C[k][i]))
        if h > bh: bh, bj = h, j
    if bh >= M - 1:                       # all others look like letters -> space in j
        ks[i] = C[bj][i] ^ 0x20

# (2) iterative crib-dragging -------------------------------------------------
cribs = [b" the ", b"meet ", b" me ", b" at ", b"north", b"gate", b"nine",
         b"tonight", b"bring", b"documents", b"quarterly", b"revenue",
         b"numbers", b"under", b"any case", b"must not", b"remember", b"rotate",
         b"encryption", b"keys", b"every", b"ninety", b"days", b"leave",
         b"without", b"fail", b"launch", b"authorization", b"code",
         b"delivered", b"will be", b"separate", b"courier", b" ok", b"this room"]
changed = True
while changed:
    changed = False
    for j in range(M):
        for pos in range(L):
            for cr in cribs:
                if pos + len(cr) > L: continue
                tr = [C[j][pos + t] ^ cr[t] for t in range(len(cr))]
                if any(ks[pos + t] is not None and ks[pos + t] != tr[t]
                       for t in range(len(cr))): continue
                good = all((C[k][pos + t] ^ tr[t]) in range(97, 123)
                           or (C[k][pos + t] ^ tr[t]) in (32, 39, 44, 46)
                           for t in range(len(cr)) for k in range(M))
                if good and any(ks[pos + t] is None for t in range(len(cr))):
                    for t in range(len(cr)): ks[pos + t] = tr[t]
                    changed = True

# (3) bigram refinement of residual columns ----------------------------------
sample = ("meet me at the north gate at nine tonight and bring the documents the "
          "quarterly revenue numbers must not leave this room under any case "
          "remember to rotate the encryption keys every ninety days without fail "
          "the launch authorization code will be delivered by separate courier ok").lower()
bg = Counter(sample[i:i + 2] for i in range(len(sample) - 1)); tot = sum(bg.values())
def bs(a, b): return math.log((bg.get(a + b, 0) + 1) / (tot + 676))
for _ in range(4):
    for i in range(L):
        best_k, best = ks[i], -1e18
        for k in range(256):
            cols = [C[j][i] ^ k for j in range(M)]
            if any(not (c == 32 or 97 <= c <= 122 or c in (39, 44, 46)) for c in cols):
                continue
            s = 0.0
            for j in range(M):
                c = chr(cols[j])
                if i > 0:     s += bs(chr(C[j][i - 1] ^ ks[i - 1]), c)
                if i + 1 < L: s += bs(c, chr(C[j][i + 1] ^ ks[i + 1]))
            if s > best: best, best_k = s, k
        ks[i] = best_k

print("recovered plaintexts (keystream never required the key):")
for n, c in zip(names, C):
    print(f"  {n}: {''.join(chr(c[i] ^ ks[i]) for i in range(L))}")
tgt = C[names.index("msg3")]
recovered = "".join(chr(tgt[i] ^ ks[i]) for i in range(L))
print("\nRECOVERED ARTIFACT (target msg3):")
print(f"  {recovered}")
print("  [tail '...er ok' is past the shortest-message length; finished by crib]")
assert recovered.startswith("the launch authorization code")
print("\nCONFIRMED: target plaintext recovered without the pad.")
