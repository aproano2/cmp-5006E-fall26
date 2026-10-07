#!/usr/bin/env python3
"""Break #3 — ctr_log  (Tier 1, mode/cipher misuse)

ASSUMPTION: "AES-CTR is a strong modern mode, so the audit log is safe" —
forgetting CTR's guarantee is conditional on a UNIQUE nonce per message; here one
nonce is reused for every entry, so entries share a keystream and
C_i ⊕ C_j = P_i ⊕ P_j — the week-2 two-time pad inside a modern mode.

CLASS: misuse (AES/CTR are fine; nonce reuse is the error).

BREAK: the two benign entries follow the deployment's fixed log format, so an
analyst can reconstruct them. Treating each as a full crib recovers the shared
keystream; the ORACLE is cross-consistency — the keystream from one benign line
correctly decrypts the OTHER benign line. Applying that keystream to the TARGET
ciphertext yields the admin/export line. _CTR_KEY and _CTR_NONCE never seen.
"""
import _pathfix  # noqa
from duel1_targets import ctr_log_entries

cts = {k: bytes.fromhex(v) for k, v in ctr_log_entries().items()}
C = [cts["log0"], cts["log1"], cts["log2"]]      # log2 is the TARGET

# Known-format benign lines (the two non-target entries an analyst can guess).
benign = [b"2025-03-01 12:00 user=alice action=login result=success from=10.0.0.5",
          b"2025-03-01 12:04 user=bob00 action=login result=failure from=10.0.0.9"]

def keystream_from(guess, ct):
    return bytes(g ^ c for g, c in zip(guess, ct[:len(guess)]))

ks = None
for gi, g in enumerate(benign):
    cand = keystream_from(g, C[gi])
    other = 1 - gi
    dec_other = bytes(cand[i] ^ C[other][i] for i in range(min(len(cand), len(C[other]))))
    if dec_other[:40] == benign[other][:40]:     # ORACLE: decrypts the OTHER line
        ks = cand
        print(f"keystream recovered from benign {['log0','log1'][gi]}; "
              f"it correctly decrypts {['log0','log1'][other]} -> confirmed.")
        break
assert ks is not None, "guessed benign lines did not match the keystream"

target = bytes(ks[i] ^ C[2][i] for i in range(min(len(ks), len(C[2]))))
print("\nRECOVERED ARTIFACT (target log2):")
print(f"  {target.decode(errors='replace')}")
print("  [final IP octet is 1 char past the shortest line; a single digit, crib-filled]")
assert b"user=admin" in target and b"action=export" in target
print("\nCONFIRMED: the admin/export audit entry recovered via nonce reuse.")
