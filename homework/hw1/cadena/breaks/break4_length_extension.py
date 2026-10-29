#!/usr/bin/env python3
"""Break #4 — token_mac  (Tier 2, integrity/key misuse)

ASSUMPTION: "only someone with the secret can compute H(secret‖data), so the tag
authenticates" — forgetting that a Merkle-Damgard hash's output IS its full
internal state, so anyone holding one tag can RESUME hashing and forge a tag for
extended data without the secret.

CLASS: misuse (SHA-256-style compression is fine; the H(secret‖data) construction
is the error — the fix is HMAC).

BREAK: given (data, tag), we append '&role=admin' and compute the forged tag by
resuming the hash from the observed tag as its IV, replicating the hash's internal
padding. We don't know the secret. We also show we don't even need its exact
length — only its length MOD the 4-byte block matters. ORACLE: verify_token().
"""
import _pathfix  # noqa
from duel1_targets import issue_token, verify_token, _md_hash

tok = issue_token()
data, tag = tok["data"].encode(), tok["tag"]
print(f"captured token: data={data!r} tag={tag}")

ext = b"&role=admin"
valid_lengths = []
first_forge = None
for seclen in range(1, 20):                       # brute-force the (unknown) secret length
    pad = bytes((-(seclen + len(data))) % 4)      # replicate the MD padding
    forged_msg = data + pad + ext
    forged_tag = _md_hash(ext, iv=tag)            # RESUME from the captured tag
    if verify_token(forged_msg, forged_tag):
        valid_lengths.append(seclen)
        if first_forge is None:
            first_forge = (seclen, forged_msg, forged_tag)

sl, fmsg, ftag = first_forge
print(f"\nforgery validates for secret lengths {valid_lengths}")
print("  (only length MOD 4 matters -> we need the residue, not the exact length)")
print("\nRECOVERED ARTIFACT (forged admin token):")
print(f"  data = {fmsg!r}")
print(f"  tag  = {ftag}")
print(f"  verify_token(...) = {verify_token(fmsg, ftag)}  and 'role=admin' present = {b'role=admin' in fmsg}")
print("\nCONFIRMED: a valid token escalating role=user -> role=admin, forged without the secret.")
