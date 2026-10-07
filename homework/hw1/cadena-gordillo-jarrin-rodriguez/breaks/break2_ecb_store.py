#!/usr/bin/env python3
"""Break #2 — ecb_store  (Tier 1, mode/cipher misuse)

ASSUMPTION: "AES is strong, so AES-ECB protects the records" — forgetting that
ECB encrypts each block independently, so identical plaintext blocks map to
identical ciphertext blocks and structure leaks.

CLASS: misuse (the block cipher is fine; ECB mode is the error).

BREAK: no key needed. Split each ciphertext into blocks; records that share the
'role:dept' fields produce identical trailing blocks. The repetition itself is
the leak — we infer which employees share a role ('admn') purely from matching
ciphertext blocks. Artifact recovered: the set of admin employees.
"""
import _pathfix  # noqa
from duel1_targets import ecb_store_records

recs = ecb_store_records()                      # hex strings, no key
BS_HEX = 8                                        # 4-byte block -> 8 hex chars
labels = ["record0", "record1", "record2", "record3"]

def blocks(hexstr):
    return [hexstr[i:i + BS_HEX] for i in range(0, len(hexstr), BS_HEX)]

B = [blocks(r) for r in recs]
print("ciphertext blocks per record (first block = name, rest = role/dept):")
for lab, bl in zip(labels, B):
    print(f"  {lab}: {bl}")

# Group records by their trailing (role+dept) blocks.
from collections import defaultdict
groups = defaultdict(list)
for lab, bl in zip(labels, B):
    groups[tuple(bl[1:])].append(lab)

print("\nrecords sharing identical role+dept ciphertext blocks:")
shared = [g for g in groups.values() if len(g) > 1]
for g in shared:
    print(f"  {g}  <- same role & dept (ECB leaked it)")

# The two matching records are the two 'admn' employees (record0 & record2).
assert any(set(g) == {"record0", "record2"} for g in shared)
print("\nRECOVERED ARTIFACT: record0 and record2 share a role+dept — they are the")
print("two 'admn:engr' employees. Inferred from block repetition, no key used.")
print("\nCONFIRMED: structure/role leaked via ECB block equality.")
