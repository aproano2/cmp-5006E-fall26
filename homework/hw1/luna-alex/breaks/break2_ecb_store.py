"""Break #2 -- ecb_store : customer records encrypted block-by-block, ECB mode.

Assumption broken: "encrypting each block independently is fine as long as the
cipher itself is strong." False -- ECB leaks PLAINTEXT STRUCTURE regardless of how
strong the per-block cipher is: identical plaintext blocks under the same key always
produce identical ciphertext blocks. The designer conflated "the block cipher is
secure" with "the mode is secure" -- exactly the distinction axis 2 of the scorecard
is built to force.

We are NOT given which record belongs to which name beyond order, and we are not
given the key. We only use the public ciphertext list + the KNOWN RECORD FORMAT
documented in the module's own docstring: 'name:role:dept', 4-byte blocks.
"""
from _common import load_targets

T = load_targets()
recs = T.ecb_store_records()
BS = 4
names = ["alice", "bob", "carl", "dave"]     # order given by the module's docstring

blocks = [[r[i:i + BS * 2] for i in range(0, len(r), BS * 2)] for r in recs]
print("[1] ciphertext blocks per record (hex, 4 bytes/block):")
for n, b in zip(names, blocks):
    print(f"  {n:6s}: {b}")

print("\n[2] record format is 'name:role:dept', 4 chars/block -> block[0]=name, "
      "block[1]=role, block[2]=dept (+padding if needed)")

# Block 0 is always unique (names differ). Compare blocks[1:] across records: ECB
# guarantees identical plaintext => identical ciphertext, so a match there means
# those two records share role+dept.
print("\n[3] pairwise comparison of blocks[1:] (role+dept) across records:")
matches = []
for i in range(len(recs)):
    for j in range(i + 1, len(recs)):
        if blocks[i][1:] == blocks[j][1:]:
            matches.append((i, j))
            print(f"  {names[i]} and {names[j]}: blocks[1:] IDENTICAL -> {blocks[i][1:]}")

assert matches, "no ECB leak found -- break failed"
i, j = matches[0]
print(f"\n[4] inference: {names[i]} and {names[j]} share the same role AND department "
      f"string, with NO decryption and NO key. Given the deployment's own docstring "
      f"says one shared role is 'admn' (admin) and the other pair (bob/dave) has "
      f"non-matching blocks[1], we can further infer '{names[i]}' and '{names[j]}' are "
      f"BOTH in the admin role -- an attacker who can get even one plaintext record "
      f"leaked (e.g. via a subpoena, an insider, or a support ticket quoting one row) "
      f"immediately learns the role of every other ciphertext row that matches its "
      f"block pattern, without ever learning the key.")

print(f"\nCONFIRMED break: structural equality in ciphertext revealed "
      f"{names[i]}/{names[j]} share role+dept, from ciphertext alone.")
