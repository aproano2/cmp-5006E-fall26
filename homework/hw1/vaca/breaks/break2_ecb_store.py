#!/usr/bin/env python3
"""Break #2 (Tier 1) -- ECB structure leakage.

ASSUMPTION the designer made:
    "The records are encrypted, so an attacker learns nothing about their
    contents." ECB encrypts each block independently and deterministically, so
    equal plaintext blocks become equal ciphertext blocks -- encryption hides
    the bytes but not the *pattern* of repetition.

THE FLAW:
    Each record is `name:role:dept` cut into 4-byte blocks. Two employees with
    the same role (and dept) therefore share the corresponding ciphertext
    blocks. The repetition is visible with no key.

PRIMITIVE BREAK or MISUSE?
    MISUSE. The block cipher itself is treated as a black box; nothing about it
    is broken. The failure is the *mode*: ECB leaks equality across blocks.
    CBC/CTR/GCM with a fresh IV/nonce would not.

METHOD / CONFIRMATION:
    Cut every ciphertext into 4-byte blocks and compare. With the published
    schema `name:role:dept` (4-byte blocks), the role+dept fields occupy blocks
    1..3 and the name occupies block 0. Records whose blocks 1..3 match share
    role AND dept; records whose block 1 matches share the role. This partition
    is recovered with ZERO key knowledge and is confirmed by exact block
    equality. Mapping a class to the literal string "admn" needs exactly one
    labelled record (a crib -- e.g. one account the attacker already knows, or
    their own); ECB then propagates that label to everyone in the class.
"""

from __future__ import annotations

from _common import targets

BS = 4  # block size (bytes); 1 block == 8 hex chars


def blocks_of(hex_record: str) -> list[str]:
    return [hex_record[i:i + BS * 2] for i in range(0, len(hex_record), BS * 2)]


def main() -> None:
    records = targets.ecb_store_records()
    # Published schema -> block 0 is the name, blocks 1..3 are role+dept.
    name_prefixes = ["alic", "bob0", "carl", "dave"]

    print("=== Break #2: ECB structure leakage ===")
    print("schema: name:role:dept, 4-byte blocks -> block0=name, blocks1-3=role+dept\n")
    grid = [blocks_of(r) for r in records]
    for i, bl in enumerate(grid):
        print(f"  record {i} ({name_prefixes[i]}...): {bl}")

    # role+dept == blocks 1..3; role prefix == block 1.
    roledept = {}
    rolepfx = {}
    for i, bl in enumerate(grid):
        roledept.setdefault(tuple(bl[1:]), []).append(i)
        rolepfx.setdefault(bl[1], []).append(i)

    print("\nclasses sharing BOTH role and dept (blocks 1-3 identical):")
    for key, members in roledept.items():
        if len(members) > 1:
            print(f"  records {members} -> identical role+dept  (key blocks {list(key)})")
    print("classes sharing the role field (block 1 identical):")
    for key, members in rolepfx.items():
        if len(members) > 1:
            print(f"  records {members} -> identical role        (role block {key})")

    # One crib (a single labelled record) turns the leak into named facts.
    crib = {0: ("admn", "engr")}  # e.g. learned from an org chart / own account
    print("\nRECOVERED ARTIFACT (with one crib: record 0 == admn:engr):")
    admins = [i for i, bl in enumerate(grid) if bl[1:] == grid[0][1:]]
    for i in admins:
        print(f"  record {i} ({name_prefixes[i]}...) is admn in engr "
              f"-- exposed with no key, purely from matching ciphertext blocks")
    assert admins == [0, 2], "expected records 0 and 2 to be the admin class"
    assert grid[0][1:] == grid[2][1:] and grid[0][1:] != grid[1][1:]
    print("\n[confirmed] ECB leaked that records 0 and 2 are the same role+dept; "
          "one labelled record names them both as admins.")


if __name__ == "__main__":
    main()
