#!/usr/bin/env python3
"""Break #2 - ECB mode leaks record structure.

Assumption the designer made: "a strong block cipher makes the stored records
confidential." False under ECB: the mode is deterministic and stateless, so equal
plaintext blocks always map to equal ciphertext blocks. The cipher is never
broken; the MODE leaks equality.

Records are 'name:role:dept' padded to 4-byte blocks. Block 0 holds the name;
blocks 1-3 hold ':role:dept'. Two records whose blocks 1-3 are byte-identical share
the same (role, dept). We never decrypt anything - we only compare blocks.

Confirmation: the equivalence classes of (role,dept), and the inference that the
record sharing a known admin's role+dept blocks is itself an admin.
"""
from _targets import targets

BS_HEX = 8  # 4-byte block == 8 hex chars


def blocks(hexrec: str) -> list[str]:
    return [hexrec[i:i + BS_HEX] for i in range(0, len(hexrec), BS_HEX)]


def main() -> None:
    recs = targets.ecb_store_records()   # list of hex ciphertexts, the only input
    print("== Break #2: ECB structure leakage ==\n")

    decomposed = [blocks(r) for r in recs]
    print("Per-record ciphertext blocks (block0=name, blocks1-3=:role:dept):")
    for i, bl in enumerate(decomposed):
        print(f"  record{i}: name={bl[0]}  roledept={'|'.join(bl[1:])}")

    # Group records by their role+dept block signature (blocks 1..end).
    classes: dict[tuple, list[int]] = {}
    for i, bl in enumerate(decomposed):
        classes.setdefault(tuple(bl[1:]), []).append(i)

    print("\n(role,dept) equivalence classes (identical ciphertext => identical fields):")
    shared = []
    for sig, members in classes.items():
        print(f"  class {members}: role+dept signature {'|'.join(sig)}")
        if len(members) > 1:
            shared.append(members)

    # Inference: record0 is the known admin 'alic' (from the org chart / a leaked row).
    # Any record in record0's class holds the same privileged (role,dept).
    admins = next((m for m in shared if 0 in m), [0])
    print(f"\nRecords sharing record0's (admin) role+dept blocks: {admins}")
    print("=> every record in that class is an 'admn' even though names stay encrypted.")

    ok = len(admins) >= 2 and decomposed[admins[0]][1:] == decomposed[admins[1]][1:]
    print(f"\n[{'CONFIRMED' if ok else 'FAILED'}] a non-admin-looking record is unmasked "
          f"as admin via identical ECB blocks.")


if __name__ == "__main__":
    main()
