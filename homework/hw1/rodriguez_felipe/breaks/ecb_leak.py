import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "duel-1-crypto"))
from duel1_targets import ecb_store_records


def main():
    records = ecb_store_records()
    block_size = 4
    blocks_by_record = []

    for index, ciphertext_hex in enumerate(records):
        ciphertext = bytes.fromhex(ciphertext_hex)
        blocks = [
            ciphertext[offset:offset + block_size]
            for offset in range(0, len(ciphertext), block_size)
        ]
        blocks_by_record.append(blocks)
        print(f"Record {index}: {[block.hex() for block in blocks]}")

    print("\nRepeated blocks across records:")
    for i in range(len(blocks_by_record)):
        for j in range(i + 1, len(blocks_by_record)):
            for position, (first, second) in enumerate(
                zip(blocks_by_record[i], blocks_by_record[j])
            ):
                if first == second:
                    print(
                        f"Records {i} and {j}, block {position}: {first.hex()}"
                    )
    assert blocks_by_record[0][0] != blocks_by_record[2][0]
    assert blocks_by_record[0][1:] == blocks_by_record[2][1:]
    print("\nCONFIRMED: records 0 and 2 have different first blocks")
    print("and the same encrypted suffix (blocks 1, 2, and 3).")
    print(
        "Reference assumption: record 0 is Alice's record with role admn, and record 2 belongs to Carl."
    )
    print(
        "INFERRED: Carl also has role admn because records 0 and 2 share the encrypted blocks containing the role."
    )


if __name__ == "__main__":
    main()
