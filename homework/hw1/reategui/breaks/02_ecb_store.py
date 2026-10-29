"""Show equality leakage in the local four-byte ECB stand-in."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from duel1_targets import ecb_store_records


def blocks(hex_record: str) -> list[str]:
    return [hex_record[i:i + 8] for i in range(0, len(hex_record), 8)]


def main() -> None:
    records = [blocks(record) for record in ecb_store_records()]
    for i, record in enumerate(records):
        print(f"record{i} ciphertext blocks: {' | '.join(record)}")
    print("Records 0 and 2 have identical blocks after the name:",
          records[0][1:] == records[2][1:])
    print("Inference with known reference record 0 (Alice, role=admn):"
          " record 2 (Carl) also has role=admn and dept=engr.")
    assert records[0][1:] == records[2][1:]
    assert records[1][1] == records[3][1]
    assert records[0][1] != records[1][1]


if __name__ == "__main__":
    main()
