"""Recover a local audit entry using a reused CTR keystream segment."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from duel1_targets import ctr_log_entries


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def main() -> None:
    c = {name: bytes.fromhex(value) for name, value in ctr_log_entries().items()}
    known_log1 = b"2025-03-01 12:04 user=bob00 action=login result=failure from=10.0.0.9"
    assert len(known_log1) == len(c["log1"]) == len(c["log2"]) - 1
    keystream = xor(c["log1"], known_log1)
    target_prefix = xor(c["log2"], keystream)
    print("Recovered target log prefix (69/70 bytes):",
          target_prefix.decode("ascii"))
    print("Final target byte: unrecoverable from public ciphertexts alone")
    print("Confirmed relation C1 XOR C2 = P1 XOR P2 over overlap:",
          xor(c["log1"], c["log2"]) == xor(known_log1, target_prefix))
    assert b"user=admin action=export result=success" in target_prefix


if __name__ == "__main__":
    main()
