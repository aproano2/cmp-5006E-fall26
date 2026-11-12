"""Recover a local target message from a reused pad and a known plaintext crib."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from duel1_targets import reused_pad_ciphertexts


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def main() -> None:
    c = {name: bytes.fromhex(value) for name, value in reused_pad_ciphertexts().items()}
    # A known-plaintext crib from msg1. The target is one byte longer, so the
    # final target byte is information-theoretically unavailable from these outputs.
    crib = b"the quarterly revenue numbers must not leave this room under any case"
    assert len(crib) == len(c["msg1"]) == len(c["msg3"]) - 1
    pad_segment = xor(c["msg1"], crib)
    target_prefix = xor(c["msg3"], pad_segment)
    print("Recovered target plaintext prefix (69/70 bytes):",
          target_prefix.decode("ascii"))
    print("Final target byte: unrecoverable from public ciphertexts alone")
    print("Confirmed relation C1 XOR C3 = P1 XOR P3 over overlap:",
          xor(c["msg1"], c["msg3"]) == xor(crib, target_prefix))
    assert target_prefix.startswith(b"the launch authorization code")


if __name__ == "__main__":
    main()
