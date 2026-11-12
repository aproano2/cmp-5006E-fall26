"""Recover the covered log prefix from nonce reuse and an assumed known entry."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "duel-1-crypto"))
import duel1_targets as target


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# This full-message crib comes from the visible classroom fixture, not the
# ciphertext API. Knowing it is an explicit attacker-knowledge assumption.
KNOWN_LOG = b"2025-03-01 12:04 user=bob00 action=login result=failure from=10.0.0.9"


def recover_prefix(logs: dict[str, bytes], known: bytes) -> bytes:
    """Do not invent plaintext beyond the known entry's keystream coverage."""
    if not known or len(known) != len(logs["log1"]):
        raise ValueError("provide a nonempty full-message crib for log1")
    return xor(xor(logs["log1"], logs["log2"]), known)


def main() -> None:
    logs = {
        name: bytes.fromhex(value) for name, value in target.ctr_log_entries().items()
    }
    recovered = recover_prefix(logs, KNOWN_LOG)
    print("assumption: the attacker knows the plaintext of log1")
    print(f"recovered log2 prefix ({len(recovered)} bytes): {recovered!r}")
    print(f"unrecovered suffix: {len(logs['log2']) - len(recovered)} byte(s)")
    print("confirmation: python3 verify_plaintext_evidence.py from the submission folder")


if __name__ == "__main__":
    main()
