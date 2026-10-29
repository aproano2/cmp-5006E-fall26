"""Recover the covered target prefix under an explicit known-plaintext assumption."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "duel-1-crypto"))
import duel1_targets as target


# These full-message cribs come from the visible classroom fixture. They are an
# attacker-knowledge assumption, not information returned by the ciphertext API.
KNOWN_PLAINTEXTS = {
    "msg0": b"meet me at the north gate at nine tonight and bring the documents",
    "msg1": b"the quarterly revenue numbers must not leave this room under any case",
    "msg2": b"remember to rotate the encryption keys every ninety days without fail",
}


def recover_prefix(ciphertexts: dict[str, bytes], known: dict[str, bytes]) -> bytes:
    """Recover only positions covered by consistent, aligned companion cribs."""
    if not known or "msg3" in known:
        raise ValueError("provide companion plaintexts, not the target plaintext")
    target_ct = ciphertexts["msg3"]
    keystream = {}
    for name, plaintext in known.items():
        if not plaintext or len(plaintext) != len(ciphertexts[name]):
            raise ValueError(f"{name}: expected a nonempty full-message crib")
        for offset, (cipher_byte, plain_byte) in enumerate(
            zip(ciphertexts[name], plaintext)
        ):
            key_byte = cipher_byte ^ plain_byte
            if offset in keystream and keystream[offset] != key_byte:
                raise ValueError(f"inconsistent cribs at offset {offset}")
            keystream[offset] = key_byte

    covered_length = min(len(target_ct), len(keystream))
    return bytes(target_ct[i] ^ keystream[i] for i in range(covered_length))


def main() -> None:
    ciphertexts = {
        name: bytes.fromhex(value)
        for name, value in target.reused_pad_ciphertexts().items()
    }
    plaintext = recover_prefix(ciphertexts, KNOWN_PLAINTEXTS)
    print("assumption: the attacker knows the three companion plaintexts")
    print(f"recovered msg3 prefix ({len(plaintext)} bytes): {plaintext!r}")
    print(f"unrecovered suffix: {len(ciphertexts['msg3']) - len(plaintext)} byte(s)")
    print("confirmation: python3 verify_plaintext_evidence.py from the submission folder")


if __name__ == "__main__":
    main()
