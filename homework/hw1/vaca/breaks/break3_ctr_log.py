#!/usr/bin/env python3
"""Break #3 (Tier 1) -- AES-CTR nonce reuse.

ASSUMPTION the designer made:
    "CTR is a modern mode, so the audit log is safe." CTR turns a block cipher
    into a stream cipher: ciphertext = plaintext XOR keystream(key, nonce, ctr).
    Its security rests on the keystream never repeating -- i.e. a UNIQUE nonce
    per message under a given key. The code reuses one nonce for every entry.

THE FLAW:
    With the nonce fixed, every entry is XORed with the SAME keystream. For any
    two entries C_i XOR C_j = P_i XOR P_j (the keystream cancels) -- exactly the
    two-time-pad failure of Break #1, now wearing a block-cipher costume.

PRIMITIVE BREAK or MISUSE?
    MISUSE. AES (here a SHA-256 stand-in PRF) is untouched; CTR is a sound mode.
    The deployment broke CTR's one precondition: nonce uniqueness.

METHOD / CONFIRMATION:
    The attacker knows one full entry's plaintext -- the cheapest realistic
    source is an entry they caused themselves (here log1: a failed login they
    performed from their own host, so they know its exact text). Nonce reuse
    makes that a full known-plaintext:
        keystream = C(log1) XOR P(log1)
    and the same keystream decrypts every other entry, including the TARGET
    admin entry. Confirmed because the decrypted bytes are exactly the audit
    log's known format, not guesswork.

RELIABILITY:
    Deterministic. One honest gap: the target is one byte longer than the known
    entry, so the final keystream byte is not covered -- the last character of
    the source IP stays unknown. The security-relevant content (an admin ran an
    `export`) is fully recovered. See honesty.md.
"""

from __future__ import annotations

from _common import targets, xor

# An entry the attacker generated, so its plaintext is known exactly.
KNOWN_ENTRY = "log1"
KNOWN_PLAINTEXT = b"2025-03-01 12:04 user=bob00 action=login result=failure from=10.0.0.9"


def main() -> None:
    logs = {k: bytes.fromhex(v) for k, v in targets.ctr_log_entries().items()}

    # Known-plaintext -> keystream (valid for every entry: the nonce is reused).
    keystream = xor(logs[KNOWN_ENTRY], KNOWN_PLAINTEXT)

    print("=== Break #3: CTR nonce reuse ===")
    print(f"known entry : {KNOWN_ENTRY} (attacker-generated, plaintext known)")
    print(f"keystream   : {len(keystream)} bytes recovered from the known entry\n")

    for name, ct in logs.items():
        rec = xor(ct, keystream)
        shown = rec.decode("latin-1")
        tail = "" if len(ct) <= len(keystream) else "?" * (len(ct) - len(keystream))
        mark = "  <-- TARGET" if name == "log2" else ""
        print(f"  {name}: {shown}{tail}{mark}")

    target = xor(logs["log2"], keystream)
    print("\nRECOVERED ARTIFACT (target audit entry):")
    print(f"  {target.decode('latin-1')}?   (final IP digit uncovered)")
    assert b"user=admin action=export result=success" in target
    print("\n[confirmed] the admin's EXPORT action was recovered from ciphertext "
          "plus one self-generated known entry.")


if __name__ == "__main__":
    main()
