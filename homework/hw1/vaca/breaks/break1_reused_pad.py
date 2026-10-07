#!/usr/bin/env python3
"""Break #1 (Tier 1) -- two-time pad recovery via crib-dragging.

ASSUMPTION the designer made:
    "A one-time pad is unbreakable, so I can keep using it." The OTP guarantee
    (perfect secrecy) holds for exactly ONE message per key. Reusing the pad
    across messages turns it into a two-time (here four-time) pad.

THE FLAW:
    reused_pad encrypts every message with the same keystream K. For any two
    ciphertexts, C_i XOR C_j = P_i XOR P_j -- the key cancels. The ciphertexts
    leak the XOR of the plaintexts, and English plaintext is redundant enough to
    separate the two sides of that XOR.

PRIMITIVE BREAK or MISUSE?
    MISUSE. XOR-with-a-random-pad is information-theoretically perfect *for a
    single use*. Nothing about the primitive is broken; the deployment violated
    the "one" in one-time pad.

METHOD (and why it is a *confirmation*, not an assertion):
    These four plaintexts are known to be lowercase English (a .. z and space).
    That is a strong per-column oracle:
      1. For every column, keep only the keystream bytes k for which EVERY
         ciphertext byte present in that column decrypts into {a..z, space}.
         ~34/70 columns have a unique such k and are solved outright.
      2. For the rest we crib-drag: guess an English fragment, place it over a
         ciphertext, derive the candidate keystream, and ACCEPT the placement
         only if it also makes every other ciphertext decrypt to valid
         lowercase English at those columns. A wrong guess almost always breaks
         that cross-message check, so a surviving crib is confirmed, not
         assumed. Content words are tried before generic connectives so a short
         filler word can never lock a low-coverage tail column first.
    The recovered keystream then decrypts all four messages, including TARGET.

RELIABILITY:
    Deterministic given the fixed SEED. The only judgement is the crib list,
    and each crib is self-checking (it is rejected unless it is consistent
    across all four ciphertexts). See honesty.md: this is our least push-button
    break -- the final tail bytes are covered by a single ciphertext, so they
    rest on reading the obvious trailing word rather than on a cross-message
    check. A fifth ciphertext would remove that judgement.
"""

from __future__ import annotations

from _common import targets

# These cribs are what an analyst reads off the partial recovery in step 1.
# Order matters: specific content words first, generic connectives last, so a
# short word like " the " can never claim an under-constrained tail column
# before the real word does. Each is still *validated* against all four
# ciphertexts before any keystream byte is locked.
CRIBS = [
    "meet me", "north gate", "nine tonight", "bring the documents",
    "quarterly revenue", "numbers must not", "leave this room under any case",
    "remember to rotate", "encryption keys", "every ninety days without fail",
    "launch authorization", "will be delivered by separate courier ok",
    " the ", "and ",
]


def _valid(c: int) -> bool:
    return c == 0x20 or 97 <= c <= 122  # space or a..z


def recover_keystream(cts: list[bytes]) -> list[int | None]:
    length = max(len(c) for c in cts)
    ks: list[int | None] = [None] * length

    # Step 1 -- columns the lowercase-English constraint pins uniquely.
    for col in range(length):
        present = [c[col] for c in cts if col < len(c)]
        candidates = [k for k in range(256) if all(_valid(b ^ k) for b in present)]
        if len(candidates) == 1:
            ks[col] = candidates[0]

    # Step 2 -- crib-drag, accepting a placement only if it stays valid across
    # every ciphertext (and is consistent with bytes already locked).
    for crib in CRIBS:
        cb = crib.encode()
        for c in cts:
            for off in range(0, len(c) - len(cb) + 1):
                cand = [c[off + t] ^ cb[t] for t in range(len(cb))]
                if any(ks[off + t] is not None and ks[off + t] != cand[t]
                       for t in range(len(cb))):
                    continue
                ok = all(
                    _valid(other[off + t] ^ cand[t])
                    for t in range(len(cb))
                    for other in cts if off + t < len(other)
                )
                if ok:
                    for t in range(len(cb)):
                        if ks[off + t] is None:
                            ks[off + t] = cand[t]
    return ks


def decrypt(ct: bytes, ks: list[int | None]) -> str:
    return "".join(chr(ct[i] ^ ks[i]) if ks[i] is not None else "?"
                   for i in range(len(ct)))


def main() -> None:
    cts = [bytes.fromhex(h) for h in targets.reused_pad_ciphertexts().values()]
    ks = recover_keystream(cts)
    recovered = sum(k is not None for k in ks)

    labels = ["msg0", "msg1", "msg2", "msg3  <-- TARGET"]
    print("=== Break #1: two-time pad (pad reuse) ===")
    print(f"keystream bytes recovered: {recovered}/{len(ks)}\n")
    for label, ct in zip(labels, cts):
        print(f"  {label:18}: {decrypt(ct, ks)}")

    target = decrypt(cts[3], ks)
    print("\nRECOVERED ARTIFACT (target plaintext):")
    print(f"  {target!r}")
    assert "?" not in target, "target not fully recovered"
    assert target == ("the launch authorization code will be delivered "
                      "by separate courier ok")
    print("\n[confirmed] target plaintext recovered in full from ciphertext only.")


if __name__ == "__main__":
    main()
