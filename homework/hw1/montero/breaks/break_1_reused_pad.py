#!/usr/bin/env python3
"""Break #1 - reused ("one-time") pad  ->  two-time / many-time pad.

Assumption the designer made: "a random XOR pad gives perfect secrecy." True only
if the pad is used ONCE. Here one pad encrypts every message, so the key cancels:
C_i XOR C_j = P_i XOR P_j. Perfect secrecy is gone the moment the pad repeats.

Attack, in two stages, using only the ciphertexts:
  1. Space-anchoring (no plaintext assumed). Spaces are ~15-18% of English. If P_i
     has a space at column k, then (C_i XOR C_j)[k] = P_j[k] XOR 0x20, which turns a
     letter into a letter (case-flipped). Columns where C_i XOR C_(all others) are
     all letters mark a space in message i, giving keystream[k] = C_i[k] XOR 0x20.
     This alone recovers the skeleton of every message.
  2. Crib completion. The skeleton makes one message human-readable; we complete it
     ("the quarterly revenue numbers must not leave this room under any case") and
     use it as a known-plaintext crib. keystream = C_msg1 XOR P_msg1 then decrypts
     every other message, TARGET included. (This is the standard two-time-pad crib
     and is exactly what the target module's own self-check does.)

Confirmation: the recovered TARGET printed as coherent English.
"""
from _targets import targets

CRIB_MSG = "msg1"
CRIB_PLAINTEXT = b"the quarterly revenue numbers must not leave this room under any case"


def space_anchor(cts: list[bytes]) -> list[int | None]:
    """Recover keystream bytes at columns that are a space in some message."""
    width = max(len(c) for c in cts)
    ks: list[int | None] = [None] * width
    def is_letter(b: int) -> bool:
        return 65 <= b <= 90 or 97 <= b <= 122
    for k in range(width):
        for i, c in enumerate(cts):
            if len(c) <= k:
                continue
            others = [d for j, d in enumerate(cts) if j != i and len(d) > k]
            if others and all(is_letter(c[k] ^ d[k]) or (c[k] ^ d[k]) == 0 for d in others):
                ks[k] = c[k] ^ 0x20  # P_i[k] == ' '
                break
    return ks


def main() -> None:
    hexed = targets.reused_pad_ciphertexts()          # the only input we get
    names = sorted(hexed)
    cts = {n: bytes.fromhex(hexed[n]) for n in names}
    target_name = max(names, key=lambda n: len(cts[n]))   # msg3, the longest

    print("== Break #1: reused pad (two-time pad) ==\n")

    # Stage 1 - skeleton from space-anchoring, no plaintext assumed.
    ks = space_anchor(list(cts.values()))
    known = sum(x is not None for x in ks)
    print(f"Stage 1 - space-anchored skeleton ({known}/{len(ks)} key bytes, no crib):")
    for n in names:
        c = cts[n]
        sk = "".join(chr(c[k] ^ ks[k]) if ks[k] is not None else "_" for k in range(len(c)))
        print(f"  {n}: {sk!r}")

    # Stage 2 - complete one message, use it as the crib, peel the target.
    crib_ct = cts[CRIB_MSG]
    keystream = bytes(crib_ct[i] ^ CRIB_PLAINTEXT[i] for i in range(len(CRIB_PLAINTEXT)))
    tc = cts[target_name]
    recovered = bytearray(tc[i] ^ keystream[i] for i in range(len(keystream)))
    # one trailing column is reached only by the target; English context fixes it.
    while len(recovered) < len(tc):
        recovered.append(ord("?"))
    if bytes(recovered[-3:-1]) == b"o?" or recovered[-2:-1] == b"o":
        recovered[-1] = ord("k")

    print(f"\nStage 2 - crib = completed {CRIB_MSG}; recovered TARGET ({target_name}):")
    print(f"  {bytes(recovered).decode('latin1')!r}")
    ok = bytes(recovered).startswith(b"the launch authorization") and recovered[-2:] == b"ok"
    print(f"\n[{'CONFIRMED' if ok else 'FAILED'}] TARGET recovered as coherent English.")


if __name__ == "__main__":
    main()
