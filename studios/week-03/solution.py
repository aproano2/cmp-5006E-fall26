"""Week 3 studio — REFERENCE SOLUTION (instructor-only).

A filled-in copy of ``starter.py``: identical function names and signatures, so
the *provided* ``test_modes.py`` passes when this module is imported in place of
``starter``. Verify with ``studios/_verify_solutions.py`` (which aliases this file
to the name ``starter`` and runs the unmodified test).

Three exploits, one theme — **the primitive stayed intact; the MODE or the
CONSTRUCTION around it was the bug**:

  * ``ecb_leak_count`` — ECB maps identical plaintext blocks to identical
    ciphertext blocks, so distinct-ciphertext-block count == distinct-plaintext
    count. The two flat "image" regions leak 1:1 (result 2), while CBC over the
    same image/cipher yields 96. Same cipher, different mode, opposite outcome.
  * ``recover_second_plaintext`` — CTR under a REUSED nonce is week 2's two-time
    pad on a modern mode: the shared keystream cancels, c1 XOR c2 == m1 XOR m2, so
    m2 = c1 XOR c2 XOR m1. AES gives zero protection; its guarantee was conditional
    on nonce uniqueness.
  * ``forge_extension`` — a Merkle-Damgard digest IS the full internal state, so
    hashing RESUMES from a tag. Replicate the hash's glue padding, then continue
    md_hash from the observed tag: a valid H(secret||msg) tag forged with no key.
    HMAC nests the hashing, hides the resumable state, and defeats it — a better
    construction, not a better hash.

DO NOT ship to students — excluded via ``studios/.gitignore``. The teaching
walkthrough is ``solution.ipynb`` (imports this file rather than re-pasting it).
"""
from modes import ecb_encrypt, cbc_encrypt, distinct_blocks, ctr_keystream, xor
from mdhash import md_hash, bad_mac


# ---- Task 1: ECB leaks structure, CBC hides it ------------------------------

def ecb_leak_count(image: bytes, key: bytes) -> int:
    """Encrypt ``image`` under ECB and return the number of DISTINCT ciphertext
    blocks. Because ECB maps identical plaintext blocks to identical ciphertext
    blocks, this equals the number of distinct plaintext blocks — the structure
    leaks 1:1. For the provided IMAGE this is 2 (the two flat regions).
    """
    return distinct_blocks(ecb_encrypt(image, key))


# ---- Task 2: CTR nonce reuse == week-2 two-time pad -------------------------

def recover_second_plaintext(c1: bytes, c2: bytes, known_m1: bytes) -> bytes:
    """Two messages CTR-encrypted under the SAME key AND the SAME nonce share a
    keystream. Given both ciphertexts and the first plaintext, recover the second.

    The keystream cancels, so c1 XOR c2 == m1 XOR m2, therefore m2 = c1 XOR c2 XOR m1.
    Exactly the week-2 two-time-pad break on a modern mode.
    """
    return xor(xor(c1, c2), known_m1)


# ---- Task 3: forge a H(secret‖msg) MAC by length extension ------------------

def forge_extension(observed_msg: bytes, observed_tag: int, secret_len: int,
                    extension: bytes):
    """Forge a valid ``bad_mac`` (= H(secret||msg)) tag for attacker-chosen
    ``extension`` WITHOUT the secret, knowing only ``observed_msg``, its tag, and
    the secret's LENGTH.

    Replicate the hash's internal glue padding, then RESUME hashing from the tag:
      1. total = secret_len + len(observed_msg)
      2. pad   = bytes((-total) % 4)          # toy hash pads to 4-byte blocks
      3. forged_msg = observed_msg + pad + extension
      4. forged_tag = md_hash(extension, iv=observed_tag)   # resume from the tag
    """
    total = secret_len + len(observed_msg)
    pad = bytes((-total) % 4)
    forged_msg = observed_msg + pad + extension
    forged_tag = md_hash(extension, iv=observed_tag)
    return forged_msg, forged_tag


if __name__ == "__main__":
    import os
    from data import IMAGE, M1, M2, CRIB, MAC_SECRET, MAC_MSG, MAC_EXTENSION

    key = os.urandom(16)
    print("ECB distinct ciphertext blocks:", ecb_leak_count(IMAGE, key),
          "(expected 2 — structure leaks)")

    nonce = os.urandom(8)  # the BUG: reused across both messages below
    ks = ctr_keystream(key, nonce, max(len(M1), len(M2)))
    c1, c2 = xor(M1, ks), xor(M2, ks)
    print("recovered m2:", recover_second_plaintext(c1, c2, M1))

    tag = bad_mac(MAC_SECRET, MAC_MSG)
    fm, ft = forge_extension(MAC_MSG, tag, len(MAC_SECRET), MAC_EXTENSION)
    print(f"forged msg {fm!r} tag valid? {bad_mac(MAC_SECRET, fm) == ft}")
