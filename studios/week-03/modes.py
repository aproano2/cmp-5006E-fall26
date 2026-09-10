"""Week 3 studio — the block-cipher-mode engine (GIVEN to you; do not modify).

These are the mode implementations from the Session-A notebook, unchanged.
Week 3 is about *how you use a cipher* (the mode), not about implementing AES —
so the primitive and the modes are provided. You write the exploits in
``starter.py``.

A note on the primitive: ``block_cipher`` is a small stand-in that is only
DETERMINISTIC in the block (identical block -> identical output). That is the
one property ECB needs to leak, and the one CTR needs for a keystream. Real AES
has the same property; the lessons transfer verbatim. Nothing here is a break of
the primitive — every failure this week is a misuse of the *mode*.
"""
import hashlib


def block_cipher(block, key):
    """Stand-in for a real block cipher: a deterministic keyed map on a block.
    Real AES is a keyed permutation; the only property we need here is that it is
    DETERMINISTIC in the block (identical block -> identical output)."""
    return hashlib.sha256(key + block).digest()[:len(block)]


BS = 3


def ecb_encrypt(data, key):
    data += bytes((-len(data)) % BS)                       # pad to block size
    return b"".join(block_cipher(data[i:i+BS], key) for i in range(0, len(data), BS))


def distinct_blocks(data):
    return len({data[i:i+BS] for i in range(0, len(data), BS)})


def cbc_encrypt(data, key, iv):
    data += bytes((-len(data)) % BS)
    prev, out = iv, b""
    for i in range(0, len(data), BS):
        x = bytes(a ^ b for a, b in zip(data[i:i+BS], prev))
        prev = block_cipher(x, key)
        out += prev
    return out


def ctr_keystream(key, nonce, length):
    ks, ctr = b"", 0
    while len(ks) < length:
        ks += hashlib.sha256(key + nonce + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return ks[:length]


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
