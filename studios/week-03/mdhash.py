"""Week 3 studio — the toy hash + MAC constructions (GIVEN to you; do not modify).

The hash below is a tiny Merkle-Damgard construction, taken unchanged from the
Session-A notebook. The property that matters is the property real MD hashes
(MD5, SHA-1, SHA-256) share: **the digest IS the full internal state**, so
hashing can be RESUMED from a digest. That is what makes ``bad_mac`` — the
``H(secret‖msg)`` construction — forgeable by length extension WITHOUT the key.

``good_mac`` is real ``hmac`` over real SHA-256. HMAC nests the hashing so the
attacker never sees the inner state and cannot resume it — the extension attack
simply does not apply. The week's pattern: the primitive was fine; the naive
CONSTRUCTION was the bug; the fix is a better construction, not a better hash.
"""
import hmac
import hashlib as h


def compress(state, block):
    """Toy Merkle-Damgard compression: state = f(state, block). The point is that
    the hash's OUTPUT is this state, so hashing can be RESUMED from a digest."""
    s = state
    for b in block:
        s = ((s * 31) + b) & 0xFFFFFFFF
    return s


def md_hash(msg, iv=0x12345678):
    msg += bytes((-len(msg)) % 4)
    s = iv
    for i in range(0, len(msg), 4):
        s = compress(s, msg[i:i+4])
    return s


def bad_mac(secret, msg):
    return md_hash(secret + msg)          # the vulnerable construction


def good_mac(secret, msg):
    return hmac.new(secret, msg, h.sha256).hexdigest()
