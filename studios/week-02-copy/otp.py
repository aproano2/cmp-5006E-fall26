"""Week 2 studio — the shared crypto engine (GIVEN to you; do not modify).

These are the primitives from the Session-A notebook, unchanged. Week 2 is about
*why the guarantees hold* — entropy, unicity distance, and perfect secrecy — not
about re-deriving the arithmetic. So the measurements and the XOR core are
provided. You do the reasoning and the attack in ``starter.py``.

Pure Python, no ``seclab`` import, no network. Laptop-only.

What's here:
    xor(a, b)                     -> byte-wise XOR of two equal-ish byte strings
    entropy_bits(N)               -> log2(N): key entropy for a uniform keyspace
    unicity_distance(H_K, D)      -> H_K / D: chars of ciphertext that pin the key
    printable_word(b)             -> True if b is lowercase-letters-and-spaces
    otp_encrypt / otp_decrypt     -> the one-time pad (both are just XOR)
    SCHEMES                       -> the entropy comparison table from the notebook
    ENGLISH_REDUNDANCY            -> D ~= 3.2 bits/char (Shannon)
    load_ciphertext_pair()        -> the two-time-pad data from twotimepad.json
"""
import json
import math
from pathlib import Path


# ---- XOR core (verbatim from the notebook) ----------------------------------

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# The one-time pad is nothing but XOR with a random, message-length, single-use
# key. Encryption and decryption are the same operation.
otp_encrypt = xor
otp_decrypt = xor


# ---- Entropy: measuring what the attacker doesn't know ----------------------
# A key's strength is its entropy (bits), not its length in characters. For a key
# drawn uniformly from a space of size N, that is log2(N).

SCHEMES = [
    ("Caesar shift (26 keys)", 26),
    ("substitution (26! keys)", math.factorial(26)),
    ("56-bit DES key", 2 ** 56),
    ("128-bit AES key", 2 ** 128),
]


def entropy_bits(N):
    """Key entropy in bits for a uniform keyspace of size N: log2(N)."""
    return math.log2(N)


def entropy_table():
    """Return the notebook's scheme/keyspace/entropy rows as a formatted string."""
    lines = [f"  {'scheme':<28}{'keyspace':>26}{'entropy (bits)':>16}",
             "  " + "-" * 70]
    for name, N in SCHEMES:
        lines.append(f"  {name:<28}{N:>26.3g}{math.log2(N):>16.1f}")
    return "\n".join(lines)


# ---- Unicity distance: how much ciphertext betrays the key ------------------
# U = H(K) / D. Below U, many keys give plausible plaintext (ambiguous); above U,
# the real key is (in principle) uniquely pinned. D is language redundancy.

ENGLISH_REDUNDANCY = 3.2   # bits/char that are predictable in English (Shannon)


def unicity_distance(H_K, D=ENGLISH_REDUNDANCY):
    """Shannon's unicity distance: characters of ciphertext before only one key
    is consistent with it. U = H(K) / D."""
    return H_K / D


# ---- Crib-dragging helper (verbatim from the notebook) ----------------------

def printable_word(b):
    return all(c == 32 or 97 <= c <= 122 for c in b)   # lowercase + spaces only


# ---- Two-time-pad data loading ----------------------------------------------

def load_ciphertext_pair(path=None):
    """Load the reused-key ciphertext pair as (c1, c2) bytes. This is exactly what
    a real attacker holds: two ciphertexts, no key, no plaintext. See
    twotimepad.json."""
    path = Path(path or Path(__file__).with_name("twotimepad.json"))
    data = json.loads(path.read_text())
    return bytes.fromhex(data["c1"]), bytes.fromhex(data["c2"])
