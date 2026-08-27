"""Week 1 studio — the shared crypto engine (GIVEN to you; do not modify).

This is the substitution cipher and the *public* English language model from the
Session 1A notebook, unchanged. Week 1 is about the **attack** — frequency
analysis and bigram hill-climbing — not about re-implementing the cipher or the
statistics of English, so those are provided. You write the attack in
``starter.py``.

Pure Python. No ``seclab`` import, no network, no lab target — the whole point of
this week is that a 4x10^26 keyspace falls to public knowledge alone.

What lives here (all GIVEN):
    make_key / encrypt / decrypt   — the monoalphabetic substitution cipher
    ENGLISH_FREQ                   — the attacker's PUBLIC prior on English
    letter_counts / apply_guess    — bookkeeping helpers
    score                          — a 1930s-style bigram language model, built
                                     from a PUBLIC English sample (never the secret
                                     plaintext) — this is the attacker's oracle
    recovery_rate                  — % of characters a decryption got right
    load_ciphertexts               — the provided ciphertext bank (ciphertexts.json)
"""
import json
import math
import random
import string
from collections import Counter
from pathlib import Path

ALPHABET = string.ascii_uppercase


# ---- the cipher -------------------------------------------------------------

def make_key(seed):
    """A random substitution: a permutation of the alphabet."""
    rng = random.Random(seed)
    shuffled = list(ALPHABET)
    rng.shuffle(shuffled)
    return {p: c for p, c in zip(ALPHABET, shuffled)}


def encrypt(text, key):
    out = []
    for ch in text.upper():
        out.append(key.get(ch, ch))     # non-letters pass through
    return "".join(out)


def decrypt(text, key):
    inv = {c: p for p, c in key.items()}
    return "".join(inv.get(ch, ch) for ch in text.upper())


# ---- the attacker's PUBLIC prior knowledge of English -----------------------

# Standard English letter frequencies (%). This is public; it is not the key.
ENGLISH_FREQ = {
    "E": 12.7, "T": 9.1, "A": 8.2, "O": 7.5, "I": 7.0, "N": 6.7, "S": 6.3,
    "H": 6.1, "R": 6.0, "D": 4.3, "L": 4.0, "C": 2.8, "U": 2.8, "M": 2.4,
    "W": 2.4, "F": 2.2, "G": 2.0, "Y": 2.0, "P": 1.9, "B": 1.5, "V": 1.0,
    "K": 0.8, "J": 0.15, "X": 0.15, "Q": 0.10, "Z": 0.07,
}


def letter_counts(text):
    return Counter(ch for ch in text.upper() if ch in ALPHABET)


def apply_guess(ciphertext, guess):
    """Apply a decryption map {cipher_symbol: guessed_plaintext_letter}."""
    return "".join(guess.get(ch, ch) for ch in ciphertext.upper())


# A compact bigram log-likelihood over English. Built from a sample of English so
# the attack uses only PUBLIC knowledge about the language, never the secret
# plaintext. This is the same "1930s language model" from the notebook.
ENGLISH_SAMPLE = ("""
Security through obscurity is the reliance on secrecy of design as the main method
of providing security for a system. A system relying on obscurity may have real
security vulnerabilities, but its owners or designers believe that if the flaws
are not known then attackers will be unlikely to find them. Kerckhoffs argued the
opposite: a system should be secure even if everything about it except the key is
public knowledge. The lesson for this course is that we can publish exactly how an
attack works, because a system whose security depended on your ignorance was
already broken.
""".strip() + " " + """
the quick brown fox jumps over the lazy dog and then the cat sat on the mat while
the rain in spain stays mainly in the plain a system should be secure even if all
about it except the key is public and attackers will study every message they can
""").upper()


def bigram_logscores(sample):
    counts = Counter()
    letters = [c for c in sample if c in ALPHABET]
    for a, b in zip(letters, letters[1:]):
        counts[a + b] += 1
    total = sum(counts.values())
    # log-prob with add-1 smoothing so unseen bigrams are very unlikely, not impossible
    return counts, total, math.log(1 / (total + 26 * 26))


BG_COUNTS, BG_TOTAL, BG_FLOOR = bigram_logscores(ENGLISH_SAMPLE)


def score(text):
    """Higher = more English-like, by bigram log-likelihood.

    This is the attacker's oracle: it ranks a candidate decryption by how much it
    looks like English, using only the PUBLIC bigram model above.
    """
    letters = [c for c in text.upper() if c in ALPHABET]
    s = 0.0
    for a, b in zip(letters, letters[1:]):
        c = BG_COUNTS.get(a + b, 0)
        s += math.log((c + 1) / (BG_TOTAL + 26 * 26))
    return s


# ---- scoring a decryption ---------------------------------------------------

def recovery_rate(recovered, plaintext):
    """Fraction of characters ``recovered`` got right vs. the true ``plaintext``.

    Used only to *grade* an attack after the fact. The attack itself never sees
    the plaintext — that is the whole point.
    """
    pt = plaintext.upper()
    hit = sum(a == b for a, b in zip(recovered, pt))
    return hit / max(1, len(pt))


# ---- the provided ciphertext bank -------------------------------------------

def load_ciphertexts(path=None):
    """Load ciphertexts.json (generated with fixed seeds by _generate_ciphertexts.py).

    Returns the parsed dict:
        {"crack_seed": int,
         "english":     [{"key_seed", "plaintext", "ciphertext"}, ...],
         "non_english": {"key_seed", "plaintext_seed", "plaintext", "ciphertext"}}
    """
    path = Path(path or Path(__file__).with_name("ciphertexts.json"))
    return json.loads(path.read_text())
