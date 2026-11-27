"""Week 1 studio — the attack you build (fill in the TODOs).

You are the attacker. You have the ciphertext and public knowledge of English.
You do NOT have the key. Your job is to recover the plaintext anyway.

The engine (the cipher, the English prior, the bigram oracle ``score``) is GIVEN
in ``cipher.py`` — do not modify it. You implement the two pieces of the attack:

    frequency_guess_key  — the fast, noisy first pass (single-letter frequencies)
    crack                — refine it by hill-climbing the bigram score

Then run ``python3 test_cipher.py``. The centerpiece is the *guarantee* test:
it watches the cipher's confidentiality guarantee COLLAPSE the instant the
plaintext is English — because English leaks its letter statistics through any
substitution. Naming that assumption is naming the attack (Kerckhoffs, week 1).
"""
import random
from collections import Counter

from cipher import (ALPHABET, ENGLISH_FREQ, apply_guess, letter_counts, score)


# ---- the attack -------------------------------------------------------------

def frequency_guess_key(ciphertext):
    """Map cipher symbols to English letters purely by frequency RANK.

    Idea: the most common cipher symbol is *probably* E, the next *probably* T,
    and so on down ``ENGLISH_FREQ``. This is a guess, not a key — it will be
    mostly wrong on a short text, but readably close. That "readably close" is
    the tell that the English assumption is right even when the details aren't.

    Return a dict {cipher_symbol: guessed_plaintext_letter}.
    """
    cipher_by_rank = [symbol for symbol, _ in letter_counts(ciphertext).most_common()]
    english_by_rank = sorted(ENGLISH_FREQ, key=ENGLISH_FREQ.get, reverse=True)
    return dict(zip(cipher_by_rank, english_by_rank))


def crack(ciphertext, restarts=8, iters=3000, seed=0):
    """Recover the decryption key by hill-climbing the bigram ``score``.

    This is a tiny statistical language model driving a local search — the same
    shape as an optimizer, decades before anyone called it that. You never
    enumerate the 26! keyspace; you search only the far smaller space of "keys
    that produce English", guided by ``score``.

    Return the best decryption map {cipher_symbol: plaintext_letter}.

    NOTE: nothing in this function may reference the true key or the plaintext.
    The only inputs are the ciphertext and the public ``score`` / ``ENGLISH_FREQ``.
    """
    rng = random.Random(seed)
    bigrams = _ciphertext_bigrams(ciphertext)
    initial_guess = frequency_guess_key(ciphertext)

    best_key, best_score = None, float("-inf")
    for _ in range(restarts):
        # Every restart begins at the same frequency guess but fills the unseen
        # symbols differently, so each climb starts on a different hillside.
        key = _complete_key(initial_guess, rng)
        current = _score_key(key, bigrams)

        for _ in range(iters):
            a, b = rng.sample(ALPHABET, 2)
            key[a], key[b] = key[b], key[a]
            candidate = _score_key(key, bigrams)
            if candidate > current:
                current = candidate               # more English-like: keep it
            else:
                key[a], key[b] = key[b], key[a]   # worse: undo the swap

        if current > best_score:
            best_key, best_score = dict(key), current

    return best_key


# ---- scoring a candidate key ------------------------------------------------
#
# ``score`` is the oracle, but calling it on a full re-decryption for every one
# of the ~24k swaps below re-reads the whole text each time. A substitution maps
# bigrams to bigrams, so the score of a decryption is fully determined by *how
# often each cipher bigram occurs* — count those once, then a candidate key
# costs one lookup per DISTINCT bigram instead of one per character.
#
# The bigram log-probabilities come from the public oracle itself: ``score`` of
# a two-letter string is exactly the model's log-probability for that bigram, so
# nothing here duplicates or second-guesses ``cipher.py``.

BIGRAM_LOGPROB = {a + b: score(a + b) for a in ALPHABET for b in ALPHABET}


def _ciphertext_bigrams(ciphertext):
    """Count adjacent cipher-letter pairs, ignoring spaces and punctuation.

    Returns [((first_symbol, second_symbol), count), ...] — the same pairs
    ``score`` would walk, since it filters non-letters the same way.
    """
    letters = [ch for ch in ciphertext.upper() if ch in ALPHABET]
    counts = Counter(zip(letters, letters[1:]))
    return list(counts.items())


def _score_key(key, bigrams):
    """English-likeness of decrypting ``bigrams`` with ``key``. Higher is better."""
    return sum(n * BIGRAM_LOGPROB[key[a] + key[b]] for (a, b), n in bigrams)


def _complete_key(guess, rng):
    """Extend a partial guess into a full permutation of the alphabet.

    The frequency guess only covers symbols that actually appear in the
    ciphertext; the hill climb swaps over all 26, so the leftover plaintext
    letters are handed to the unseen symbols at random.
    """
    key = dict(guess)
    unused_symbols = [c for c in ALPHABET if c not in key]
    unused_letters = [c for c in ALPHABET if c not in key.values()]
    rng.shuffle(unused_letters)
    key.update(zip(unused_symbols, unused_letters))
    return key


# ---- Task: defeat your own attack (analysis, no test) -----------------------
# See README.md. After the tests pass, encrypt a message so frequency analysis
# FAILS, and describe — in the Control Scorecard's terms (axis 2) — what your
# defense *guarantees* and what it costs. "It's harder now" is not a guarantee.


if __name__ == "__main__":
    # Smoke test: crack the provided primary ciphertext and print recovery.
    from cipher import load_ciphertexts, recovery_rate
    bank = load_ciphertexts()
    item = bank["english"][0]          # key_seed=1, the notebook's demo ciphertext
    ct, pt = item["ciphertext"], item["plaintext"]
    try:
        key = crack(ct, seed=bank["crack_seed"])
    except NotImplementedError:
        print("crack() not implemented yet — fill in the TODOs.")
    else:
        recovered = apply_guess(ct, key)
        print(recovered[:320], "...\n")
        print(f"recovered {100 * recovery_rate(recovered, pt):.0f}% of characters "
              "WITHOUT the key")
