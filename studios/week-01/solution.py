"""Week 1 studio — REFERENCE SOLUTION (instructor-only).

A filled-in copy of ``starter.py``: identical function names and signatures, so
the *provided* ``test_cipher.py`` passes when this module is imported in place of
``starter``. Verify with ``studios/_verify_solutions.py`` (which aliases this file
to the name ``starter`` and runs the unmodified test).

DO NOT ship to students — excluded via ``studios/.gitignore``. The teaching
walkthrough is ``solution.ipynb`` (imports this file rather than re-pasting it).
"""
import random

from cipher import (ALPHABET, ENGLISH_FREQ, apply_guess, letter_counts, score)


# ---- the attack -------------------------------------------------------------

def frequency_guess_key(ciphertext):
    """Map cipher symbols to English letters by frequency RANK (commonest cipher
    symbol -> E, next -> T, ...). A noisy first pass, but readably close — and
    that "readably close" is the tell that the English assumption is right."""
    cipher_by_freq = [sym for sym, _ in letter_counts(ciphertext).most_common()]
    english_by_freq = sorted(ENGLISH_FREQ, key=ENGLISH_FREQ.get, reverse=True)
    return {sym: eng for sym, eng in zip(cipher_by_freq, english_by_freq)}


def crack(ciphertext, restarts=8, iters=3000, seed=0):
    """Recover the decryption key by random-restart hill-climbing the bigram
    ``score``. Never enumerates 26! — searches only "keys that produce English".

    Uses a seeded RNG so results are reproducible. Reads only the ciphertext and
    the PUBLIC score/ENGLISH_FREQ — never the true key or plaintext.
    """
    rng = random.Random(seed)
    symbols = list(ALPHABET)
    guess = frequency_guess_key(ciphertext)

    best_key, best_score = None, float("-inf")
    for r in range(restarts):
        # Restart 0 starts from the frequency guess (completed to a full
        # permutation); later restarts start from random permutations for the
        # diversity that lets a bigram climber escape a bad basin.
        if r == 0:
            key = dict(guess)
            used = set(key.values())
            spare = [c for c in ALPHABET if c not in used]
            rng.shuffle(spare)
            for sym in (c for c in ALPHABET if c not in key):
                key[sym] = spare.pop()
        else:
            perm = list(ALPHABET)
            rng.shuffle(perm)
            key = {sym: pt for sym, pt in zip(ALPHABET, perm)}

        current = score(apply_guess(ciphertext, key))
        for _ in range(iters):
            a, b = rng.sample(symbols, 2)
            key[a], key[b] = key[b], key[a]
            new = score(apply_guess(ciphertext, key))
            if new >= current:
                current = new
            else:
                key[a], key[b] = key[b], key[a]   # revert: keep the climb monotone

        if current > best_score:
            best_score, best_key = current, dict(key)
    return best_key


if __name__ == "__main__":
    from cipher import load_ciphertexts, recovery_rate
    bank = load_ciphertexts()
    item = bank["english"][0]
    ct, pt = item["ciphertext"], item["plaintext"]
    key = crack(ct, seed=bank["crack_seed"])
    recovered = apply_guess(ct, key)
    print(recovered[:320], "...\n")
    print(f"recovered {100 * recovery_rate(recovered, pt):.0f}% of characters WITHOUT the key")
