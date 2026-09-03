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
from cipher import (ALPHABET, ENGLISH_FREQ, apply_guess, letter_counts, score)


# ---- the attack -------------------------------------------------------------

def frequency_guess_key(ciphertext):
    """Map cipher symbols to English letters purely by frequency RANK.

    Idea: the most common cipher symbol is *probably* E, the next *probably* T,
    and so on down ``ENGLISH_FREQ``. This is a guess, not a key — it will be
    mostly wrong on a short text, but readably close. That "readably close" is
    the tell that the English assumption is right even when the details aren't.

    Return a dict {cipher_symbol: guessed_plaintext_letter}.

    Hints:
      - ``letter_counts(ciphertext).most_common()`` gives cipher symbols, commonest
        first.
      - ``sorted(ENGLISH_FREQ, key=ENGLISH_FREQ.get, reverse=True)`` gives English
        letters, commonest first.
      - ``zip`` the two rankings.
    """
    # TODO: build and return the frequency-rank decryption map.
    raise NotImplementedError


def crack(ciphertext, restarts=8, iters=3000, seed=0):
    """Recover the decryption key by hill-climbing the bigram ``score``.

    This is a tiny statistical language model driving a local search — the same
    shape as an optimizer, decades before anyone called it that. You never
    enumerate the 26! keyspace; you search only the far smaller space of "keys
    that produce English", guided by ``score``.

    Algorithm (do this for each of ``restarts`` restarts, keeping the best):
      1. Start from ``frequency_guess_key(ciphertext)`` as the initial key.
      2. Complete it into a FULL permutation over ``ALPHABET`` — the frequency
         guess only covers symbols that appear, so fill the missing plaintext
         letters into any unmapped cipher symbols (use ``random`` for the spares).
      3. ``current = score(apply_guess(ciphertext, key))``.
      4. For ``iters`` iterations: pick two plaintext letters at random and swap
         their assignments (``key[a], key[b] = key[b], key[a]``). Recompute the
         score. Keep the swap if it improved the score; otherwise revert it.
      5. Track the best-scoring key across all restarts and return it.

    Return the best decryption map {cipher_symbol: plaintext_letter}. Use a seeded
    ``random.Random(seed)`` so the result is reproducible.

    NOTE: nothing in this function may reference the true key or the plaintext.
    The only inputs are the ciphertext and the public ``score`` / ``ENGLISH_FREQ``.
    """
    # TODO: implement the random-restart hill climb described above.
    raise NotImplementedError


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
