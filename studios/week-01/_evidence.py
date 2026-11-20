"""Evidence for the Week 1 writeup — Failure Atlas + 'defeat your own attack'.

Pure Python, same rules as the studio: the attack sees only ciphertext and the
public ``score`` / ``ENGLISH_FREQ``. Run: ``python3 _evidence.py``.
"""
import base64
import zlib

from cipher import (ALPHABET, ENGLISH_FREQ, apply_guess, encrypt, letter_counts,
                    make_key, recovery_rate)
import starter as s

CRACK_SEED = 1
RULE = "-" * 70


def freq_rank_report(tag, plaintext, key_seed):
    """Encrypt, run the frequency-only pass, show what it mis-ranked."""
    key = make_key(key_seed)
    ct = encrypt(plaintext, key)
    guess = s.frequency_guess_key(ct)
    recovered = apply_guess(ct, guess)
    rate = recovery_rate(recovered, plaintext)

    # true cipher->plain map restricted to symbols that actually occur
    inv = {c: p for p, c in key.items()}
    seen = [sym for sym, _ in letter_counts(ct).most_common()]
    wrong = [(sym, guess.get(sym), inv[sym]) for sym in seen
             if guess.get(sym) != inv[sym]]

    print(f"\n{tag}  (len={len(plaintext)} chars, key_seed={key_seed})")
    print(f"  plaintext : {plaintext}")
    print(f"  freq-only : {recovered}")
    print(f"  recovery  : {rate:.0%}")
    print(f"  mis-ranked: {len(wrong)}/{len(seen)} symbols  "
          f"(guessed->actual: " +
          ", ".join(f"{g}!={a}" for _, g, a in wrong[:12]) + ")")
    return rate


def sample_vs_population(plaintext):
    """Show the short sample's letter order vs the population (ENGLISH_FREQ)."""
    sample_order = [c for c, _ in letter_counts(plaintext).most_common()]
    pop_order = sorted(ENGLISH_FREQ, key=ENGLISH_FREQ.get, reverse=True)
    pop_order = [c for c in pop_order if c in sample_order]
    print("  sample rank:", " ".join(sample_order))
    print("  pop.   rank:", " ".join(pop_order))


def defeat_attack():
    """Defense: compress (deflate) then re-alphabetise before the cipher.

    zlib.compress destroys single-letter and bigram frequencies; base32 maps the
    bytes onto A-Z (+ 2..7, which the cipher passes through untouched).
    """
    messages = [
        "ATTACK AT DAWN. THE FLAWS ARE NOT KNOWN, SO THE DESIGNERS BELIEVE THE "
        "SYSTEM IS SAFE. IT IS NOT. MEET AT THE OLD BRIDGE BEFORE FIRST LIGHT.",
        "KERCKHOFFS ARGUED THAT A SYSTEM SHOULD BE SECURE EVEN IF EVERYTHING "
        "ABOUT IT EXCEPT THE KEY IS PUBLIC KNOWLEDGE AND STUDIED BY ATTACKERS.",
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG WHILE THE RAIN IN SPAIN "
        "STAYS MAINLY IN THE PLAIN AND THE CAT SAT QUIETLY ON THE WARM MAT.",
        "FREQUENCY ANALYSIS NEEDS THE REDUNDANCY OF LANGUAGE. REMOVE IT BY "
        "COMPRESSING FIRST AND THE SAME ATTACK RECOVERS ALMOST NOTHING AT ALL.",
    ]
    print("\nDEFEAT YOUR OWN ATTACK — compress + base32, then substitute")
    held = 0
    for i, msg in enumerate(messages):
        packed = base64.b32encode(zlib.compress(msg.encode(), 9)).decode().rstrip("=")
        key = make_key(7 + i)
        ct = encrypt(packed, key)
        recovered = apply_guess(ct, s.crack(ct, seed=CRACK_SEED))
        rate = recovery_rate(recovered, packed)
        held += rate < 0.40
        print(f"  msg {i}: len(transport)={len(packed):>3}  "
              f"attack recovery={rate:>4.0%}  {'held' if rate < 0.40 else 'BROKEN'}")
    print(f"  => defense held on {held}/{len(messages)} messages "
          f"(recovery < 40%, same bar as the non-English control)")
    packed0 = base64.b32encode(zlib.compress(messages[0].encode(), 9)).decode().rstrip("=")
    print("  letter-freq signal the attack needs (msg 0 transport form):")
    sample_vs_population(packed0)


if __name__ == "__main__":
    print(RULE)
    print("FAILURE ATLAS — short text mis-ranks the rare letters")
    print(RULE)
    short = "THE JAZZ QUARTET PLAYED A QUICK WALTZ FOR THE QUEEN."
    r1 = freq_rank_report("A. short sentence, rare letters present", short, 3)
    sample_vs_population(short)

    tiny = "QUIZ VEXED NYMPH."
    freq_rank_report("B. tiny pangram-ish fragment", tiny, 5)

    print("\n" + RULE)
    print("DEFENSE")
    print(RULE)
    defeat_attack()
