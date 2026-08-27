"""Generator for the week-1 provided ciphertext bank. Run once at build time;
commits ``ciphertexts.json`` alongside. Deterministic.

The audit flagged the "provided ciphertext" as living only inside the notebook.
This script extracts it to a data file, verbatim: the ENGLISH plaintext is the
notebook's PLAINTEXT, and the primary ciphertext (english[0]) uses ``make_key(1)``
exactly as the notebook's live demo does. We add key seeds 1..12 so the studio can
show recovery is not a fluke of one key (build history: 100% recovery across 12
seeds with crack_seed=1), plus one NON-ENGLISH control so students can watch the
cipher *hold* the moment the English assumption is false.

Regenerate only if you rotate a seed; the values are meant to be stable.
"""
import json
import random
from pathlib import Path

from cipher import ALPHABET, make_key, encrypt

# The notebook's PLAINTEXT, verbatim. Ordinary English prose — that is the whole
# vulnerability, though it does not look like one yet.
PLAINTEXT = """
Security through obscurity is the reliance on secrecy of design as the main method
of providing security for a system. A system relying on obscurity may have real
security vulnerabilities, but its owners or designers believe that if the flaws
are not known then attackers will be unlikely to find them. Kerckhoffs argued the
opposite: a system should be secure even if everything about it except the key is
public knowledge. The lesson for this course is that we can publish exactly how an
attack works, because a system whose security depended on your ignorance was
already broken.
""".strip()

KEY_SEEDS = list(range(1, 13))     # 12 keys — english[0] (seed 1) == notebook demo
CRACK_SEED = 1                     # hill-climb RNG seed, matching the notebook
PLAINTEXT_SEED = 42                # for the non-English (uniform-random) control


def main():
    english = [
        {"key_seed": ks, "plaintext": PLAINTEXT,
         "ciphertext": encrypt(PLAINTEXT, make_key(ks))}
        for ks in KEY_SEEDS
    ]

    # A NON-ENGLISH plaintext: uniform-random letters of the same length. It has
    # no letter- or bigram-frequency structure for the attack to exploit, so the
    # very same cracker recovers ~nothing. The cipher is only as weak as its
    # plaintext's structure.
    rng = random.Random(PLAINTEXT_SEED)
    rand_pt = "".join(rng.choice(ALPHABET) for _ in range(len(PLAINTEXT)))
    non_english = {
        "key_seed": 1, "plaintext_seed": PLAINTEXT_SEED,
        "plaintext": rand_pt, "ciphertext": encrypt(rand_pt, make_key(1)),
    }

    out = {
        "note": "Provided ciphertext bank for the week-1 studio. english[0] "
                "(key_seed=1) is the notebook's live-demo ciphertext, verbatim.",
        "crack_seed": CRACK_SEED,
        "english": english,
        "non_english": non_english,
    }
    dest = Path(__file__).with_name("ciphertexts.json")
    dest.write_text(json.dumps(out, indent=2))
    print(f"wrote {dest} — {len(english)} English + 1 non-English ciphertext")


if __name__ == "__main__":
    main()
