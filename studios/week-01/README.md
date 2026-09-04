# Week 1 Studio — Break a Cipher: the assumption *is* the attack

**Companion to** [`../../weeks/week-01.md`](../../weeks/week-01.md) — Session 1B.
**Time budget:** Recap 5 · Lab 45 · Demos 20 · Debrief 10 (80 min total).
**Deliverables:** the provided tests pass, a recovered plaintext with your
pre-correction accuracy, a named assumption, and a defense stated in Control
Scorecard terms.

> **Recap (5 min).** Cold call: *what assumption made the substitution cipher
> breakable, and what would you have to change about the plaintext to defeat
> frequency analysis?*

This folder is the code half of the studio — the "break it yourself" task and its
deliverables. The threat-modeling and AI tasks (1B Task 2 and Task 3) run on paper
and the LLM, against your week-0 DVWA target; see the plan and the linked resources
for those. Everything here is **pure Python — no `seclab`, no Docker, no network.**

## Files in this folder

| File | Purpose | You edit it? |
|---|---|---|
| [`cipher.py`](cipher.py) | Given: the substitution cipher + the PUBLIC English prior and bigram oracle, verbatim from the notebook | No |
| [`ciphertexts.json`](ciphertexts.json) | Given: the provided ciphertext bank — 12 English (key seeds 1–12) + 1 non-English control. `english[0]` is the notebook's live-demo ciphertext | No |
| [`starter.py`](starter.py) | **Task 1** — implement the attack: `frequency_guess_key` then `crack` (bigram hill-climb) | Yes |
| [`test_cipher.py`](test_cipher.py) | Provided tests, incl. the guarantee test `test_english_assumption_collapses_confidentiality` | No |
| [`_generate_ciphertexts.py`](_generate_ciphertexts.py) | Regenerates `ciphertexts.json` (only if you rotate a seed) | No |

## Task 1 — Break it yourself (15 min)

You are the attacker. You have the ciphertext and public knowledge of English. You
do **not** have the key. Open `starter.py` and implement:

- `frequency_guess_key(ciphertext)` — the fast, noisy first pass. Map the *k*-th
  most common cipher symbol to the *k*-th most common English letter. This gets you
  *readably close*, not correct — and "readably close" is the tell that the English
  assumption is right even when the per-letter details are wrong.
- `crack(ciphertext, restarts, iters, seed)` — refine it. Start from the frequency
  guess, then **hill-climb** the bigram `score` from `cipher.py`: swap two plaintext
  letters, keep the swap if English-likeness improves, else revert. Random restarts
  escape local optima.

Then run:

```bash
python3 test_cipher.py
```

All four tests must pass. Nothing you write may reference the key or the plaintext —
the attack sees only the ciphertext and the public `score` / `ENGLISH_FREQ`. A
26! ≈ 4×10²⁶ keyspace is a decoy: you never search it. You search the far smaller
space of *keys that produce English*, guided by letter statistics.

**Report before you hand-correct anything:** run `python3 starter.py`, read the
recovered text, and note the % it got and which letters it missed. Small samples
don't match population frequencies, so short texts mis-rank the rare letters (`J X
Q Z`) — that mismatch is your Failure Atlas material below.

### The guarantee that collapses

The centerpiece is `test_english_assumption_collapses_confidentiality`. A
substitution cipher's confidentiality "guarantee" is real **only** under an
assumption the designer rarely says out loud: *the plaintext has no exploitable
structure.* The test watches that guarantee fall the instant the plaintext is
English — recovered without the key, on all 12 keys, from public knowledge alone.

Its companion, `test_cipher_holds_on_non_english_plaintext`, is the other face of
the same coin: encrypt a uniform-random plaintext and the **identical** attack
recovers almost nothing. The cipher is exactly as strong as the assumption is true.
A test you can watch fail on English and hold on noise is how you know the guarantee
was never about the algorithm. **Name the assumption and you have named the
attack** — this is Kerckhoffs, and it licenses the whole course: we publish attacks
because a system whose security depended on your ignorance was already broken.

Fast-finishing pairs: **the frequency-only pass gets ~50–70% on this text; the
hill-climb gets ~100%. Where does the extra signal come from, and why does bigram
structure survive a substitution when you cannot read the letters?**

## Task 1 deliverables (carry into your writeup)

1. **The recovered plaintext**, and the % you got *before* any hand-correction.
2. **Name the assumption** your attack relied on, in one sentence.
3. **Defeat your own attack.** Encrypt a message so frequency analysis fails
   (compress first? encode non-linguistically? change the alphabet?), and state —
   in [`control-scorecard`](../../resources/control-scorecard.md) **axis 2** terms —
   what your defense *guarantees* and under what condition, plus what it costs.
   *"It's harder now" is not a guarantee.*
4. **Failure Atlas entry** — the most instructive case: a short ciphertext where
   frequency analysis gets it *wrong*, and why (small samples ≠ population
   frequencies).

## Tasks 2 & 3 — threat model + the AI angle (30 min, not in this folder)

Per the plan, the rest of Session 1B is on paper and the LLM, not here:

- **Task 2 (20 min)** — STRIDE-model your week-0 DVWA target with the
  [threat-model template](../../resources/threat-model-template.md): data-flow
  diagram, trust boundaries, one threat per STRIDE category. **You attack this exact
  app in week 6 — commit it; it is the map you will test.**
- **Task 3 (10 min)** — hand the app description to an LLM and ask it to
  threat-model it. With the scorecard's honesty clause: what did it find that you
  missed, what did it assert that is wrong for *your* app, and where is it strongest
  (breadth) vs. weakest (your specific trust boundaries)?

## Demos (20 min)

- Ask for the recovered plaintexts and the pre-correction accuracy. The
  characteristic shape — frequency-only garbled, hill-climb clean — is best
  discovered by students, then seen to **replicate** across the room.
- Prioritize the pair whose LLM threat model was most confidently *wrong* about
  their own app. Day two establishes that we study AI's failures, not only its wins.

## Debrief (10 min)

- A cipher is broken by an **assumption the designer didn't know they were making**,
  not by cleverness. Every break this term is this move (scorecard axis 1).
- The confidentiality guarantee was conditional all along; the condition (plaintext
  structure) is what the attack removes (axis 2).
- Kerckhoffs licenses the course: we publish attacks because obscurity is not
  security.
- The LLM is a breadth-first checklist to be verified, not a substitute for knowing
  your own boundaries.

## Links

- Session 1A notebook — [`../../notebooks/week-01-break-a-cipher.ipynb`](../../notebooks/week-01-break-a-cipher.ipynb)
- Control Scorecard — [`../../resources/control-scorecard.md`](../../resources/control-scorecard.md)
- Ethics & scope — [`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md)
