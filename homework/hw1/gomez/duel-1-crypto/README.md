# Duel 1 — starter files

Full assignment: [`../hw-1-crypto.md`](../hw-1-crypto.md).

## What's here

- **`duel1_targets.py`** — six flawed crypto/protocol deployments. This is your
  target. Read it (every flaw is marked `# FLAW`), then break at least four
  (≥ 1 per tier). You get the functions' *outputs*, never the keys.

  ```bash
  python duel1_targets.py            # print the public artifacts you attack
  ```

- **`SOLUTIONS.md`** — *not present in your branch* (instructor only).

## Submit

The full assignment says to submit a PR to `/homework/hw1/<lastname>/`, while
the original starter brief says `/projects/duel-1-crypto/<lastnames>/`. These
instructions conflict; confirm the course's expected destination before opening
the PR. This local folder is not itself a Git checkout.

A submission should contain:

- `breaks/` — one reproducible script per break, each printing the recovered
  artifact, plus a short `README` naming the assumption and misuse-vs-primitive.
- `secs-design.md` — the Secure Electronic Contract Signing design (Part B), with a
  flow diagram, trust boundaries, and an axis-2 guarantee+condition per goal.
- `honesty.md` — "Where our breaks or design might be unfair" (≥ 3 points).
- `AI_LOG.md` — per [`../../cmp-5006E-fall26-main/resources/ai-policy.md`](../../cmp-5006E-fall26-main/resources/ai-policy.md).

⚠️ Every guarantee must be stated as a **conditional** (axis 2). All work against
these local targets only — see
[`../../cmp-5006E-fall26-main/resources/ethics-and-scope.md`](../../cmp-5006E-fall26-main/resources/ethics-and-scope.md).

## Local completed submission

The completed English-language work is saved in this directory:

- [`breaks/README.md`](breaks/README.md) explains the six attacks, artifacts,
  assumptions, misuse classifications, reliability, and conditional controls.
- `breaks/01_reused_pad.py` through `breaks/06_timing_compare.py` reproduce the
  local attacks. Run `python breaks/01_reused_pad.py` and similarly for the
  remaining scripts from this directory. Python 3 and the standard library are
  sufficient.
- [`secs-design.md`](secs-design.md) gives the SECS protocol and Control
  Scorecard axis-2 statements for each required goal.
- [`honesty.md`](honesty.md) records substantive limitations and tradeoffs.
- [`AI_LOG.md`](AI_LOG.md) discloses AI assistance; the student should complete
  its personal understanding field after reproducing the work.

Two targets have an evidence limit in the provided outputs: the pad
and CTR target messages are one byte longer than every auxiliary ciphertext.
The scripts recover their 69-byte prefixes and state this limit explicitly.
No pull request or external submission is part of this local copy.
