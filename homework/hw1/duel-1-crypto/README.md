# Duel 1 — starter files

Full assignment: [`../duel-1-crypto.md`](../duel-1-crypto.md).

## What's here

- **`duel1_targets.py`** — six flawed crypto/protocol deployments. This is your
  target. Read it (every flaw is marked `# FLAW`), then break at least four
  (≥ 1 per tier). You get the functions' *outputs*, never the keys.

  ```bash
  python duel1_targets.py            # print the public artifacts you attack
  ```

- **`SOLUTIONS.md`** — *not present in your branch* (instructor only).

## Submit

A PR to `/projects/duel-1-crypto/<lastnames>/` containing:

- `breaks/` — one reproducible script per break, each printing the recovered
  artifact, plus a short `README` naming the assumption and misuse-vs-primitive.
- `secs-design.md` — the Secure Electronic Contract Signing design (Part B), with a
  flow diagram, trust boundaries, and an axis-2 guarantee+condition per goal.
- `honesty.md` — "Where our breaks or design might be unfair" (≥ 3 points).
- `AI_LOG.md` — per [`../../resources/ai-policy.md`](../../resources/ai-policy.md).

⚠️ Every guarantee must be stated as a **conditional** (axis 2). All work against
these local targets only — see
[`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md).
