# Duel 1 — Crypto & Protocols

**Homework 1 / Duel 1 — weeks 1–5.** Submission for `/homework/hw1/cadena-gordillo-jarrin-rodriguez/`.

## Team

- Juan Diego Cadena
- Omar Gordillo
- Pablo Jarrín
- Santiago Rodríguez

## Contents

| File | Part | What it is |
|------|------|------------|
| `breaks/` | A | Six confirmed breaks (≥4 required, ≥1 per tier). One script per break + `breaks/README.md` giving the assumption, misuse-vs-primitive, and recovered artifact. |
| `secs-design.md` | B | Secure Electronic Contract Signing design: primitives, message flow, trust boundaries, guarantee+condition (axis-2) per goal. |
| `honesty.md` | C | "Where our breaks or design might be unfair" (6 points). |
| `AI_LOG.md` | — | AI-usage log, per `resources/ai-policy.md`. |

## Running the breaks

The scripts locate the provided `duel1_targets.py` by walking up the tree (`_pathfix.py`); it is found in the sibling `homework/hw1/duel-1-crypto/` folder, or in any directory above this one. Then:

```bash
cd breaks
python break1_reused_pad.py
python break2_ecb_store.py
python break3_ctr_log.py
python break4_length_extension.py
python break5_shared_prime.py
python break6_timing.py          # noisy; optional args: rounds reps runs
```

All six are **misuses**, not primitive breaks: the primitive keeps its promise; the deployment violated the *condition* the guarantee depends on.
