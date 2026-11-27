# Review notes — what was reproduced, corrected, and still limited

This file records the independent verification done on the group implementation
and the cross-checks added in this folder. It exists so a PR reviewer can see
what is measured first-hand versus what is carried over.

## Reproduced independently

- **All six headline CSVs.** `attack/attack.py`, `defend/defend.py` and
  `duel/score.py` were re-run from a clean checkout and in a renamed copy of this
  folder (`verify_readiness.py`). Output matched the committed CSVs byte-for-byte
  (only the host Python version differs in `results/readiness/summary.json`).
- **The three Part-A oracles.** SQLi (canary leak), XSS (live `<script>`), cmdi
  (metachar reaches the command string) all fire exactly as the attack README
  claims; naive payloads die at Medium, bypasses land, controls stay clean.
- **The duel scoring.** `duel/score.py` reproduces the precision/recall/F1 table
  and the non-determinism table from the committed `duel/raw/` outputs.

## Corrections / honesty adjustments made here

- **Readiness controls and the `o'brien` fixture.** The committed
  `results/readiness/controls.csv` expected an `o'brien` account to log in, but
  the course `vuln-web` (`make_db`) seeds only `admin` and `alice`. The rebuilt
  `verify_readiness.py` uses the stock DB, so it expects `o'brien` to be rejected
  and observes exactly that. Two control rows therefore read `False/False` here
  instead of `True/True`. This is the honest behavior against the unmodified
  target; the B2 point (the fix stops `o'brien` from crashing the query) is
  unchanged and still shown in `defend/defend.py`.
- **Removed process scaffolding.** The imported folder carried an `AGENTS.md`
  (instructions for an AI coding tool) and README paragraphs describing the
  local import workflow. These are not deliverables and were dropped from this
  copy; the substance (scope caveats, Medium interpretation) is kept in the
  README and in `honesty.md`.

## Added evidence (measured first-hand in this folder)

| Addition | File | Closes which gap |
|---|---|---|
| Real DVWA Medium SQLi | `attack/dvwa_medium.py`, `results/dvwa_medium_sqli.csv` | the "our Medium is not DVWA's" risk (honesty §5) |
| WAF FP on the `pw` field | `defend/measure_pw_fp.py`, `results/waf_pw_*.csv` | the corpus never tested passwords (axis 5) |
| Fresh WAF_V2 bypass attempt | `defend/bypass_v2.py`, `results/waf_v2_bypass_attempts.csv` | "we only tried 4 bypasses of V2" (honesty §2) |
| LLM comment ablation | `duel/llm_ablation.py`, `results/llm_ablation_scores.csv` | the `# VULN` hints help the LLM (honesty §1) |

## Remaining limitations (not resolved)

- **Provenance of the main duel's LLM outputs.** `duel/raw/llm_*.json` were
  produced on another group member's machine with `qwen3.8:27b`; the files carry
  no model digest, and that model is not installed here, so those specific runs
  cannot be reproduced locally. The ablation uses the model installed on this
  machine and is reproducible here; it is a same-model original-vs-stripped
  comparison, not a reproduction of the qwen runs.
- **The committed `duel/raw/semgrep.json` and `bandit.json`** record an absolute
  path from the original author's machine. They are preserved verbatim as raw
  evidence rather than rewritten.
- **cmdi is simulated.** `vuln-web` returns `would_run` instead of executing, so
  the cmdi oracle proves data reached the command context, not that a command
  ran. (See `honesty.md` §4.)
