# Submission checklist — homework/hw2/soto

Run from this folder. Everything except the two optional tool-dependent steps is
stdlib-only and finishes in a few seconds.

## Deliverables present

- [x] `attack/` — SQLi, XSS, cmdi confirmed at a DVWA-style Medium, each via a
      bypass, each oracle-confirmed (`results/attack_results.csv`).
- [x] `attack/dvwa_medium.py` — SQLi confirmed on **real DVWA at Medium**
      (`results/dvwa_medium_sqli.csv`).
- [x] `defend/` — WAF_V1 (coverage + 4 bypasses + FP), WAF_V2 (FP trade-off),
      parameterized fix with a stated guarantee.
- [x] `defend/measure_pw_fp.py` + `benign_passwords.json` — WAF false positives on
      the password field (`results/waf_pw_*.csv`).
- [x] `defend/bypass_v2.py` — fresh V2 bypass attempt
      (`results/waf_v2_bypass_attempts.csv`).
- [x] `duel/` — scanner vs. LLM scored against a hand-built ground truth, with the
      LLM hallucination, the scanner miss, and non-determinism over 5 runs.
- [x] `duel/llm_ablation.py` — LLM recall with vs. without the `# VULN` hints
      (`results/llm_ablation_scores.csv`).
- [x] `honesty.md`, `AI_LOG.md`, `AI_LOG_GROUP.md`, `REVIEW.md`.
- [x] `verify_readiness.py` — reproduction + full composition replay + controls.

## Verification commands (all should print OK / pass their asserts)

```bash
python3 attack/attack.py
python3 defend/defend.py
python3 defend/measure_pw_fp.py
python3 defend/bypass_v2.py
python3 duel/score.py
python3 verify_readiness.py
```

Optional (need Docker / external tools):

```bash
docker run -d --rm --name dvwa-aio -p 127.0.0.1:8081:80 vulnerables/web-dvwa
python3 attack/dvwa_medium.py http://127.0.0.1:8081
docker stop dvwa-aio

pip install semgrep bandit sqlmap && python3 duel/run_scanners.py
SECLAB_MODEL=<installed-model> python3 duel/llm_ablation.py && python3 duel/ablation_score.py
```

## Before opening the PR

- [ ] Each group member copies the reviewed shared work into their own
      `homework/hw2/<lastname>/` and adjusts the folder references, their personal
      `AI_LOG.md`, and the group-name line.
- [ ] Fill in the "Did I understand it?" field in `AI_LOG.md` honestly.
- [ ] Stage only `homework/hw2/soto/` and inspect the full staged diff.
- [ ] Confirm the raw group outputs in `duel/raw/` are unchanged.
- [ ] PR from the `origin` fork into course `aproano2/cmp-5006E-fall26:main`,
      reviewer = one assigned classmate.

## Known limitations (see REVIEW.md and honesty.md)

- The main duel's `qwen3.8:27b` outputs were produced on another machine and are
  not reproducible here; the ablation uses the locally installed model.
- cmdi execution is simulated by the target.
- Two readiness control rows differ from the imported copy on purpose: the stock
  `vuln-web` DB has no `o'brien` account, so it is expected to be rejected.
