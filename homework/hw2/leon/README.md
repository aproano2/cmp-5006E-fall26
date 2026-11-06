# Homework 2: Web Attack & Defend (vuln-web)

**Group:** Julian Leon, Mauricio Mantilla, James Soto
**Course:** CMP 5006E Computer Security, USFQ, fall 2026
**Target:** the course's `labs/vuln-web` app, run in-process on `127.0.0.1` only
(local sandbox, see [`resources/ethics-and-scope.md`](../../../resources/ethics-and-scope.md)).

We attack vuln-web at a DVWA-style **Medium** level (SQLi, XSS, cmdi), defend the
SQLi two ways (a blocklist WAF that we then bypass, and a parameterized query),
and run a scanner-vs-LLM duel scored against a ground truth we wrote by hand.

## Headline results

| Part | Result | Evidence |
|---|---|---|
| **A** Attack | 3 classes confirmed at Medium **only through a bypass**. 5 naive payloads blocked (0/3), 10 bypasses confirmed (3/3), negative controls clean | [`attack/`](attack/README.md), `results/attack_results.csv` |
| **B1** WAF | V1: coverage **5/5**, **4/4 bypasses** land, FP **0/26**. V2 (hardened): 0/4 bypasses, FP **8/26 = 31 %** (blocks `o'brien`) | [`defend/`](defend/README.md), `results/defense_attacks.csv`, `results/waf_false_positives.csv` |
| **B2** Fix | Parameterized `do_login`: **0/9** attacks land, real logins still work. Guarantee stated as a conditional | [`defend/`](defend/README.md) |
| **C** Duel | LLM (qwen3.8:27b): recall **3/3** in all 5 runs, precision **43 % at T=0 vs 75 % at T=0.7**. Best hallucination: CSRF in an app with no sessions. sqlmap 100 % precision / 33 % recall. bandit 33 % / 33 %. **semgrep 0/3** (worst miss: a textbook f-string SQLi). No tool claimed access control, which is correct because none exists |  [`duel/`](duel/README.md), `results/duel_*.csv`, `results/llm_nondeterminism.csv` |
| **D** Honesty | 5 self-critiques | [`honesty.md`](honesty.md) |

## Layout

```
common.py              shared: start vuln-web on 127.0.0.1, senders, the 3 oracles, CSV writer
attack/medium_app.py   the Medium level: DVWA-style filters in front of the real sinks
attack/attack.py       Part A
defend/waf.py          B1: WAF_V1 (deployed) and WAF_V2 (broad) blocklists
defend/fixed_app.py    B2: parameterized do_login
defend/defend.py       Part B: coverage, bypasses, FP rate, re-run against the fix
defend/benign_traffic.json  benign corpus (copy of the course's duel-2-web file)
duel/ground_truth.json hand-built ground truth (frozen before any tool ran)
duel/run_scanners.py   semgrep + bandit (static), sqlmap (dynamic) -> duel/raw/
duel/llm_review.py     local LLM via seclab.LLM, 5 runs -> duel/raw/llm_*.json
duel/score.py          seclab.scan scoring of everything in duel/raw/
results/*.csv          every number quoted in the READMEs
honesty.md, AI_LOG.md
```

## Reproduce (from `homework/hw2/leon/`, Python 3.10+)

```bash
python3 attack/attack.py          # Part A, stdlib only, ~1 s, asserts its claims
python3 defend/defend.py          # Part B, stdlib only, ~1 s, asserts its claims
python3 duel/score.py             # Part C scoring from the committed raw outputs
```

To re-run the tools themselves (optional, slow):

```bash
pip install semgrep bandit sqlmap && python3 duel/run_scanners.py
ollama pull qwen3.8:27b && python3 duel/llm_review.py   # delete duel/raw/llm_*.json first
```

No Docker needed: the scripts import `labs/vuln-web/app/vulnweb_app.py` and serve
it on a free localhost port, the same way the week-6/7 studios do. Tested on
macOS (M1 Pro), Python 3.14.7.
