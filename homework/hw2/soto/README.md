# Homework 2: Web Attack & Defend (vuln-web)

**Group:** Julian Leon, Mauricio Mantilla, James Soto
**Course:** CMP 5006E Computer Security, USFQ, fall 2026
**Target:** the course's `labs/vuln-web` app, run in-process on `127.0.0.1` only
(local sandbox, see [`resources/ethics-and-scope.md`](../../../resources/ethics-and-scope.md)),
plus **real DVWA at Medium** for one cross-check (Part A).

We attack vuln-web (SQLi, XSS, cmdi), defend the SQLi two ways (a blocklist WAF
we then bypass, and a parameterized query), and run a scanner-vs-LLM duel scored
against a ground truth we wrote by hand. The homework is a group implementation;
this folder is **James Soto's** copy and adds the independent cross-checks listed
under "Extended evidence" below.

## Headline results

| Part | Result | Evidence |
|---|---|---|
| **A** Attack | 3 classes confirmed at a DVWA-style **Medium** only through a bypass (naive payloads blocked, bypasses confirmed, controls clean). **Also confirmed on real DVWA at Medium**: the numeric bypass `1 OR 1=1` returns 5 users and a UNION dumps 10 credential rows while the quoted payload is escaped | [`attack/`](attack/README.md), `results/attack_results.csv`, `results/dvwa_medium_sqli.csv` |
| **B1** WAF | V1: coverage 5/5, **4/4 bypasses** land, FP 0/26 on the course corpus. V2 (hardened): 0/4 of those bypasses, FP 8/26 = 31 %. **New:** on a password corpus V1 blocks real passwords too, and a fresh 13-payload battery finds **no** V2 bypass — because V2 bans every quote, at a 53 % password-FP cost | [`defend/`](defend/README.md), `results/defense_attacks.csv`, `results/waf_false_positives.csv`, `results/waf_pw_false_positives.csv`, `results/waf_v2_bypass_attempts.csv` |
| **B2** Fix | Parameterized `do_login`: 0/9 attacks land, real logins still work. Guarantee stated as a conditional | [`defend/`](defend/README.md) |
| **C** Duel | LLM recall 3/3 in all 5 runs; precision 43 % (T=0) vs 75 % (T=0.7). Best hallucination: CSRF in an app with no sessions. sqlmap 100 % precision / 33 % recall; semgrep 0/3 (worst miss: a textbook f-string SQLi). **New:** a comment-ablation measures how much the LLM leaned on the `# VULN` hints | [`duel/`](duel/README.md), `results/duel_*.csv`, `results/llm_nondeterminism.csv`, `results/llm_ablation_scores.csv` |
| **D** Honesty | 6 self-critiques, now backed by the new measurements | [`honesty.md`](honesty.md) |

## Layout

```
common.py                shared: start vuln-web on 127.0.0.1, senders, the 3 oracles, CSV writer
attack/medium_app.py     the DVWA-style Medium level: filters in front of the real sinks
attack/attack.py         Part A
attack/dvwa_medium.py    Part A cross-check on REAL DVWA at Medium (needs Docker)
defend/waf.py            B1: WAF_V1 (deployed) and WAF_V2 (broad) blocklists
defend/fixed_app.py      B2: parameterized do_login
defend/defend.py         Part B: coverage, bypasses, FP rate, re-run against the fix
defend/benign_traffic.json    benign corpus (the course's duel-2-web file)
defend/benign_passwords.json  benign PASSWORD corpus (new; the course corpus has none)
defend/measure_pw_fp.py  B1 extension: WAF false positives on the pw field
defend/bypass_v2.py      B1 extension: a genuine fresh bypass attempt against WAF_V2
duel/ground_truth.json   hand-built ground truth (frozen before any tool ran)
duel/run_scanners.py     semgrep + bandit (static), sqlmap (dynamic) -> duel/raw/
duel/llm_review.py       local LLM via seclab.LLM, 5 runs -> duel/raw/llm_*.json
duel/score.py            seclab.scan scoring of everything in duel/raw/
duel/llm_ablation.py     duel extension: LLM with and without the # VULN hints
duel/ablation_score.py   scores the ablation
verify_readiness.py      reproduction in a renamed copy + full composition replay + controls
coverage_payloads.json   20 supplementary SQLi inputs, with provenance
results/*.csv            every number quoted in the READMEs
honesty.md               limitations (Part D)
AI_LOG.md                this member's AI-assistance log
AI_LOG_GROUP.md          the group's AI log, preserved from the source commit
REVIEW.md                what was independently reproduced, and remaining limitations
READINESS.md             submission checklist
```

## Reproduce (from this folder, Python 3.10+, stdlib only for A/B)

```bash
python3 attack/attack.py          # Part A, ~1 s, asserts its claims
python3 defend/defend.py          # Part B, ~1 s, asserts its claims
python3 defend/measure_pw_fp.py   # Part B extension: password false positives
python3 defend/bypass_v2.py       # Part B extension: fresh V2 bypass attempt
python3 duel/score.py             # Part C scoring from the committed raw outputs
python3 verify_readiness.py       # renamed-copy reproduction + full HTTP replay
```

Optional (slower, needs extra tools):

```bash
python3 -m seclab.targets --up dvwa    # or: docker run -d --rm -p 127.0.0.1:8081:80 vulnerables/web-dvwa
python3 attack/dvwa_medium.py http://127.0.0.1:PORT     # real DVWA Medium SQLi
pip install semgrep bandit sqlmap && python3 duel/run_scanners.py
ollama pull <model> && python3 duel/llm_review.py       # delete duel/raw/llm_*.json first
SECLAB_MODEL=<model> python3 duel/llm_ablation.py && python3 duel/ablation_score.py
```

No Docker is needed for Parts A/B/C (the scripts import `labs/vuln-web/app/vulnweb_app.py`
and serve it on a free localhost port). Docker is only needed for the optional
DVWA cross-check.

## Extended evidence (this member's additions)

These are independent cross-checks added to strengthen the group deliverable;
the original six result CSVs and the group's raw scanner/LLM outputs are
preserved unchanged.

1. **Real DVWA at Medium** (`attack/dvwa_medium.py`) — confirms SQLi on genuine
   DVWA Medium, so the result no longer depends only on the group's own
   Medium-style filter.
2. **Password false positives** (`defend/measure_pw_fp.py`,
   `defend/benign_passwords.json`) — the WAF inspects the `pw` field, but the
   course corpus has no passwords; this measures the real false positives there.
3. **Fresh WAF_V2 bypass attempt** (`defend/bypass_v2.py`) — 13 same-intent
   payloads not in V2's training set, closing the "we only tried 4" gap.
4. **LLM comment ablation** (`duel/llm_ablation.py`) — measures how much the LLM
   leaned on the source's `# VULN` comments, instead of only noting the concern.
5. **Readiness checker** (`verify_readiness.py`) — reproduces the six CSVs in a
   renamed copy and replays every input across seven WAF/Medium compositions.

## Scope and honesty

The group's custom Medium layer (`attack/medium_app.py`) is an interpretation of
the assignment; `attack/dvwa_medium.py` now also confirms the SQLi on real DVWA
Medium. The B1 headline numbers are the WAF alone on the Low sink; the
WAF/Medium composition is measured separately in `verify_readiness.py`. See
[`honesty.md`](honesty.md) and [`REVIEW.md`](REVIEW.md) for every limitation.
All work is local (`127.0.0.1`); the only external image is DVWA, pulled and run
bound to localhost for the optional cross-check.
