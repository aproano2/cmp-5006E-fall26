# Homework 2: Web Attack & Defend (vuln-web)

**Group:** Julian Leon, Mauricio Mantilla, James Soto
**Course:** CMP 5006E Computer Security, USFQ, fall 2026
**Target:** the course's `labs/vuln-web` app, run in-process on `127.0.0.1` only
(local sandbox, see [`resources/ethics-and-scope.md`](../../../resources/ethics-and-scope.md)).

We attack vuln-web at a custom DVWA-style **Medium** level (SQLi, XSS, cmdi), defend the
SQLi two ways (a blocklist WAF that we then bypass, and a parameterized query),
and run a scanner-vs-LLM duel scored against a ground truth we wrote by hand.

## Headline results

| Part | Result | Evidence |
|---|---|---|
| **A** Attack | 3 classes confirmed at the custom Medium **only through a bypass**. An additional real-DVWA Medium SQLi cross-check confirms numeric and UNION bypasses | [`attack/`](attack/README.md), `results/attack_results.csv`, `results/dvwa_medium_sqli.csv` |
| **B1** WAF | On the **Low baseline**: V1 coverage **5/5**, **4/4 bypasses** land, FP **0/26** on the supplied corpus. Additional password testing finds V1 blocks 1/15 human passwords and V2 blocks 8/15 | [`defend/`](defend/README.md), `results/defense_attacks.csv`, `results/waf_false_positives.csv` |
| **B2** Fix | Parameterized `do_login`: **0/9** attacks land, real logins still work. Guarantee stated as a conditional | [`defend/`](defend/README.md) |
| **C** Duel | Main LLM/scanner results are unchanged. A same-model comment ablation measures performance with and without `# VULN` hints |  [`duel/`](duel/README.md), `results/duel_*.csv`, `results/llm_ablation_scores.csv` |
| **D** Honesty | 6 self-critiques, including the new cross-checks | [`honesty.md`](honesty.md) |

## Layout

```
common.py              shared: start vuln-web on 127.0.0.1, senders, the 3 oracles, CSV writer
attack/medium_app.py   the Medium level: DVWA-style filters in front of the real sinks
attack/attack.py       Part A
attack/dvwa_medium.py  optional real-DVWA Medium SQLi cross-check
defend/waf.py          B1: WAF_V1 (deployed) and WAF_V2 (broad) blocklists
defend/fixed_app.py    B2: parameterized do_login
defend/defend.py       Part B: coverage, bypasses, FP rate, re-run against the fix
defend/benign_traffic.json  benign corpus (copy of the course's duel-2-web file)
defend/benign_passwords.json password-field false-positive corpus
defend/measure_pw_fp.py  password-field WAF false-positive measurement
defend/bypass_v2.py    fresh WAF_V2 bypass attempt
duel/ground_truth.json hand-built ground truth (frozen before any tool ran)
duel/run_scanners.py   semgrep + bandit (static), sqlmap (dynamic) -> duel/raw/
duel/llm_review.py     local LLM via seclab.LLM, 5 runs -> duel/raw/llm_*.json
duel/score.py          seclab.scan scoring of everything in duel/raw/
duel/llm_ablation.py   LLM comparison with and without # VULN comments
duel/ablation_score.py score the ablation outputs
duel/raw_ablation/     saved ablation responses
results/*.csv          every number quoted in the READMEs
honesty.md, AI_LOG.md   limitations and local AI assistance log
AI_LOG_GROUP.md        original group AI log, preserved from the source commit
```

## Reproduce (from `homework/hw2/mantilla/`, Python 3.10+)

```bash
python3 attack/attack.py          # Part A, stdlib only, ~1 s, asserts its claims
python3 defend/defend.py          # Part B, stdlib only, ~1 s, asserts its claims
python3 defend/measure_pw_fp.py   # password-field false positives
python3 defend/bypass_v2.py       # fresh V2 bypass attempt
python3 duel/score.py             # Part C scoring from the committed raw outputs
python3 duel/ablation_score.py    # score saved LLM comment-ablation outputs
```

To re-run the tools themselves (optional, slow):

```bash
pip install semgrep bandit sqlmap && python3 duel/run_scanners.py
ollama pull qwen3.8:27b && python3 duel/llm_review.py   # delete duel/raw/llm_*.json first
```

No Docker needed: the scripts import `labs/vuln-web/app/vulnweb_app.py` and serve
it on a free localhost port, the same way the week-6/7 studios do. Tested on
macOS (M1 Pro), Python 3.14.7 by the group; the attack, defense, and committed-output
scoring commands were also reproduced locally on Linux, Python 3.12.3.

## Local copy and submission workflow

This group implementation was imported from
[`jjjulianleon/cmp-5006E-fall26`, branch `hw2`](https://github.com/jjjulianleon/cmp-5006E-fall26/tree/1805e412dbacf2685e264fc4ac51d8984f3ae03d/homework/hw2/leon),
commit `1805e412dbacf2685e264fc4ac51d8984f3ae03d`. The original scanner/LLM raw
outputs are unchanged. Historical
paths and first-person review statements in [AI_LOG_GROUP.md](AI_LOG_GROUP.md)
belong to the source group's log; they do not establish Mauricio's personal review.

`homework/hw2/mantilla/` is the main working directory. The active branch is
`hw2-mantilla`, based on course `upstream/main`; keep the PR diff confined to this
folder. Unrelated studio work is still present in the working tree.

The results are reproducible for the configurations described here. The custom
Medium layer is the group's interpretation of the assignment; the repository
contains no evidence that the instructor has accepted it as equivalent to DVWA
Medium. Keep that distinction visible when preparing the final submission.

When the group is ready to submit, stage only this directory and inspect the
full staged diff. Push `hw2-mantilla` to `origin`
(`MantiMantilloso/cmp-5006E-fall26`) and open the group PR into course
`aproano2/cmp-5006E-fall26:main`.

Each group member must upload the same reviewed group work under their own
`homework/hw2/<lastname>/` directory and submit their own PR. Synchronize the
corrected scorer, ground truth, reports, and generated CSVs before making those
copies. Merge each member's own contributions into that shared version first,
preserving their work and resolving any conflicting changes. Re-run affected
experiments and regenerate the corresponding CSVs and report numbers when a
contribution changes behavior. Every member's copy should include the combined
group contributions and the corrections from this review.

Preserve the shared raw tool outputs and list all three group members.
The scripts resolve paths relative to their files, so changing the submission
folder name at the same depth requires no runtime code changes. Adjust displayed
folder/branch references and personal AI-log entries for each member; keep the
shared experiment code, inputs, raw outputs, and results consistent.

No remote push or PR was made during this local import.
