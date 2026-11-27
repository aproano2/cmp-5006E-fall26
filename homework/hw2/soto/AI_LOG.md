# AI assistance log — James Soto

> **Group:** Julian Leon, Mauricio Mantilla, James Soto.
> This is my personal AI log for HW2, following `resources/ai-policy.md`. The
> group's shared implementation and its original log are preserved in
> [`AI_LOG_GROUP.md`](AI_LOG_GROUP.md); the entries below cover the work I added
> to my copy. The local model used in the Part C duel (and in my ablation) is the
> **subject** of the experiment, not an assistant, so its outputs live in
> `duel/raw/` and `duel/raw_ablation/` as evidence, not here.
>
> **Data handling:** the assistant saw only course material — the public course
> repo, our own code, and synthetic lab data (the canary is a fake flag). No real
> credentials or personal data were shared. DVWA was pulled from its public image
> and run bound to `127.0.0.1`.

---

## 2026-11-06 — Review of the group deliverable and five cross-checks

**Tool:** Claude (Claude Code, Opus).

**What I asked:** I asked for a review of the group's HW2 under
`homework/hw2/mantilla/`, using the assignment requirements to identify missing
evidence and weak claims. I set two priorities: check the existing results and
add the supporting evidence still needed. I also specified that the group's
original results and raw outputs must remain unchanged, so the follow-up work
could be assessed separately from the original submission.

**What I got / what was done in my copy:**
- A reproduction of the three driver scripts (`attack/attack.py`,
  `defend/defend.py`, `duel/score.py`); all six headline CSVs regenerated
  identically to the committed ones.
- `attack/dvwa_medium.py`: confirms SQLi on **real DVWA at Medium**. The quoted
  payload `1' OR '1'='1` is escaped (0 rows); the numeric bypass `1 OR 1=1`
  returns 5 users; a UNION dumps 10 credential rows. This answers the biggest
  grading risk (the group's "Medium" was its own filter).
- `defend/benign_passwords.json` + `defend/measure_pw_fp.py`: the WAF also guards
  the `pw` field, but the course corpus has no passwords. Measured: V1 blocks a
  real password with a quote; V2 blocks 53 % of a human password set and
  13–20 % of random password-manager output.
- `defend/bypass_v2.py`: 13 fresh same-intent payloads against WAF_V2 (none in
  its training set). None bypasses it, and the script shows why — V2 bans every
  single quote, which the quoted-string sink requires. A measured "no bypass",
  not an assumed one.
- `duel/llm_ablation.py` + `duel/ablation_score.py`: runs the same LLM review on
  the source with and without the `# VULN` hint comments, to measure how much the
  model's recall depended on the hints.
- `verify_readiness.py`: rebuilt. Reproduces the six CSVs in a renamed copy and
  replays every Part-A input, the B1 bypasses, and the 20-input supplementary
  corpus across seven WAF/Medium compositions (294 rows, 882 trials), plus
  controls. I made one honesty correction to the committed readiness controls:
  they assumed an `o'brien` account that is **not** seeded in the course
  vuln-web, so my controls expect `o'brien` to be rejected and observe exactly
  that.
- Documentation cleanup: a self-contained README for this folder, this log, and
  the previously-referenced `REVIEW.md` / `READINESS.md`.

**What I did with it:** Everything is committed under `homework/hw2/soto/`. I kept
the group's original six CSVs and `duel/raw/` outputs unchanged; my additions
write new files (`results/dvwa_medium_sqli.csv`, `results/waf_pw_*.csv`,
`results/waf_v2_bypass_attempts.csv`, `results/llm_ablation_scores.csv`,
`results/readiness/*`).

**Did I understand it?** Yes. DVWA Medium escapes quotes, but `1 OR 1=1` changes
the logic of its unquoted numeric query without needing one. Blocking all quotes
stops our quoted-string SQLi attempts, but also rejects legitimate usernames and
passwords; parameterized queries separate data from SQL syntax. The comment
ablation kept recall at 3/3 with and without the hints, while some runs without
them added false positives, so recall alone does not establish reliability.
The readiness copy needs the same folder depth because imports locate the repo
through parent directories. These checks support specific claims, not a general
guarantee that the filters or model are secure.
