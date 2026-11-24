# AI Log — Homework 2 (Web Attack & Defend)

Per [`../../../resources/ai-policy.md`](../../../resources/ai-policy.md). AI
materially shaped this submission, so it is logged in full. There is no penalty
for heavy use; there is a penalty for hiding it.

> **Attestation note (mine to confirm before submitting):** The "Did I understand
> it?" line in each entry is *my* claim, not the model's. I have read every script
> and document here; I should edit any "Yes" down to the truth for a closed-book
> checkpoint, because I own what I submit. — B.V.

**Tool used throughout:** Claude (Claude Code, Opus-class model), November 2026.

***

## Entry 1 — the whole harness and the four parts (code)

**What I asked:** Solve Homework 2 end to end against the course `vuln-web`
target: three oracle-confirmed attacks with filter bypasses, a WAF plus a bypass
of my own WAF plus a false-positive measurement, a parameterized fix with a stated
guarantee, and an LLM-vs-scanner duel scored against the provided ground truth.

**What I got:** `_common.py` (in-process bring-up), `medium_filter.py`,
`attack/confirm_attacks.py`, `defend/waf_blocklist.py`, `defend/measure_waf.py`,
`defend/positive_fix.py`, `duel/semgrep_rules.yml`, `duel/run_duel.py`, and the
README / honesty / this log. All payloads attack only the app's public endpoints
on `127.0.0.1`.

**What I did with it:** Ran every script and read its output. Confirmed the
oracles fire on real effects (canary leak, raw `<script>`/`onerror` in the body,
`injection_detected`) and that all Part-A controls land 0/3. Ran
`verify_fixtures.py` → *FIXTURES SOUND*. Checked the B1 bypasses actually leak the
canary through the WAF, not just pass it. Confirmed the B2 parameterized query
admits 0/9.

**Did I understand it?** Partially — confirm before checkpoint. I can derive each
attack and the parameterization guarantee on a whiteboard (injection = untrusted
data crossing into a control channel; the fix fixes the parse-tree and binds input
as data). I should double-check I can re-explain *why* the no-comment SQLi bypass
balances the template's trailing quote, since that is query-shape-specific.

## Entry 2 — the SQLi bypass technique

**What I asked:** Why do my SQLi bypasses work without a trailing `-- ` comment,
and why does the blocklist miss them?

**What I got:** The value ends in a quote-balanced token (`'1`) so the template's
own trailing `'` closes the string; `AND` binds tighter than `OR`, so the wrong
password is OR-ed away and `user='admin'` alone returns the row. The blocklist is
whitespace-anchored, so `/**/` between tokens, or `LIKE`/`>` instead of `=`,
evades every rule.

**What I did with it:** Verified each bypass leaks the canary over HTTP and that
`waf_block()` returns `None` for it. Kept the raw `admin' OR '1'='1` as the
"blocked" control.

**Did I understand it?** Yes — operator precedence + quote-balancing + a
whitespace-anchored negative filter. This is the week-6/7 thread.

## Entry 3 — the duel and its honest reading

**What I asked:** Score sqlmap, semgrep, and a local LLM against the ground truth;
surface the LLM's best hallucination, the scanner's worst miss, and the
non-determinism over ≥2 runs.

**What I got:** sqlmap confirms SQLi (3 techniques) and is blind to XSS/cmdi;
semgrep catches XSS+cmdi, false-positives on `/safe`, misses the two-line SQLi;
qwen2.5:3b finds all three cleanly and is stable across 5 seeds; llama3.1:8b
hallucinates Broken Access Control in 3/5 runs. The model is the subject of the
experiment here, so the duel findings live in the README, not in this log.

**What I did with it:** Read the raw model transcripts (`duel/llm_runs.json`) to be
sure the parser was not inventing or dropping findings — I caught and fixed a
parser bug that was under-counting the model's recall before trusting any number.
I did **not** paste any real secret or personal data into a hosted model; the only
model inputs are the synthetic lab source and synthetic payloads, and the LLM arm
runs on a local ollama model.

**Did I understand it?** Yes. The comparison — high-recall/high-hallucination LLM
vs. precise-but-narrow scanners, neither finding #1 — is the deliverable, not the
F1 column.

## Entry 4 — factual claims checked against primary sources

**What I asked / checked:** The OWASP-2021 category for each class, and the DVWA
Medium filter behaviour I reproduced in `medium_filter.py`.

**What I did with it:** Mapped SQLi/XSS/cmdi to **A03:2021 – Injection** (XSS folded
into Injection in the 2021 Top 10) against the OWASP page, and read the actual
DVWA `medium.php` sources from the running DVWA Medium container before reproducing
them, rather than trusting the model's description. No CVE or statute is cited in
this submission, so there is nothing of that kind to verify.

**Did I understand it?** Yes.
