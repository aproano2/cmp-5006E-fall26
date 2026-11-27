# AI_LOG.md — Homework 2

## Entry 1 — Alex — Part A, the WAF bypass candidates, and the Medium-filter investigation

**Tool:** ChatGPT (OpenAI) for integration and bypass-candidate design; Claude
(claude.ai) for an earlier round of scaffolding and this local-review pass.

**What I asked:** Help integrating the course's real `seclab.attack` API
(`Payload`, `run_payloads`, `contains_oracle`) into the Part-A confirmation
harness, help checking whether three candidate same-intent payloads (HTML
character-reference variants of a `javascript:` link) would reach the same
XSS sink as our baseline payload, and help diagnosing environment errors
along the way (a Windows PowerShell vs. bash mismatch, a relative-path bug in
`verify_fixtures.py` that broke once our folder was nested deeper than the
instructor's original script assumed, and a `subprocess` encoding crash on
Windows inside `run_semgrep.py`).

**What I got:** A working `attack/confirm_template.py` using the real
`seclab.attack` API; three WAF-bypass candidates to test; fixes for the three
environment bugs above.

**What I did with it:** I ran everything against the real official
`vuln-web` Docker container, not a reconstruction. All three Part-A oracles
confirmed 3/3 (reliability 1.0). The three WAF-bypass candidates evade our
blocklist lexically (3/3, confirmed live against the deployed proxy), but
when I ran the required Playwright/Chromium check, **no candidate actually
fired a JavaScript dialog** — I reported that negative result as-is in
`honesty.md` rather than treating "evades the regex" as equivalent to
"working XSS." I also confirmed, by reading `vulnweb_app.py`,
`labs/vuln-web/README.md`, the Dockerfile, and `seclab/targets.py`, that none
of them implement a "Medium" filter level — so Part A's filter-bypass
requirement is still open, and I'm asking the instructor about it directly
rather than guessing or inventing one.

**Did I understand it?** The `seclab.attack` oracle pattern and the WAF/proxy
architecture, yes. The exact reason the Playwright dialog never fired, no —
I know modern browsers have tightened `javascript:`-URL handling in several
contexts, but I did not verify that's the specific mechanism here, and I say
so rather than asserting a cause I didn't confirm.

---

## Entry 2 — Kevin — B1/B2 defensive code and the Part C duel harness (scaffolding)

**Tool:** Claude (claude.ai), with later integration work on the course's
real `seclab` package done via ChatGPT.

**What I asked:** Help structuring the defensive side — a WAF blocklist and
false-positive measurement script, a structurally parameterized/escaped/
allowlisted B2 fix, a deployed reverse-proxy version of the WAF, and a Part C
harness (an LLM code-review prompt plus scoring against the official
`seclab.scan.compare_scanners`).

**What I got:** `defend/waf.py`, `defend/waf_proxy.py`,
`defend/measure_fp.py`, `defend/measure_b1.py`, `defend/positive_fix.py`,
`defend/run_fixed_target.py`, `duel/llm_review.py`, `duel/score.py`,
`duel/run_semgrep.py` and its rules.

**What I did with it:** Wrote and locally smoke-tested the scaffolding
before handing it off for Alex to run against the official target and the
real Semgrep/Ollama tools (see Entry 3) — that execution, and a real bug it
turned up in the LLM output parser, happened after this entry and is logged
separately rather than folded in here as if I'd run it myself.

**Did I understand it?** The SQLi/XSS fix mechanics and the
precision/recall/F1 calculation, yes, cleanly. I did not anticipate the
specific JSON shapes `qwen2.5:3b` would use for findings, which is exactly
the gap Entry 3 describes.

---

## Entry 3 — Alex — running Semgrep and Ollama for real, and finding a parsing bug in the LLM harness

**Tool:** Claude (claude.ai), across several follow-up sessions used to debug
Windows-specific errors as they came up while actually running the package
end to end against the official target.

**What I asked:** Help diagnosing a string of real runtime errors while
executing the full pipeline — a PowerShell vs. bash mismatch, a relative-path
bug in `verify_fixtures.py`, two servers (`waf_proxy.py`,
`run_fixed_target.py`) being killed with Ctrl+C before the scripts that
depend on them ran, a `subprocess` Windows-encoding crash in
`run_semgrep.py`, and — after running the 5 Ollama reviews — why `score.py`
reported 10% precision / 13% recall for the LLM when that felt too low to
report without checking.

**What I got:** Fixes for each environment bug, and a walkthrough of exactly
why 4 of 5 "zero-finding" LLM runs weren't actually zero: `raw_text` showed
the model had reported 3–4 real findings in every single run, in JSON shapes
(findings double-wrapped in a list; findings as positional arrays instead of
objects) the original normalizer in `duel/llm_review.py` didn't recognize
and silently dropped.

**What I did with it:** Re-ran the pipeline after each fix and confirmed it
worked (B1 live-proxy test went from 0/20 to 20/20 matching once I stopped
killing the proxy early; `verify_fixtures.py` ran clean after the path fix).
For the parsing bug specifically, I did not just accept a provided fix — I
had the raw 5-run output reprocessed with the corrected logic and the
resulting precision/recall/F1 recomputed from the same captured model output
(no new inference calls), and checked the new numbers against the raw text
by hand for two of the five runs before updating `scorecard.md` and
`honesty.md`. This is the specific case `honesty.md` §10 now describes: the
first numbers looked plausible on their own, and the only way to know they
were wrong was to go back to the raw output instead of trusting a clean
summary table.

**Did I understand it?** Yes — I could explain to a grader exactly which
JSON shape broke the original parser and why, because I checked it against
the actual `raw_text` field myself rather than taking the diagnosis on
faith.

---