# AI Log for Duel 2 — Homework 2 (Web Attack & Defend)

**Names:** Luis Eduardo Zaldumbide, Miguel Jarrin, Josue Lopez
**Class:** Computer Security
**Date:** 6/11/2026

Per the course AI policy (`../../../resources/ai-policy.md`), this log records the
material use of AI assistants in the submitted work.

---

## Part A — Attack (Luis Eduardo Zaldumbide)

**Tool used:** Claude (claude.ai)

**Purpose:**
Used Claude to understand the seclab.attack framework API and build
attack_partA.py, confirming the three Part-A vulnerabilities (SQLi, XSS, cmdi)
with oracle-backed evidence instead of suggestive responses.

**Main assistance received:**
- Walked through SQLi, XSS, and command injection manually with curl first
  (black-box, without reading the source) to understand each vulnerability
  before automating it.
- Helped debug an AttributeError in the first script version: run_payloads
  passes payload.text (a string) to send(), not the Payload object — fixed
  the three send_* functions accordingly.
- Helped design the BASE_URL fix (reading VULN_WEB_URL from the environment)
  so the script doesn't need editing every time the Docker port changes.

**Student contribution:**
I ran every curl command myself, read each response, and decided when a
result counted as confirmation vs. a suggestive response. I understand why
each oracle is sound (canary leak, unescaped <script>, injection_detected
flag) and why Broken Access Control doesn't apply to this target.

---

## Part B — Defend, then bypass (Miguel Jarrin)

**Tool used:** Claude Code (Claude Opus 4.8)

**Purpose:**
Used Claude Code to build and document Part B: the WAF blocklist (B1) and the
parameterized fix (B2), defending the SQL injection in `do_login`.

**Main assistance received:**
- Helped design the WAF blocklist (SQL comments, stacked queries, `union|select`
  keywords, `OR/AND x=y` tautology) and the three same-intent bypasses (`LIKE`,
  `<>`, `>` tautologies) confirmed against the real `do_login` with the canary
  oracle.
- Wrote the parameterized `do_login_safe()` and the re-run showing all payloads and
  bypasses now fail, and helped phrase the guarantee.
- Flagged that a `\b` word-boundary rule gave a misleadingly low 0 % false-positive
  rate (the `_` in `select_committee_chair` defeats the boundary); we switched to a
  substring match so the measured 22 % FP cost is honest.

**Student contribution:**
I (Miguel) reviewed every WAF rule, bypass, and the fix, and re-ran
`defend_partB.py` to verify the numbers. I understand the core lesson: the
blocklist only *raises cost* (bypassable + 22 % false positives) while
parameterization *gives a guarantee* (0 leaks for any input).

---

## Part C and Part D (Josue Lopez)

Tool used: Claude Code (Claude Opus 5.5)

Purpose:
Used Claude Code to build and document Part C, the duel between sqlmap and an LLM
reviewer (qwen2.5:1.5b on a local Ollama) scored against `duel/ground_truth.json`,
and to draft the Part D honesty section (`honesty.md`). The local model is the
subject of the experiment, not an assistant, so its answers are reported in the
README and kept in `duel/raw/`.

Main assistance received:
* Wrote `duel/duel_partC.py`: sqlmap against the 4 endpoints, the LLM review run
  twice with the comments removed from the source, the parser that turns the LLM
  answers into `ScanResult`s, and the scoring with `seclab.scan`.
* Found that qwen2.5:1.5b repeats the same line forever and times out, and added
  a 600 token cap as the only change to `seclab.LLM`. Suggested raising sqlmap to
  level 3 and risk 3 after the default settings found nothing.
* Drafted the Part C text of the README and helped the answers to the four honesty
  questions in `honesty.md`.

Student contribution:
I (Josue) reviewed the script and both LLM answers in `duel/raw/`, reran
`duel_partC.py score` to verify that the numbers in the README match
`c_scores.csv`, and decided what goes in the final submission. I understand the
core lesson: sqlmap is precise but narrow (no false positives, but it only looks
for SQL injection), while the LLM hallucinates bugs in code that is not there and
changes its answer just by changing the seed, so a single LLM run is not evidence.
