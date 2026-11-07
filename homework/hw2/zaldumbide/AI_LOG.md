# AI Log for Duel 2 — Homework 2 (Web Attack & Defend)

**Names:** Luis Eduardo Zaldumbide, Miguel Jarrin, Josue Lopez
**Class:** Computer Security
**Date:** 6/11/2026

Per the course AI policy (`../../../resources/ai-policy.md`), this log records the
material use of AI assistants in the submitted work.

---

## Part A — Attack (Luis Eduardo Zaldumbide)


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


