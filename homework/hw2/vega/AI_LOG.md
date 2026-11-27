# AI_LOG

**Members**: Daniel Andrade - Andrés Vega - Carlos Flores

Maintained per [`resources/ai-policy.md`](../../../resources/ai-policy.md).

---

## Part C — setting up the duel code (`duel/`)

**Tool:** Claude Opus 4.8 (via Claude Code)

**What I asked:** How to set up the code for Part C — how to wire the duel
together: how to invoke `semgrep` against the provided source and read its JSON,
how to structure the LLM-reviewer arm (`run_llm_review`), what prompt format to send
so the model's free-text answer could be parsed back into `ScanResult`s, how to map
a model's prose vulnerability names to canonical rules (`sqli`/`xss`/`cmdi`), and how
to score both tools against `ground_truth.json` with `seclab.scan.compare_scanners`.

**What I got:** The overall pipeline shape and the plumbing — the `semgrep` command
with three registry configs, a `_build_prompt()` output format
(`[SEVERITY] <type> in <function>`) aligned to our `parse_llm_review()` parser, the
`RULE_ALIASES` / `do_*` location matching, running the LLM review across several
seeds for the non-determinism section, and scoring against the provided ground truth.

**What I did with it:** Kept the structure and wrote/ran the code ourselves against
the live target. We did not accept any vulnerability on the model's word — every
reported number (precision/recall/F1, the stable vs. flaky findings, the 0 false
positives, the semgrep misses) comes from running the code and scoring against
`ground_truth.json`, not from anything the LLM asserted.

**Did I understand it?** Yes. We can explain why the prompt format has to match the
parser, why running the review across several seeds is required (the findings are
non-deterministic, so one run is not reproducible evidence), and why scoring must be
done against an independently-built ground truth rather than "whatever the tool
found."

---

## Part C — semgrep JSON parser (`run_semgrep`)

**Tool:** Claude Opus 5.5 (via Claude Code)

**What I asked:** "Generate the code of the run_semgrep parser."

**What I got:** A `run_semgrep()` that turns semgrep's JSON into `ScanResult`s:
- the rule comes from the CWE metadata (89 → `sqli`, 79 → `xss`, 78 → `cmdi`) through
  our existing `canonical_rule()`; findings without a known CWE keep semgrep's rule id
  so they count as false positives;
- the location is the function containing the flagged line, found with `ast`;
- duplicates across configs are removed.

It was tested on our saved output (0 results) and on two synthetic results (a CWE-89 hit
mapped to `('sqli', 'do_login')`; an unknown rule scored as a false positive).

**What I did with it:** Kept the parsing logic but changed the function to always run
semgrep live and save the JSON, so the evidence file is regenerated on every run. The
assistant pointed out three issues we have not fixed yet: this overwrites the saved
evidence and depends on the current registry rules, a failed semgrep run is not detected
(exit code ≥ 2 is not checked), and `canonical_rule()` misses rules that store their
CWE as a single string. It also noted that our `semgrep_output.json` has empty rule
lists, so without a positive control we cannot show that rules actually ran.

**Did I understand it?** Yes, the parser has to produce the same `(rule, location)`
keys as `ground_truth.json`, otherwise a correct finding is scored as a miss, and a
scanner that reports nothing has to be checked against a file it *should* flag before
"0 findings" means anything.

---

## Part C — rewriting the LLM answer parser (`parse_llm_review`)

**Tool:** Claude Opus 5.5 (via Claude Code)

**What I asked:** "Improve the LLM parser", and later to update the notebook, which
required fixing how the parser read the v2 answers.

**What I got:** A new `parse_llm_review()`:
- about 35 aliases for vulnerability names; unknown types are kept as a slug so they are
  scored as false positives instead of being dropped;
- any function name is accepted, not only `do_*`;
- a regex for our `[SEVERITY] <type> in <function>: <reason>` format that tolerates
  missing brackets, list markers and copied `[SEVERITY]` tags;
- an optional `dropped` list for lines that are not findings, including a `NONE` that
  follows findings;
- the rule is read from the *reason* only when the type field is generic ("Injection") or
  repeats the function name. Each mapping is recorded as `mapped_by`
  (`model:type` / `model:reason` / `model:slug` / `model:prose`).

**What I did with it:**
- Checked that re-parsing the cached answers gives exactly the same findings as our
  earlier `findings.csv`; it also passed a set of malformed-line edge cases.
- Read every v2 answer that relies on the reason-based rule. In 4 of the 6 v2 runs the
  model wrote the function name in the type field.
- Because this rule raises v2's recall, `honesty.md` reports what recall would be
  without it.

**Did I understand it?** Yes — the parser decides what counts as a finding, so a parser
that drops unknown claims hides hallucinations and inflates precision. Every non-literal
mapping therefore has to be visible in the output.