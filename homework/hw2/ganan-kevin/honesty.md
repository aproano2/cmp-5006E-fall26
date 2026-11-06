# Where our attack, defense, or comparison might be unfair.

## 1. Was our ground truth independent of the tools?

The supplied `ground_truth.json` states that it was built by reading the
application source, not by running a scanner. We preserve that instructor
fixture and do not derive the truth set from Semgrep or the LLM. We have not
independently reconstructed every entry from scratch, however. The local
fixture verifier checks that the three positive findings reproduce and that
the safe endpoint and benign corpus behave as described; it does not prove
that the fixture covers every possible weakness in the application.

## 2. Did we tune the WAF and LLM equally?

No. The WAF is intentionally a short first-pass regex blocklist. The LLM prompt
is more carefully constrained to exact function names and JSON output. The
WAF was not iteratively tuned to minimize its false positives, while the LLM
prompt was designed to reduce malformed/hallucinated findings. This asymmetry
likely disadvantages the WAF on precision/noise comparisons and must be
considered when interpreting results.

## 3. Is the benign corpus realistic?

It is the instructor's small synthetic corpus, not production telemetry or a
random sample of users. It deliberately includes SQL-adjacent words, quotes,
and ordinary names that challenge broad regexes. The measured 5/26 (19.23%)
false-positive rate is valid for this corpus only. It must not be extrapolated
to production traffic, and the corpus size is too small for a precise
population estimate.

## 4. Which Part-A finding is least reproducible?

**Answer, now backed by real runs: command injection, but not for reliability
reasons.** All three Part-A findings reproduced at 3/3 (reliability 1.0)
against the official target via `seclab.attack` — so by the numbers, nothing
was flaky. The honest caveat is about what the number means for CMDi
specifically: `do_ping` never launches a shell, so "reproducible 3/3" means
the lab's own `injection_detected` simulation flag fires consistently, not
that a real command executed. SQLi and XSS both have oracles tied to a real
effect (a real row leaking the canary secret, a real unescaped `<script>` in
the DOM); CMDi's oracle is one step more removed from the vulnerability class
it represents. This is a property of the teaching target, not something our
run uncovered as broken.

## 5. The Medium-filter question — asked and resolved

We confirmed directly with the instructor: the Medium-filter bypass
requirement in `hw2-web.md` applies **only** to groups using DVWA as their
target. Groups using the provided `vuln-web` app, as-is, are not expected to
demonstrate a Medium-filter bypass — there is none to bypass, by design for
that target. We used `vuln-web`, not DVWA, so `medium_bypass_confirmed:
false` in `attack/part_a_results.json` is the correct, expected value for
this submission, not an unresolved gap. We asked rather than assumed this,
because the assignment text alone (without this clarification) reads as if
every group owes a filter bypass — a reasonable thing to get wrong without
checking.

## 6. Bypass evidence has two levels — and they disagreed

Our three XSS candidates evade the WAF regex (confirmed live against the
proxy: 3/3 `ALLOW`, HTTP 200, reflected unescaped) and the Python HTML parser
decodes their attribute values into `javascript:` URLs. We then ran the
Playwright/Chromium check we said we would require before calling this a
real XSS bypass: it loaded each reflected link and clicked it, with a dialog
listener attached. **`dialog_fired` was `False` for all three.** No alert
fired in an actual browser.

We are reporting this as what it is — a confirmed *lexical* bypass of our
WAF's pattern-matching, and an *unconfirmed* browser-level XSS — rather than
rounding it up to "we bypassed the WAF with working XSS." We do not know
with certainty why the dialog didn't fire (modern Chromium has tightened
restrictions on `javascript:`-scheme navigation in several contexts, and we
did not dig further into browser-security internals to confirm that's the
exact mechanism here — see the limitation in §1). What we can state
confidently either way: the WAF's blocklist is evaded by payloads that do not
demonstrably execute, in this test, in a real browser. That is still a real
finding for axis 4 (a defense that can be evaded lexically has a real gap,
independent of whether this specific evasion also achieves code execution),
but it is a narrower claim than "we have working XSS past the WAF."

## 7. The scanner comparison is not a neutral off-the-shelf benchmark

The Semgrep rules we ran are narrow and tailored to the source shapes in this
teaching app, not a broad default ruleset. The SQLi signature is deliberately
single-line, while the lab's query is assembled from two adjacent f-strings
on separate lines — so the scanner's setup is not independent of source
knowledge, and its one miss (`sqli`/`do_login`, confirmed in the real run:
TP=2, FP=0, FN=1) was predicted by us before we ran it, not discovered after
the fact. We think disclosing the rule and the predicted miss up front, then
showing the real run matched the prediction, is more honest than either (a)
hiding that we wrote the rule narrow on purpose, or (b) writing a broad rule
that might have caught everything and made the scanner look artificially
strong. Readers should weigh Semgrep's 100% precision / 67% recall knowing
the ruleset was never a fair test of "what a general SAST tool would catch
here" — it is a test of "does a narrow, disclosed rule miss what we said it
would."

## 8. Limits of our operational measurements

False positives are measured. Proxy latency, memory, CPU, tuning hours, and
production support cost were not measured in this lab run. We do not invent
those values; the scorecard marks them as not measured.


## 9. Scoring code uses the official course API

`duel/score.py` imports `ScanResult` and calls `compare_scanners` directly
from the course's own `seclab/scan.py`, rather than reimplementing the
comparison logic. All precision/recall/F1 numbers reported here are the
official function's output, not ours.

## 10. A parsing bug almost cost us the real result — and changed our conclusion

Our first pass at this duel reported the LLM at 10% precision / 13% recall,
because `duel/llm_review.py`'s output normalizer only recognized findings
shaped as a flat list of JSON objects, and silently dropped findings in two
other shapes the model actually used (each finding double-wrapped in its own
list; findings given as positional `[rule, location, evidence, confidence]`
arrays). Four of five runs "scored" zero findings — not because the model
found nothing, but because we weren't parsing what it said. We caught this
by going back to the raw `raw_text` field for each run, by hand, before
writing the final report, which is the exact check this course's materials
ask for and which we almost skipped because the first numbers looked
internally consistent (a tool "mostly finding nothing" is a plausible-sounding
story for a 3B local model). **Consistent-looking numbers are not the same
as correct numbers**, and we think this near-miss is worth reporting as
honestly as the result itself: our Part C conclusion changed from "the
scanner wins decisively" to "the two tools trade precision for recall" once
the bug was fixed, using the identical raw model output, with no new
inference calls. See `AI_LOG.md` for how this was found.

## 11. Is it fair to score the LLM one run at a time?

With the corrected numbers (macro: 75% precision / 86.7% recall / F1 0.800,
LLM recall perfect in all 5 runs), the per-run-vs-aggregate question still
matters, just differently than we first thought: scored individually, 2 of 5
runs would mislead a reader into auto-trusting a hallucinated
`broken-access-control` finding or a false alarm on the safe endpoint. Scored
as "does the model eventually find the real bug," it's 5 for 5. We report
per-run numbers (the harsher, more realistic standard for a one-shot
workflow) because the assignment's axis 9 is specifically about run-to-run
*consistency*, not best-case capability — but we think both readings are
defensible, and a deployment that could afford to run the model multiple
times and union or vote on the results would see a meaningfully better
picture than any single run shows.
