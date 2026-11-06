# AI use log: Homework 2 (Web Attack & Defend)

Group: Isabella Tulcan, Martin Montero, Santiago Arellano.
All attacks ran against a local DVWA bound to `127.0.0.1` and the course's
`vuln-web` source. No credentials, real data, or external hosts were given to any
assistant; the DVWA password is read from the shell or a prompt and never stored.

## 2026-11-01: Part A attacks and oracles

**Who:** Santiago Arellano

**Tool:** Claude Opus 5.5.

**What I asked:** Read `hw2-web.md`, `seclab.attack`, and the week-6 material, then
help me set up the notebook against a local DVWA at Medium: a logged-in session,
one sender per exercise, and an oracle per vulnerability that checks a
security-relevant effect instead of a changed page.

**What I got:** The notebook scaffold (course-root discovery, localhost-only guard,
DVWA login and security-level check), senders for SQLi, XSS, and command
injection, three oracles, and a benign control per case run through
`run_payloads` with `trials=3`.

**What I did with it / verification:** I ran Part A against my local DVWA. All
three payloads confirmed 3/3 and all three benign controls stayed 0/3. I rejected a
first XSS oracle that only looked for the payload text in the page, because that
proves reflection, not an executable context; the final oracle requires the raw
`<ScRiPt>` element with our unique marker to survive unencoded.

**Did I understand it?** Yes. DVWA Medium's SQLi sends the ID as a number, so
quoting is irrelevant and `1 OR 1=1` works without any quote to escape; the extra
`Smith` row is the proof. Its XSS filter is a case-sensitive `str_replace` on
`<script>`, so mixed case gets through, and its command filter strips `&&` and `;`
but not `|`. Each bypass is a gap in a list of bad strings.

**What I kept or rejected:** Kept the effect-based oracles and the benign controls.
Rejected any oracle based on status codes or echoed input.

## 2026-11-02: Part B WAF, false positives, and structural fix

**Who:** Isabella Tulcan

**Tool:** Claude Opus 5.5.

**What I asked:** Help me write a small blocklist WAF for the Part-A payloads, find
same-intent mutations that evade it, measure false positives on
`benign_traffic.json`, and replay every attack and bypass against DVWA's Impossible
level without leaving DVWA stuck at Impossible if a check fails.

**What I got:** A five-rule blocklist (numeric tautology, UNION SELECT, script tag,
DROP TABLE, shell metacharacters) that URL- and HTML-decodes input first, a coverage
measurement, three bypasses
(`1/**/OR/**/1=1`, an `<img onerror>` handler, and a newline command separator), the
false-positive loop over the 26 benign inputs, and separate Impossible-level replay
cells that restore Medium in `finally`, with benign checks to show the fixed
endpoints still work.

**What I did with it / verification:** Coverage was 3/3, all three bypasses still
confirmed 3/3 on the real target, and 2/26 benign inputs were blocked (7.7 %), both
by the DROP TABLE rule (`drop table tennis lessons for beginners`, `reserve the drop
table at the makerspace friday`). At Impossible, 0/2 payloads confirmed in each class
and the three benign controls still worked. I made sure the B2 guarantee is stated
as a conditional on the parameterized path staying in place.

**Did I understand it?** Yes. The WAF matches the surface of known attacks, so any
equivalent form it did not list goes through, and widening a rule to catch more
variants blocks more real users. A prepared statement is different in kind: the ID
is sent as data and never parsed as SQL, so no input value can change the query
structure, as long as nobody reverts to building the query from strings.

**What I kept or rejected:** Kept the false-positive examples and the conditional
guarantee. Rejected a suggestion to add a rule for `/**/` after the fact, since
tuning the WAF to the bypasses we had already found would inflate its coverage.

## 2026-11-05: Part C duel, honesty review, and submission

**Who:** Martin Montero

**Tool:** Claude Opus 5.5.

**What I asked:** Help me run Semgrep and the local Ollama model against
`vuln-web`, score both with `seclab.scan` against `ground_truth.json`, and measure
non-determinism over two runs. Then audit the whole notebook against the rubric,
check every number in the README against the recorded outputs, and package the
folder for the PR.

**What I got:** Custom Semgrep rules, an Ollama prompt that asks for JSON findings,
a parser into `ScanResult`, two uncached runs with different seeds, the scoring
table, and the cell that saves the raw outputs to `duel/`. The audit flagged that
Part D was thin on the duel and that the LLM's evidence strings copy the `# VULN`
comments in the source.

**What I did with it / verification:** Semgrep found `xss/do_reflect` and
`cmdi/do_ping` but missed `sqli/do_login` (F1 0.80). Both Ollama runs found all
three with no false positives (F1 1.00, Jaccard 1.0) and neither tool claimed
Broken Access Control. I compared the model's evidence text with the source and it
matches the comments almost verbatim, so I added that to Part D along with the
limits of two identical runs, our reliance on DVWA's Impossible code for B2, and
the thin per-class bypass sample. I also moved the work to `homework/hw2/montero/`,
put the three of us in the notebook header and README, and removed local paths and
draft notes.

**Did I understand it?** Yes. Semgrep misses the SQLi because our rule only matches
an f-string passed directly to `execute`, and in `do_login` the f-string is first
assigned to a `query` variable over two lines and executed later. A taint rule
from the request to `execute` would have caught it; we kept the narrow rule and
report the miss. The LLM's perfect score does not show it can
find bugs: the file labels each one, and a fair test would strip the comments first.
Two matching runs at temperature 0.7 show agreement on this file, not determinism
in general.

**What I kept or rejected:** Kept the recorded outputs exactly as produced, including
the absolute paths from Santiago's machine, rather than editing evidence. Rejected
wording that presented the LLM's 3/3 as a win over the scanner.
