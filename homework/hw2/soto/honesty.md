# Where our attack, defense, or comparison might be unfair

> **Update (this member's copy).** Four of the self-critiques below were turned
> from statements into measurements. Each is now backed by a script and a CSV:
>
> | Self-critique | Measured by | Evidence |
> |---|---|---|
> | §1 the `# VULN` comments help the LLM | `duel/llm_ablation.py` | `results/llm_ablation_scores.csv` |
> | §2 we only tried 4 bypasses of V2 | `defend/bypass_v2.py` | `results/waf_v2_bypass_attempts.csv` |
> | §3 the benign corpus has no passwords | `defend/measure_pw_fp.py` | `results/waf_pw_false_positives.csv` |
> | §5 our Medium is not DVWA's | `attack/dvwa_medium.py` | `results/dvwa_medium_sqli.csv` |
>
> The critiques are kept below as written; the measurements do not erase them,
> they quantify them. See [`REVIEW.md`](REVIEW.md) for what remains unverifiable
> (chiefly the provenance of the main duel's qwen outputs).

## 1. Was the ground truth built independently of the tools we scored?

**Mostly, but not fully.** [`duel/ground_truth.json`](duel/ground_truth.json) was
written by reading `vulnweb_app.py` before semgrep, bandit, sqlmap or the LLM
ran, and it was not edited after their outputs were seen. It has three
weaknesses:

- **We had already seen the answer.** The instructor fixture
  (`duel-2-web/ground_truth.json`) and the `# VULN` comments in the source name
  the three sinks. Our scored set equals the fixture (checked by `score.py`), so
  "independent" means "independent of the tools", not "found without help".
- **The `# VULN` comments help a reader, an LLM and a grep-style rule, but not
  sqlmap.** The source tells any reader where the bugs are. That favors the
  static tools (and the LLM) over the dynamic one in a way a real codebase
  would not.
- **Where the scope line goes changes the score.** We scored only the three
  injection sinks, and listed `information-disclosure`, `plaintext-password` and
  `hardcoded-credentials` as real but out of scope. Under strict scoring a tool
  that reports those is punished for telling the truth. The "adjusted" scores
  remove only exact normalized **(rule, location)** matches. The imported source
  matched by rule alone and incorrectly excused bandit's B105 on the canary
  constant, which is a false positive (the string is a CTF-style flag, not a
  password). The local review corrected this: Bandit's adjusted precision is
  33 %, not 50 %. Both strict and adjusted scores remain reported.

## 2. Did we tune one side more than the other?

**Yes, in both directions, and we say where.**

- **WAF:** V1 was written while looking at our own Part-A payloads, so its 5/5
  coverage is coverage on the test set it was fit to. The 4 bypasses were then
  written while looking at V1's regexes (white-box). A black-box attacker would
  need more attempts. V2 was written to stop exactly those 4 bypasses, so its
  0/4 is also measured on its own training set. We did not run a fresh,
  independent payload list (for example sqlmap with `--tamper`) against V2.
- **Scanners:** semgrep and bandit ran with default community rules and no
  custom rules. A custom semgrep rule written for this file could easily match
  the three f-strings, but writing it after reading the answer would rig the
  duel (we did not try). So semgrep's 0/3
  measures "default rules on a framework-less stdlib app", not semgrep's ceiling.
- **sqlmap** ran at default `--level 1 --risk 1`; its score counts confirmed SQL
  injection points. Its raw output also contains a heuristic XSS warning, which
  is not counted as confirmation. Its recall of 1/3 reflects this scoring scope,
  not a demonstrated failure to notice every other class.
- **LLM:** one plain prompt, written once and never iterated. It does ask for
  JSON output with a function name, which makes parsing easy and may push the
  model to always name *some* function. We did not try other prompts or
  models, so the LLM numbers hold only for this prompt and for `qwen3.8:27b`.

## 3. Is the benign corpus realistic, or does it dodge our rules by luck?

**It is the course corpus, and for V1 the 0 % FP is partly luck.**
`benign_traffic.json` has 26 inputs, 9 of them usernames. V1's 0 % FP is honest
on this corpus, but a perfectly normal search like `la fièvre de l'or` (French,
"the gold rush") or `it's 'or nothing'` would trip "quote then OR" (checked). We did not invent such inputs, because choosing
benign inputs that we know break our own rules is also tuning. With n = 9
usernames, one more blocked name moves the FP rate by 11 points, so the 0 % and
22 % figures are rough estimates, not tight measurements. The corpus also
includes no non-English or long free-text fields beyond `María José`.

## 4. Which Part-A finding are we least sure reproduces, and why?

**Command injection.** vuln-web *simulates* the shell: `do_ping` returns the
command it would run plus a regex flag (`injection_detected`) and never calls
`os.system`. Our oracle requires that flag **and** the smuggled `whoami` in
`would_run`, so it shows that attacker data reached the command string. It does
not show that a command ran. Two consequences:

- `127.0.0.1 &;& whoami` relies on the Medium filter removing `;` and leaving
  `&&`. In a real shell that runs `whoami`. `127.0.0.1 & whoami` would also run
  it, in the background. Neither was executed.
- `$(whoami)` is flagged because `$` and `(` are in the app's regex. A real
  `ping` would receive the substituted user name as an extra argument. That is
  still command execution, but the output would show up differently.

The SQLi and XSS findings are stronger. The canary actually comes out of a real
SQLite query, and the `<script>` tag is really in the HTML. One caveat for XSS:
we never loaded the page in a browser to watch the script run. The oracle's
claim that the tag is executable relies on HTML parsing rules (tag names are
case-insensitive), not on an observed execution.

## 5. Our "Medium" level is ours, not DVWA's

vuln-web has no security levels. We wrote [`attack/medium_app.py`](attack/medium_app.py)
following DVWA's Medium filters (the XSS and cmdi filters copy DVWA's lists;
the SQLi one is a DVWA-style keyword strip, because DVWA Medium SQLi relies on
`mysql_real_escape_string` on a numeric parameter, which has no equivalent in a
string-quoted SQLite query). Because we wrote the filter, we could also write
one that is easy to bypass. We tried to copy DVWA's real weaknesses
(case-sensitive `str_replace`, single-pass removal) rather than invent new ones,
but a grader should treat "Medium" here as "a DVWA-style blocklist", not as
DVWA itself.

## 6. Follow-up verification and reused coverage inputs

The later local readiness check adds 20 supplementary SQLi strings from
Mauricio's Week 7 corpus and executes them again against the HW2 handlers.
Only the inputs are reused; earlier studio measurements are not submitted as
new HW2 evidence. The corpus is narrow and many strings share the same shape:
all 20 leak at Low, but Medium and both WAF versions stop all 20. That is a
useful coverage sample, not evidence that any of those filters is secure. The
separate bypass cases still leak through V1 at Low and before Medium.

The follow-up also replays all Part-A classes on their own endpoints, measures
the Medium/WAF composition explicitly, and validates a renamed submission copy.
The original group scanner/LLM raw outputs and six original result CSVs remain
preserved. The new runs and controls are in `results/readiness/`; they are
additional evidence, not retroactive proof of the original model-run chronology.
