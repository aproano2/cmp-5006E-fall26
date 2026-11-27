# Part C: The duel, LLM vs. classical scanners

```bash
python3 duel/score.py           # scores the committed raw outputs in duel/raw/
python3 duel/run_scanners.py    # optional: re-run semgrep + bandit + sqlmap (needs them on PATH)
python3 duel/llm_review.py      # optional: re-run the LLM (Ollama + qwen3.8:27b, ~3-4 min per run)
python3 duel/llm_ablation.py    # optional: LLM with vs. without the # VULN hints (see below)
python3 duel/ablation_score.py  # scores the ablation -> results/llm_ablation_scores.csv
```

> **On the CSRF and "session tokens" hallucinations (this copy's nuance).** We
> scored both as false positives, and for scoring that is right — vuln-web has no
> auth, session or cookies, so there is no classic CSRF (the browser has no
> credential to send automatically) and there are no session tokens. But two
> honest caveats: (a) the POST endpoints *do* accept `application/x-www-form-urlencoded`
> bodies (`_form()` falls back to `parse_qs`), so a cross-origin HTML form could
> submit to `/ping` — the model's *mechanism* is not pure fiction, only its
> "authenticated user" premise is; (b) the "session tokens" wording is likely
> primed by the canary column being named `...-admin-session`. So the hallucination
> is best described as a right-sounding checklist item applied without checking
> whether the app has the thing it assumes, not as an invented capability.

> **Comment ablation (`duel/llm_ablation.py`).** honesty.md §1 notes the source
> names every bug in a `# VULN` comment, which helps an LLM reader. This runs the
> same prompt on the source with and without those comments (same model) and
> scores both, so the hint effect is measured. Results in
> `results/llm_ablation_scores.csv`; the model used here is the locally installed
> one, not the main duel's qwen, so it is an original-vs-stripped comparison, not
> a reproduction of the qwen runs.
>
> **Measured result (3 runs each, local model):** mean recall **100 % with the
> comments and 100 % without** — removing the `# VULN` hints did *not* cost recall
> on these three textbook sinks; the model finds them from the code itself. Mean
> precision went 100 % → 83 %, because the stripped runs also surfaced the real
> (out-of-scope) information-disclosure bug. So for this model the hints were not
> load-bearing for *finding* the three sinks. That is a narrower, honest claim
> than "the comments give the LLM the answers"; a larger model or a subtler bug
> could still depend on them, which is why the ablation is the evidence, not the
> guess.

**Target:** `labs/vuln-web/app/vulnweb_app.py`. The same file was attacked in
Part A, so every finding can be checked by reading it.

| Arm | Tool | How it was run |
|---|---|---|
| static scanner | **semgrep 1.184.0** | community rulesets `p/python`, `p/security-audit`, `p/owasp-top-ten`, `--metrics off`, no custom rules |
| static scanner | **bandit** | default ruleset |
| dynamic scanner | **sqlmap** | default `--level 1 --risk 1 --batch` against all 4 endpoints of the live app on 127.0.0.1 |
| LLM reviewer | **`seclab.LLM`, Ollama `qwen3.8:27b`** | one plain prompt ([`llm_review.py`](llm_review.py)), 5 runs: temperature 0 with seed 0 (×2), temperature 0.7 with seeds 1/2/3 |

## Ground truth (built by hand, before any tool ran)

[`ground_truth.json`](ground_truth.json) was written by reading the source, then
frozen. Scored findings: **`sqli/do_login`, `xss/do_reflect`, `cmdi/do_ping`**.
True negative: `do_reflect_safe`. Not present: `broken-access-control`.
Real but out of scope (listed by us, not scored as TP): `information-disclosure`
(the SQL error + query are echoed back), `plaintext-password`,
`hardcoded-credentials`. `score.py` checks that our scored set equals the
instructor fixture: **True**. It was **not** built from "whatever sqlmap found".

Matching uses `seclab.scan`'s coarse key, `(rule, function)`. Tool vocabulary
is normalized to our rule names in `score.py` (`norm_rule`). semgrep and bandit
report file:line, which is mapped to the enclosing function with `ast`. sqlmap
reports an endpoint, which is mapped to its handler function.

## 1. Precision, recall, F1 (`results/duel_scores.csv`)

| Tool | TP | FP | FN | Precision | Recall | F1 | Adj. precision* |
|---|---|---|---|---|---|---|---|
| semgrep | 0 | 0 | 3 | n/a (0 reports)** | **0 %** | 0.00 | n/a |
| bandit | 1 | 2 | 2 | 33 % | 33 % | 0.33 | 33 % |
| sqlmap | 1 | 0 | 2 | **100 %** | 33 % | 0.50 | 100 % |
| LLM, T=0 (runs a, b) | 3 | 4 | 0 | 43 % | **100 %** | 0.60 | 50 % |
| LLM, T=0.7 (seeds 1, 2, 3) | 3 | 1 | 0 | 75 % | **100 %** | 0.86 | 100 % |

\* Adjusted = findings whose exact normalized `(rule, location)` key is in
`out_of_scope_real` removed before scoring. Bandit's B105 at `<module>` flags the
canary constant; it does not match the real hardcoded credentials in `make_db`
and remains a false positive. The original source excluded by rule alone; this
local copy corrects that secondary metric. Strict scores are unchanged.
\*\* `seclab.scan` prints 0 % when a tool reports nothing; precision is really undefined.

The pattern the week-6 deck predicted shows up here, but not perfectly. The LLM
has the highest recall (3/3 in every run) and pays for it in precision (4 extra
findings at T=0). sqlmap is perfectly precise and narrow. The default static
rules did badly on a framework-less stdlib app.

## 2. The LLM's best hallucination and the scanner's worst miss

**LLM hallucination: "Missing CSRF Protection" in `do_POST` (T=0, both runs).**
The model wrote that the POST endpoints accept requests "without any anti-CSRF
token or SameSite cookie enforcement, allowing a malicious page to trigger
state-changing actions on behalf of an authenticated user". vuln-web has **no
authentication, no session and no cookies**: nothing in the file sets or reads a
cookie, and no user is ever "authenticated". CSRF needs the browser to send
credentials automatically, and there are none, so there is no CSRF bug. The
model applied a generic web checklist without checking whether the app has a
session at all. Runner-ups from the same runs:

- "Sensitive Data Exposure … leaking privileged data such as **session tokens**"
  (`do_login`). There are no session tokens. The `secret` column holds our canary
  string, and it is returned only because the SQLi lets the attacker pick the row.
  The model is restating the SQLi as a second bug.
- "Unrestricted Network Binding" (`main`, `0.0.0.0`) and "No Rate Limiting"
  (`do_POST`): real hardening topics, not vulnerabilities in a container that
  `seclab.targets` publishes only on `127.0.0.1` (bandit's B104 makes the same
  false call).

What the LLM did **not** do: it never flagged the escaped `/safe` endpoint and
never claimed Broken Access Control. That is better than the canned review in
the week-6 studio predicted, for this model and this prompt.

**Scanner's worst miss: semgrep missed the SQLi in `do_login` (and the other two
sinks, 0/3).** This is the textbook case: an f-string with `{user}` and `{pw}`
inside a `SELECT … WHERE`, then `DB.execute(query)`. The committed runner uses the
three community rulesets listed above; its committed raw output records the
target as scanned, no errors, and no findings. The group log also describes
additional exploratory rulesets, whose separate outputs are not committed.
The query is built in a variable over two
lines and executed through a module-global `DB`, which the community rules'
patterns did not match. That is a known weakness of syntactic matching. bandit's
B608 did catch it (it looks for SQL keywords inside string formatting), so the
miss is about the ruleset, not about static analysis in general. Neither sqlmap
nor bandit contributed a confirmed XSS or cmdi finding to these scores. sqlmap's
raw `/` output does contain a heuristic XSS warning; the scorer excludes that
unconfirmed hint and counts only its identified SQL injection points. For
bandit there is no `os.system`/`subprocess` call or web framework
to anchor a rule on (the cmdi is simulated).

## 3. Non-determinism (axis 9), 5 runs (`results/llm_nondeterminism.csv`)

| Finding | T=0 a | T=0 b | T=0.7 s1 | s2 | s3 | runs |
|---|---|---|---|---|---|---|
| sqli/do_login (TP) | ✓ | ✓ | ✓ | ✓ | ✓ | 5/5 |
| xss/do_reflect (TP) | ✓ | ✓ | ✓ | ✓ | ✓ | 5/5 |
| cmdi/do_ping (TP) | ✓ | ✓ | ✓ | ✓ | ✓ | 5/5 |
| information-disclosure/do_login (real, out of scope) | ✓ | ✓ | ✓ | ✓ | ✓ | 5/5 |
| csrf/do_POST (hallucination) | ✓ | ✓ | · | · | · | 2/5 |
| missing-rate-limiting/do_POST | ✓ | ✓ | · | · | · | 2/5 |
| bind-all-interfaces/main | ✓ | ✓ | · | · | · | 2/5 |

- **T=0 with a fixed seed is reproducible here.** Runs a and b are
  byte-identical (2,477 chars each, checked with `cmp`), on the same machine with
  the same Ollama build and model digest. That is reproducibility under those
  conditions, not determinism in general.
- **Sampling changes the findings.** At T=0.7 the 3 false positives
  (CSRF, rate limiting, binding) disappear. So the precision you report (43 % vs.
  75 %) depends on a setting that has nothing to do with the code. A report from a
  single run would have got either number by chance.
- **Below the set level, the runs still differ.** XSS severity was HIGH in 3
  runs and MEDIUM in 2. The wording changes from run to run ("Excessive Data
  Exposure in Response" vs. "Sensitive Data Exposure"). Response length ranged
  from 1,471 to 2,477 chars, and run time from 150 to 247 s.
- **The scanners are deterministic for a fixed version and ruleset.** Re-running
  `run_scanners.py` gave the same findings. sqlmap's random payload markers change
  between runs, but its verdict did not.

Caveat: the coarse `(rule, function)` key merges two LLM items in `do_login`
("Information Disclosure" and "Sensitive Data Exposure") into one key. A finer
key would count one more FP per run.

## 4. Did either tool find an access-control issue?

**No, and that is the correct answer.** The ground truth lists
`broken-access-control` as *not present*: the file has no authentication,
session, role or ownership code, so there is no authorization decision to
break. No scanner has a rule that could fire on missing code it was never told
about, and the LLM never claimed A01 in 5 runs. But the CSRF and "session
tokens" hallucinations show that the LLM assumed an authenticated-user model
that does not exist. A01 needs **app context** (who is allowed to see what),
which neither a pattern matcher nor a model reading one file has. The SQLi in
Part A has an access-control-like *effect* (an anonymous user reads admin data),
but that is caught as injection, not as A01 (see `attack/README.md`).

## Bottom line

- The LLM (this model, this prompt) **won on recall** and **lost on precision at
  T=0**. Its best hallucination is a CSRF bug in an app with no sessions.
- The scanners were precise or silent. Their **worst miss is semgrep's 0/3**, which
  includes a textbook f-string SQLi.
- None of these numbers holds without the run settings: the LLM's precision
  moved from 43 % to 75 % just from changing the temperature.
