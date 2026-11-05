# Homework 2 

## Group members

- Felipe Rodríguez-00330528
- Josué Ponce-00330341

I chose the course's `vuln-web` target and SQLi as the main vulnerability for
comparing negative and positive defenses. This submission includes executable
code, HTTP responses, and actual measurements.

## Reproduce the results

From the repository root, using Python 3.10 or later with no dependencies:

```bash
python3 homework/hw2/rodriguez_felipe/run.py
```

The script starts temporary servers on `127.0.0.1` using available ports, runs
three trials per payload and mode, checks the expected results, and shuts down
the servers. A transport error or an unmet expectation causes the run to fail.
It regenerates the CSV files, responses, and `defend/summary.json`. Timestamps,
the Python version, and hashes identify the run.

To inspect each defense manually:

```bash
python3 homework/hw2/rodriguez_felipe/target.py --mode original
python3 homework/hw2/rodriguez_felipe/target.py --mode waf
python3 homework/hw2/rodriguez_felipe/target.py --mode positive
```

Run one server at a time; stop it with Ctrl+C. The `--port` option is configurable.

## Target and modes

Following the professor's clarification, Part A tests the original
`labs/vuln-web/app/vulnweb_app.py` directly, without student filters.
`target.py --mode original` returns the course's unmodified `app.Handler`;
only the local server binding and fresh test database are managed by the runner.
The `waf` mode adds our login blocklist, and `positive` applies the structural
fixes.

The existing payloads are retained for reproducibility. `A_control` identifies
three baseline payloads (uppercase SQL `OR`, lowercase script tags, and a
semicolon command separator); `A` identifies their lowercase SQL, mixed-case
tag, and pipe variants. All six succeed in 3/3 trials against `original`.

## A — Evidence and classification

All results go through `seclab.attack.run_payloads` with `trials=3`.
See [attack/results.csv](attack/results.csv) and the responses for each trial in
[attack/responses.json](attack/responses.json).

- **SQLi:** `POST /login`, username `admin' or 1=1--`, password `x`. SQLite
  interprets the lowercase `or`, and `--` removes the password condition. The
  oracle requires `ok=true` and the exact row
  `["admin", "FLAG-sqli-9f2c-admin-session"]` inside `rows`; it does not accept a
  SQL error or a reflected query. Confirmed in 3/3 trials.
- **Reflected XSS:** `GET /?name=...`, with URL-encoded
  `<ScRiPt>alert(1)</ScRiPt>`. The original target reflects the input without escaping. The oracle parses
  the HTML and finds an unescaped `script` element and its code. Confirmed in
  3/3 trials under the homework's criterion. No browser was automated, and no
  observed JavaScript execution is claimed.
- **Simulated command injection:** `POST /ping`, host
  `127.0.0.1 | printf CMDI_OK`. The host reaches the simulated command unchanged. The oracle
  requires `injection_detected=true` and either `| printf CMDI_OK` or
  `; printf CMDI_OK` inside `would_run`, covering both variants.
  Confirmed in 3/3 trials in the course simulator. Neither `printf`, `ping`, nor
  any other process was executed; this does not demonstrate actual shell
  execution.

All three classes fall under **A03:2021 Injection**, including XSS (CWE-79), SQLi
(CWE-89), and command injection (CWE-78), according to
[OWASP A03:2021](https://top10.owasp.org/2021/A03_2021-Injection/).

The SQLi retrieves admin data with an incorrect password, but the demonstrated
cause is the interpretation of input as SQL. This app has no sessions, roles,
private routes, or resource identifiers belonging to other users with which to
demonstrate an independent authorization flaw. We do not count another A01
vulnerability for the same effect. This does not prove the universal absence of
flaws: no access policy was defined for the public endpoints. This distinction
uses the definition of authorization in
[OWASP A01:2021](https://top10.owasp.org/2021/A01_2021-Broken_Access_Control/).

## B1 — Deployed WAF, bypasses, and cost

In `waf` mode, `target.py` applies the blocklist from
[defend/controls.py](defend/controls.py) to **both `/login` fields**, before the
actual sink. It rejects `OR` as a word or the
substrings `select`, `union`, and `drop`, ignoring case. It is not presented as a
production WAF.

Coverage of Part A (`A` and `A_control`): **2/2 SQLi payloads blocked (100%)**;
**2/6 total payloads blocked (33.33%)**. XSS and cmdi retain 3/3 successes each because this blocklist
protects only the login. Their failure is not counted as SQLi coverage.

The defense was deployed before testing these three additional payloads with
the same goal: retrieving the admin canary using password `x`.

| Username payload | Why it bypasses the WAF | Original | WAF | Positive defense |
|---|---|---|---|---|
| `admin'--` | The comment removes the password check without blocked words | 3/3 | 3/3 | 0/3 |
| `admin' and pw glob '*'--` | True GLOB predicate; does not use OR | 3/3 | 3/3 | 0/3 |
| `admin' and 2 between 1 and 3--` | True BETWEEN predicate; does not use OR | 3/3 | 3/3 | 0/3 |

These bypasses are confirmed by returned rows, not merely accepted requests.
Changing case alone does not bypass this WAF; changing the SQL construction does.

The **26 original entries** from
[`benign_traffic.json`](benign_traffic.json), copied unchanged from the course fixture, were sent to their corresponding
endpoints without modifying the corpus or applying login rules to searches.
See [defend/benign_results.csv](defend/benign_results.csv).

- Login: **2/9 false positives (FP) = 22.22%**.
- Entire corpus: **2/26 FP = 7.69%**; the other fields dilute the average.
- Blocked legitimate requests: usernames `select_committee_chair` and
  `unionrep_delegate`, because they contain the substrings `select` and `union`.
- Original: **0/26** blocked. Positive defense: **0/26** blocked.

Returning `ok=false` for nonexistent credentials is a normal authentication
response, not a false positive. Here, FP means filter rejection (403) of a
legitimate corpus entry. The corpus is small and deliberately includes words
that challenge filters; these rates do not estimate real traffic.

## B2 — Structural fix and guarantee

The `positive` mode replaces the interpolated query with SQLite placeholders:

```python
db.execute(
    "SELECT user, secret FROM users WHERE user = ? AND pw = ?", (user, pw)
)
```

It does not depend on the WAF. **If every username and
password input reaches the query exclusively as a value of these parameters,
the query preserves its structure for any input string.** The guarantee is
limited to this sink and correct API usage: it does not imply protection of
future dynamic queries or authorization flaws. Separating data from queries is
the prevention recommended by
[OWASP A03](https://top10.owasp.org/2021/A03_2021-Injection/).

To satisfy the requirement to repeat *all* Part A payloads literally, I also
added `html.escape` encoding in the HTML text context and positive host
validation with argument-list construction (simulated, without a shell).
These are auxiliary fixes and are not attributed to parameterization. The host
accepts only letters, numbers, dots, and hyphens, starts and ends with a letter
or number, and has a bounded length; it does not attempt to validate all DNS
names. The XSS guarantee applies to this text context, not to JavaScript or
attributes.

Result: the **6 Part A payloads (including `A_control`) + 3 B1 bypasses** each
have **0/3 successes** in positive mode (**0/27 trials**).
Valid admin and alice logins still work, incorrect passwords fail, and SQLi
attacks are also tested in the password field. Normal hosts and names remain
accepted. The CSV files and `defend/summary.json` record the measurements.

The blocklist recognizes a finite set of signatures: its three bypasses and
two false positives demonstrate both its incomplete coverage and its cost.
Parameterization prevents values from being interpreted as SQL structure; the
27 trials are experimental evidence, while the guarantee follows from the
separation of code and data rather than the size of the test set.

## C and D — Comparison and limitations

See [duel/results.md](duel/results.md) for the scores, hallucination,
scanner miss, run-to-run changes, and access-control result, and
[honesty.md](honesty.md) for the limitations.
[ground_truth_review.md](ground_truth_review.md) documents fixture provenance
and source verification. Both JSON fixtures are included in this directory.

Recompute the comparison from the committed original tool outputs:

```bash
python3 homework/hw2/rodriguez_felipe/duel/run_duel.py --replay
```

This does not make new model calls. Fresh-run instructions and dependencies are
in [duel/README.md](duel/README.md). Strict scoring retains malformed labels and
all reported entries without inferring vulnerability classes from function names.
