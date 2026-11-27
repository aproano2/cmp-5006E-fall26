**Group:** María Emilia Cueva (00328938), Santiago Reátegui (00331329), Jorge Gomez (00329264)
# Part B: Defend, bypass, measure, fix

Run `python3 defend/run.py` (or  `python defend/run.py` on Windows) from the submission root. The selected vulnerability is SQLi in `do_login`. The test process sends requests to the copied target over loopback through our Medium layer and the added WAF.

## B1: Negative-model WAF

`waf.py` rejects user names containing `or`, `union`, `select`, or `drop` case-insensitively. This intentionally broad substring blocklist covers the Part-A SQLi payload: **1/1 blocked** at the login sink, with canary oracle 0/3. It is not an XSS or cmdi defense; those are separate sinks.

| Same-intent WAF bypass | Why it passes | Evidence |
|---|---|---|
| `admin'--` | Removes the password clause with a SQL line comment, no blocked word. | HTTP 200; admin canary 3/3. |
| `admin'/*` | Starts a SQLite block comment, swallowing the password clause, no blocked word. | HTTP 200; admin canary 3/3. |
| `admin' AND 1=1--` | Adds a true condition and comments out the password, without a blocked word. | HTTP 200; admin canary 3/3. |

These are working SQLi payloads: the oracle checks the returned admin canary, not merely that the filter returned `None`.

The supplied benign corpus has **26** requests in three fields. The SQLi WAF is deployed only on `/login` usernames, so the applicable rate is **2/9 = 22.22%**. Across all supplied benign requests the rate is **2/26 = 7.69%**. The blocked legitimate names are `select_committee_chair` and unionrep_delegate`. The original corpus self-check defines these as benign; our measurement is recorded input by input in [benign_results.csv](benign_results.csv).

## B2: Positive-model fixes

`fixed.py` uses SQLite placeholders for **both** login inputs and executes a constant query structure. It also HTML-escapes the reflected name and validates the ping host into an argument vector without forming a shell command. The lab preserves the original no-execution policy for ping.

With Medium and the WAF both disabled, all **six** malicious inputs were retested three times: Part-A SQLi, XSS, cmdi and all three B1 SQLi bypasses. Their respective security-effect oracles were **0/3 each**; the correct admin password still succeeds in the fixed login function. See [results.csv](results.csv).

The SQLi guarantee is conditional: user and password input cannot alter the query structure **if** every SQL value is bound as a parameter and the database driver preserves parameter/data separation. HTML script injection is prevented for this text-node context **if** every untrusted value is escaped for that context before response assembly. Shell metacharacters cannot cause additional commands **if** a real ping implementation passes the validated host as one argument with `shell=False`; the teaching copy does not launch ping. The WAF cannot give any of these guarantees because it enumerates forbidden strings.
