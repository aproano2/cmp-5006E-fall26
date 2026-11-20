# Part B — Deploy, bypass, then fix SQLi

Primary evidence: [dvwa_deployed_results.csv](dvwa_deployed_results.csv), generated
against the original DVWA Medium endpoint, with three trials per input.

## B1: deployed negative model

[medium_waf.php](medium_waf.php) runs before the original vulnerable PHP sink.
It blocks numeric equality tautologies, UNION SELECT, script tags, DROP TABLE,
and selected shell punctuation after normalization. Coverage is 3/3 original
Part-A strings. The evaluated vulnerability is SQLi; the other two strings are
also replayed through this filter as coverage probes, not as attacks on their
original XSS/command endpoints during this stage.

All three same-intent SQLi variants pass the deployed WAF and leak the extra row:

| Payload | WAF-stage successes |
|---|---:|
| `1/**/OR/**/1=1` | 3/3 |
| `1 OR TRUE` | 3/3 |
| `1 OR 2>1` | 3/3 |

They preserve numeric query expansion while avoiding the WAF's whitespace and
numeric-equality signature. The initial `1 OR 1=1` is blocked (0/3 leaks).

[dvwa_waf_benign_results.csv](dvwa_waf_benign_results.csv) records 2/26 supplied
generic corpus values blocked: **7.69% FP**. One is legitimate search prose,
`drop table tennis lessons for beginners`. Values are sent through this filter
at the ID boundary to measure signatures; the corpus mixes fields and is not
a corpus of valid numeric IDs. This rate is a teaching-corpus classification
cost, not a production DVWA usability estimate. Python and deployed PHP use the
same intended rules and normalization.

## B2: our own positive model on the same target

[medium_parameterized.php](medium_parameterized.php) replaces the Medium MySQL
query with a constant prepared statement and a bound parameter. It HTML-encodes
the displayed ID and names as well. All six Part-A/bypass strings are replayed
at this SQLi sink: **0/6 leak the extra row**, each over three trials. Benign ID 1
still returns admin. This is our authored patch, separately evaluated from
DVWA's supplied Impossible implementations.

**Conditional guarantee:** as long as this statement is prepared and its ID is
bound with mysqli_stmt_bind_param, user input is one data value and cannot
change SQL structure, for any string. MySQL can coerce strings to numbers when
comparing IDs; this does not permit added predicates. This guarantee does not
establish authorization or repair other SQL statements or the separate injection
sinks. The WAF recognizes selected spellings and offers no structural guarantee.

The evaluator verifies an implementation marker after deployment, waits for
Apache OPcache revalidation, rejects request errors, and restores original source
in finally. This prevents cached WAF responses or broken endpoints from being
counted as a successful parameterized fix. Medium is restored after the supplied
Impossible comparisons too.

## Supplemental and historical evidence

The notebook additionally replays SQLi (0/4), XSS (0/2), and command injection
(0/2) at supplied Impossible implementations and verifies three functional benign
controls. This supplied code is not claimed as group-authored.

[evaluate.py](evaluate.py) is the independently runnable SQLite supplement:
three SQLi bypasses, parameter binding, and the same generic corpus. Its
sqli_results.csv and benign_results.csv are not relabeled as DVWA evidence.
[recorded_results.txt](recorded_results.txt) retains Santiago's original run.
