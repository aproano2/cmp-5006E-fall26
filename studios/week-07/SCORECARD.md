# Week 7 — Control Scorecard (Task 6)

Evidence comes from `test_waf.py` (all 6 pass) and `python starter.py`.
Threat model for both rows: an **unauthenticated remote attacker** who can send
arbitrary strings to the `vuln-web` `/login` form, with no credentials and no
access to the server.

## Measured numbers

| Measurement | Result |
|---|---|
| Coverage on KNOWN week-6 attacks (Task 1) | **4/4 blocked**, the trap |
| Same-intent bypasses through the WAF (Task 2) | **3/4 passed** (`OR 'a'='a'`, `<img onerror>`, zero-width `DR​OP`) |
| False positives on the 26-input benign corpus (Task 3) | **2/26 = 7.7 %** blocked, both by `SQLi DROP TABLE` |
| Injections that succeed under parameterization (Task 4) | **0/8** (4 attacks + 4 bypasses) |
| WAF-passed bypass leaks the admin canary on the real app (Task 5) | **True**: `admin' OR 'a'='a'--` dumps the canary |
| `anomaly()` flags among the 3 WAF-passed bypasses | **1/3** (`OR 'a'='a'`), with **0/26** benign flagged |

Legit requests the WAF turned away:
- `drop table tennis lessons for beginners`
- `reserve the drop table at the makerspace friday`

## Scorecard (all 8 axes)

| Axis | WAF blocklist | Parameterized queries | WAF as detection (`anomaly`) |
|---|---|---|---|
| **1 · Threat model** | Remote, unauthenticated attacker, free to mutate payloads | same | same |
| **2 · Guarantee** | **None.** "Blocks the 4 patterns in `WAF_RULES`". No claim about the next payload. | **"User input cannot alter query structure, for any input"**, *provided every query on the path binds input as a parameter* (one string-formatted query anywhere voids it). | None, but it gives **visibility** |
| **3 · Coverage** | 4/4 known, but only **5/8** once the bypasses are included | **8/8** stopped (0/8 succeed) | 1/3 of bypassed requests flagged |
| **4 · Bypass** | **Yes, trivial.** 3/4 mutations pass, and `OR 'a'='a'` leaks the canary on the real app | **None found.** The input is compared as a literal value, so no payload can reach a code context. | Yes: `<img onerror>` and the zero-width `DROP` are not flagged |
| **5 · FP cost** | **High: 7.7 %** of legit inputs blocked (2/26) | **Zero.** `o'brien` and `drop table tennis` log in or fail normally | 0/26 benign flagged, but every flag costs analyst time (wk 13) |
| **6 · Op cost** | Not measured. Regex scan per request, plus ongoing rule tuning forever | Not measured. Essentially free, but a one-time code change at every query | Not measured. Analyst hours per flag |
| **7 · Observability** | Good: `waf_block` returns the **rule name** that fired, which can be logged | Weak: a failed injection just looks like a failed login. No signal that someone tried. | **Its whole purpose**: it flags requests for human review |
| **8 · Failure mode** | **Fails open.** A bypass passes silently, and a WAF disabled because of FPs has coverage 0 | **Fails closed** for the queries it covers. A single unparameterized query fails silently. | **Alerts a human**, it doesn't block (a sensor, not a wall) |

## Fast-finisher: one more rule for `OR 'a'='a'`

Rule tried: `(?i)'\s*or\s+'([^']*)'\s*=\s*'\1'` (quote, OR, then a quoted string equal to itself).

- It **blocks** `admin' OR 'a'='a'--` and has **0 FPs** on the 26 benign inputs, including
  `director of operations or equivalent role` (no quote before the `or`).
- But five more minutes of mutation get through **both** the old rules and the new one,
  and on the real app each of these **leaks the canary**:
  `OR 'a' LIKE 'a'`, `OR 2>1`, `OR TRUE`, and `/**/OR/**/'a'='a'`.

**Why the tradeoff has no clean setting:** a tautology is any expression that is
always true, and there are infinitely many ways to write one in SQL. A rule narrow
enough to stay quiet on English (`or`, `drop table`, `select`, `union`) only matches
one spelling. A rule broad enough to cover the meaning (e.g. "a quote followed by
`or`") starts catching `o'brien or equivalent`-style text. The blocklist tries to
recognise SQL *meaning* from raw text without parsing it, and that problem can't be
solved by adding more regexes. Parameterization avoids it completely: the input
never gets parsed as SQL at all.

## Where we may have been unfair, and what we did not test

- **The corpus is small.** 8 attack payloads plus 6 extra mutations, which is below the
  rubric's ≥ 20. The benign corpus is 26 inputs, so the 7.7 % FP rate has a wide margin of error.
- **"Passed the WAF" is not the same as "exploited".** Of the 3 bypasses, only `OR 'a'='a'`
  leaked the canary on `/login`. `<img onerror>` is XSS, which needs an HTML sink, and the
  zero-width char breaks the SQL syntax as well. We did not test them against the sinks where
  they would work.
- **`parameterized_login` is a model** (a dict lookup), not real SQL with bound parameters.
  The real `vuln-web` app is still string-formatted. We did not port it to `?` placeholders
  and rerun Task 5 against it.
- **The WAF is a toy** (4 regexes), not a real ModSecurity CRS ruleset, which would catch
  more variants but also produce more FPs. Our numbers don't transfer directly.
- **Operational cost (axis 6) was not measured** (no latency or CPU numbers).
- **Not tried:** encoding bypasses (URL/Unicode/hex), second-order injection, and whether
  `anomaly()` false-positives on a larger, realistic benign corpus.
