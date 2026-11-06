# Part B: Defend the SQLi, then bypass our own defense

```bash
python3 defend/defend.py        # from homework/hw2/leon/
# writes results/defense_attacks.csv and results/waf_false_positives.csv
```

We defend **SQLi in `do_login`** (`POST /login`). Every attack below is sent
through HTTP to a real copy of vuln-web on 127.0.0.1, 3 trials each, and judged
by the **canary oracle** (the admin secret comes back while the password is
wrong). We never judge by "the WAF said PASS" alone.

Four servers run side by side: no defense, WAF_V1, WAF_V2, and parameterized.
The WAFs sit directly in front of the plain (Low) sink, not stacked on the Medium
filter, so the numbers show what the WAF alone does.

## B1: Negative model (blocklist WAF), [`waf.py`](waf.py)

**WAF_V1** (the one we deploy) has 4 regex rules, written against our Part-A SQLi
payloads, and inspects every `/login` field (`user` and `pw`):

| Rule | Regex |
|---|---|
| quote then OR | `(?i)'\s*or\b` |
| quote then comment | `'\s*(--\|#\|/\*)` |
| UNION SELECT | `(?i)union\s+select` |
| numeric tautology | `(?i)\bor\b\s+\d+\s*=\s*\d+` (from the week-7 studio) |

### 1. Coverage (axis 3)

All 5 Part-A SQLi payloads that work against the undefended sink are blocked:
**5/5**. (`admin'-#-` is left out because it only works when the Medium filter
rewrites it. At Low it does nothing, 0/3.)

### 2. Bypass (axis 4): 4/4 same-intent payloads get through

Each one was written after V1 was frozen, and each leaks the canary through the
WAF 3/3 times:

| Payload | Field | Why it evades V1 |
|---|---|---|
| `x' IS NOT 'y` (user = `admin`) | `pw` | No OR and no comment. SQLite parses `pw = 'x' IS NOT 'y'` as `(pw='x') IS NOT 'y'`, which is always true, so `user='admin'` alone decides. |
| `admin' AND 1--` | `user` | The comment is not right after the quote, so "quote then comment" never matches. |
| `admin' AND 1/*` | `user` | Same idea with an unterminated block comment. |
| `x' UNION ALL SELECT user, secret FROM users WHERE 1--` | `user` | `UNION ALL SELECT`: the rule expects `UNION` directly followed by `SELECT`. Dumps every row. |

### 3. False positives (axis 5), on the benign corpus (26 inputs)

The corpus is [`benign_traffic.json`](benign_traffic.json), an unmodified copy of the
course's `duel-2-web/benign_traffic.json`, committed here so the submission is
self-contained.

| WAF | `login_username` (the field it guards) | whole corpus (site-wide WAF) | bypasses that still land |
|---|---|---|---|
| **V1** (deployed) | **0/9 = 0 %** | **0/26 = 0 %** | **4/4** |
| **V2** = V1 + any `'` + SQL keywords + comments anywhere | **2/9 = 22 %** | **8/26 = 31 %** | 0/4 |

V1 blocked **no** legitimate request. When we hardened it into V2 to stop the four
bypasses, it blocked real users. Legitimate requests V2 blocks:

- `o'brien` and `d'angelo` (real surnames; "any single quote")
- `i want to select the union option on the benefits form`, `drop table tennis
  lessons for beginners`, `the OR gate and the AND gate in digital logic`,
  `director of operations or equivalent role`, `reserve the drop table at the
  makerspace friday` ("SQL keyword")
- `quotes about resilience: "don't give up"` ("any single quote")

These are the two blades of a blocklist. A narrow rule set (V1) has no false
positives and can be bypassed. A rule set wide enough to stop our bypasses (V2)
blocks 31 % of real traffic. We found no bypass for V2, but only because
"block every `'`" forbids the one character any string-context SQLi needs. It is
an allowlist in disguise, and O'Brien can no longer log in. We tried only these 4
bypasses against V2, so "no bypass found" is not a guarantee.

## B2: Positive model (the real fix), [`fixed_app.py`](fixed_app.py)

```python
QUERY = "SELECT user, secret FROM users WHERE user = ? AND pw = ?"
rows = app.DB.execute(QUERY, (user, pw)).fetchall()
```

The SQL text is a constant, and `user`/`pw` are sent to SQLite as bound values.
As a side fix, the error path no longer echoes the SQL query and DB error back
(that was a separate CWE-209 information leak in the original `do_login`).

### 5. Re-run of all Part-A payloads and all B1 bypasses

| Defense | attacks that still leak the canary (of 9 that work undefended) |
|---|---|
| none | 9/9 |
| WAF_V1 | 4/9 (exactly the 4 bypasses) |
| WAF_V2 | 0/9, at a 31 % false-positive cost |
| **parameterized** | **0/9**, at 0 % false-positive cost |

Functional checks on the fixed app: `admin`/`s3cr3t` still logs in (`ok: true`),
and `o'brien` gets a normal `{"ok": false}`. On the vulnerable app the same
input crashes the query (`sql error: near "brien"`), so the fix also repairs a
real user that the vulnerability itself was breaking.

### 6. The guarantee (axis 2), stated as a conditional

> **Provided that** every query in `fixed_login` is issued through `sqlite3`
> placeholders with a constant SQL string (no string formatting or concatenation
> anywhere on the path), and the `sqlite3` driver binds parameters correctly,
> **then no value of `user` or `pw` can change the structure of the query, for
> any input.** As a consequence, the canary is returned only when the submitted
> (`user`, `pw`) pair is equal to a stored row.

**Why the WAF cannot make this claim:** a blocklist only lists inputs it knows
are bad. Its claim is "none of these N patterns appear", which says nothing about
the infinite set of inputs it never listed (V1 → 4 bypasses). Every rule we add to
close a gap also catches legitimate text that shares the pattern (V2 → 31 % FP),
because the WAF sees a string, not the query grammar the string will be pasted
into. Parameterization does not inspect the input at all. It removes the
channel through which input could become code. The WAF can make an attack more
expensive, but parameterization removes the bug, and that is why only
parameterization comes with a guarantee.

What the guarantee does **not** cover: the XSS and cmdi sinks (fixed by
`html.escape`, as `/safe` already does, and by an allowlist on `host` plus
`subprocess.run([...])` without a shell), and plaintext password storage (see
`duel/ground_truth.json`, `out_of_scope_real`).
