# Part B: Defend the SQLi, then bypass our own defense

```bash
python3 defend/defend.py        # from homework/hw2/soto/
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

This denominator covers the five Part-A SQLi inputs that already exploit Low,
not every Part-A input or every Medium exploit. In particular, putting V1
**before** the Medium filter would let `admin'-#-` pass the WAF and then become
`admin'--`, leaking the canary. The local review reproduced that composition.
The 5/5 figure must not be presented as coverage of the full Medium configuration;
a stacked deployment needs its own evaluation and a stated filter order.

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

| WAF | `login_username` (the field it guards) | whole corpus (rule-only measurement) | bypasses that still land |
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
blocks 31 % of the supplied corpus. We found no bypass for V2 in these tests;
"block every `'`" stops these quote-breaking string-context SQLi inputs. It is
an allowlist in disguise, and O'Brien can no longer log in. We tried only these 4
bypasses against V2, so "no bypass found" is not a guarantee.

### 2b. Fresh bypass attempt against V2 ([`bypass_v2.py`](bypass_v2.py))

To make "no bypass found" a measurement rather than a hope, we fired **13 fresh
same-intent payloads** at V2 that were **not** in the 4-payload set it was tuned
on — inline comments, URL/tab whitespace, `||` concatenation, keyword-free
tautologies (`IS NOT`, `GLOB`, `LIKE`), lexical comparisons, and quote-free
attempts. Result (`results/waf_v2_bypass_attempts.csv`): **0 bypasses**. Only the
quote-free `admin` passes the filter, and with no quote it stays data (0/3). The
reason is structural: the `/login` sink interpolates input **inside a
single-quoted literal**, so changing the query structure requires a `'`, and V2
blocks every `'`. So V2's robustness is not clever rules — it is a character ban,
which is exactly why it costs so much in false positives (below).

### 3b. False positives on the `pw` field ([`measure_pw_fp.py`](measure_pw_fp.py))

The WAF inspects **every** `/login` field, including `pw`, but the course corpus
has no passwords, so the 0/26 and 8/26 figures never tested the password field.
We added a benign password corpus ([`benign_passwords.json`](benign_passwords.json))
and measured the WAF live through HTTP (`results/waf_pw_false_positives.csv`):

| Corpus | WAF_V1 blocks | WAF_V2 blocks |
|---|---|---|
| 15 human passwords (`Tr0ub4dor&3`, `O'Brien2024!`, `correct-horse-battery-staple`…) | 1/15 = 7 % | **8/15 = 53 %** |
| random password-manager output, 12 chars | 0 % | 13 % |
| random password-manager output, 16 chars | 0 % | 17 % |
| random password-manager output, 20 chars | 0 % | 20 % |

V1 is quote-anchored, so it only trips on passwords that contain a quote next to a
comment/OR (e.g. `Summer'#2024`); the generated set has no quotes, so V1 passes
them. V2's "any single quote / any SQL keyword / any comment" rules reject **more
than half** of normal human passwords and up to a fifth of random ones — a locked
account every time. This is the axis-5 cost the username-only corpus hid.

## B2: Positive model (the real fix), [`fixed_app.py`](fixed_app.py)

```python
QUERY = "SELECT user, secret FROM users WHERE user = ? AND pw = ?"
rows = app.DB.execute(QUERY, (user, pw)).fetchall()
```

The SQL text is a constant, and `user`/`pw` are sent to SQLite as bound values.
As a side fix, the error path no longer echoes the SQL query and DB error back
(that was a separate CWE-209 information leak in the original `do_login`).

### 5. Re-run of Part-A SQLi payloads and all B1 SQLi bypasses

The CSV includes all six Part-A SQLi inputs plus the four B1 bypasses: ten inputs
in total, nine of which exploit the unfiltered baseline. The fix is scoped to
`/login`; XSS and cmdi payloads on their original endpoints are outside this
replay and remain unfixed.

| Defense | attacks that still leak the canary (of 9 that work undefended) |
|---|---|
| none | 9/9 |
| WAF_V1 | 4/9 (exactly the 4 bypasses) |
| WAF_V2 | 0/9, at a 31 % false-positive cost |
| **parameterized** | **0/9**; valid-login controls pass, and no input blocklist is used |

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

## Follow-up: complete replay and Medium composition

Run `python3 verify_readiness.py` from the submission directory. This adds
separate evidence under `results/readiness/` while preserving the original
CSV measurements above. Every Part-A input, every B1 bypass, and a supplementary
20-input SQLi corpus is replayed through seven configurations, three trials each.
The additional corpus reuses only input strings from Mauricio's Week 7 work;
all HTTP outcomes are measured again for HW2.

On the combined set of 30 distinct SQLi inputs, Low confirms 29, Medium confirms
6, V1 before Low confirms 4, V2 before Low confirms none, V1 before Medium confirms
3, and both parameterized configurations confirm none. These are counts over the
same 30 attempted inputs, not a claim that all inputs exploit every baseline.

The three V1-before-Medium bypasses are `admin'-#-`, `x' IS NOT 'y` in the password
field, and `admin' AND 1/*`. All leak the canary 3/3 times. The parameterized fix
after Medium defeats all 30 SQLi inputs. The full replay also records that the
selected SQLi fix leaves the separate XSS/cmdi routes vulnerable; the assignment
asks to fix one class. The `/safe` control remains negative.

The 20 supplementary inputs each exploit Low. V1, V2, and the parameterized
versions stop all 20; Medium alone also stops them, so this particular set does
not measure extra protection from putting V1 in front of Medium. Success on
this set does not erase the separately confirmed WAF bypasses.

Evidence: [full replay](../results/readiness/full_replay.csv),
[summary](../results/readiness/summary.json), and
[login/safe-XSS controls](../results/readiness/controls.csv).

## Control Scorecard

This uses the course's required before/after format. Unmeasured operational
properties are identified explicitly.

| Axis | Before | After control | Evidence |
| --- | --- | --- | --- |
| Threat model | Unauthenticated caller chooses login fields over HTTP | Same caller and input control; V1/V2 inspect both fields; the fix binds both as values | [WAF](waf.py), [fix](fixed_app.py) |
| Guarantee | Formatted input can change SQL structure | V1 recognizes its listed patterns; fixed query structure holds provided constant SQL and correct driver parameter binding are maintained | Conditional guarantee above; [fixed query](fixed_app.py) |
| Coverage | 20/20 supplementary inputs leak the canary at Low | V1/V2 block all 20; parameterized login leaks on 0/20. The combined replay includes 30 distinct SQLi strings | [Inputs](../coverage_payloads.json), [fresh replay](../results/readiness/full_replay.csv) |
| Bypass | Four B1 inputs exploit Low | All four still exploit V1/Low; three SQLi inputs exploit V1/Medium; no tested SQLi exploits either fixed configuration | [Original replay](../results/defense_attacks.csv), [full replay](../results/readiness/full_replay.csv) |
| FP cost | No WAF rejection; malformed SQL can still break legitimate input | V1: 0/9 usernames, 0/26 corpus inputs blocked. V2: 2/9 and 8/26. Both fixes accept valid admin, Alice, and a seeded O'Brien account | [Corpus decisions](../results/waf_false_positives.csv), [controls](../results/readiness/controls.csv) |
| Op cost | Not measured separately | Latency, CPU/RAM, and tuning hours not measured; no operational-cost improvement is claimed | Limitation |
| Observability | No WAF decision | WAF returns a rule in its 403 body; the harness records decisions and response samples. Persistent server audit logging is not implemented | [WAF](waf.py), [recorded responses](../results/readiness/full_replay.csv) |
| Failure mode | Attacker-controlled structure reaches the query | Unmatched WAF inputs reach the sink; the fix protects login query structure only. Process/proxy-failure behavior was not tested | [Bypasses and residual routes](../results/readiness/full_replay.csv), [fix scope](fixed_app.py) |
