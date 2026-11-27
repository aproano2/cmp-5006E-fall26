# Part B — Defend, Then Bypass

> **Team:** Juan Diego Cadena · Omar Gordillo · Pablo Jarrín · Santiago Rodríguez

We defended the SQL injection finding.

## B1 — Negative model

The WAF is a three-rule blocklist in `controls.py`. It looks for numeric equality,
UNION/SELECT word combinations, and DROP TABLE phrases.

- Coverage on the Part A SQLi payload: **1/1 blocked (100%)**.
- Same-intent bypasses: **3/3 passed the WAF and leaked the real canary**.
- False positives: **4/26 benign inputs blocked (15.4%)**.

The working bypasses changed the tautology rather than the attack goal:

1. `admin' oR 'a'='a'--`
2. `admin' oR 2>1--`
3. `admin' oR TRUE--`

One clear false positive was `drop table tennis lessons for beginners`. The user
was talking about table tennis, but the DROP TABLE rule still blocked the text.

## B2 — Positive model

`parameterized_login` uses this query:

```python
database.execute(
    "SELECT user FROM users WHERE user = ? AND pw = ?",
    (username, password),
)
```

The Part A payload and all three WAF bypasses were tested again. **0/4 injections
succeeded.** A correct `admin` / `s3cr3t` login still works.

The conditional guarantee is: user-controlled username and password values
cannot change the SQL query structure, provided every untrusted value is passed
through parameter placeholders and no query fragment is concatenated elsewhere.

The WAF cannot give this guarantee because it only recognizes patterns that were
written in advance. Its exact evidence is in the four CSV files in this folder.
