# Homework 2 — Web Attack & Defend

**Names:** Luis Eduardo Zaldumbide, Miguel Jarrin, Josue Lopez
**Class:** Computer Security
**Date:** 6/11/2026

All work is local — see [`../../../resources/ethics-and-scope.md`](../../../resources/ethics-and-scope.md).

## Files

| File | What it is |
|---|---|
| `attack_partA.py` | Part A — confirms the 3 vulnerabilities with `seclab.attack` oracles |
| `defend_partB.py` | Part B — the WAF (B1) and the parameterized fix (B2) |
| `b1_coverage.csv` | B1.1 — WAF coverage over the SQLi attack battery |
| `b1_bypass.csv` | B1.2 — the 3 confirmed WAF bypasses |
| `b1_false_positives.csv` | B1.3 — benign-traffic false positives |
| `b2_positive_fix.csv` | B2 — every attack re-run against the parameterized login |
| `ground_truth.json` | hand-built ground truth for the target (used in Part C) |
| `benign_traffic.json` | benign corpus used to measure WAF false positives |

## Bring up the target

```bash
# Option 1 — Docker (prints a random localhost port; export it):
python -m seclab.targets --up vuln-web
export VULN_WEB_URL="http://127.0.0.1:<the-port-it-printed>"

# Option 2 — no Docker, fixed port:
PORT=8000 python labs/vuln-web/app/vulnweb_app.py
export VULN_WEB_URL="http://127.0.0.1:8000"
```

---

## Part A — Attack

`attack_partA.py` confirms **three distinct vulnerability classes**, each with a
**sound oracle** (not a suggestive response).


| Class | Endpoint / sink | Payload | Oracle (what confirms it) | OWASP 2021 |
|---|---|---|---|---|
| **SQL injection** | `POST /login` → `do_login` | `admin' --` | the admin canary `FLAG-sqli-9f2c-admin-session` comes back | **A03 — Injection** |
| **Reflected XSS** | `GET /?name=` → `do_reflect` | `<script>alert(1)</script>` | the `<script>` tag is reflected **unescaped** (the `/safe` route escapes it) | **A03 — Injection** |
| **Command injection** | `POST /ping` → `do_ping` | `127.0.0.1; whoami` | the server reports `"injection_detected": true` (shell metacharacter reached a command context) | **A03 — Injection** |

**Result:** 3/3 confirmed by the oracle.

**Note on the "Medium filter" / bypass requirement.** The `vuln-web` target ships
with **no built-in request filter**, so the Part-A payloads reach the sinks
directly — there is no Medium-level filter to bypass here. The bypass dimension is
exercised in **Part B**, where we build a WAF and then defeat it.

**Broken Access Control (OWASP A01) — is it reachable?** No. `vulnweb_app.py` has
**no authentication, session, or role code at all**: there is nothing to escalate
or bypass. The SQLi in `do_login` is an *injection/auth-logic* flaw (it leaks a
row), not a broken-access-control flaw. Any tool that "finds" broken access control
on this target is hallucinating — the week-6 lesson that A01 needs real application
context to exist.

---

## Part B — Defend, then bypass our own defense

We defend **one** Part-A vulnerability — the **SQL injection in `do_login`** — two
ways. `defend_partB.py` imports the **real vulnerable `do_login`** in-process (no
Docker / no random port needed) and confirms every result with the same canary
oracle Part A used. Run:

```bash
PYTHONPATH=. python homework/hw2/jarrin-miguel/defend_partB.py
```

### B1 — Negative model (WAF blocklist)

The WAF has four rules: SQL comments (`--`, `#`, `/* */`), stacked queries (`;`),
the keywords `union|select` (a **substring** match, the way naive blocklists are
really written), and the tautology shape `OR/AND x=y`. It deliberately does **not**
ban a bare single quote, because that alone would block `o'brien` / `d'angelo`.

| Axis | Measure | Result | Evidence |
|---|---|---|---|
| **3 — Coverage** | SQLi attacks blocked | **6/6 = 100 %** | `b1_coverage.csv` |
| **4 — Bypass** (mandatory) | same-intent payloads that evade the WAF **and** still leak the canary | **3/3** | `b1_bypass.csv` |
| **5 — False positives** (mandatory) | benign inputs wrongly blocked | **login 2/9 = 22.2 %**; whole corpus 3/26 = 11.5 % | `b1_false_positives.csv` |

**The 3 bypasses** (injected into the `pw` parameter so the tautology sits at the
end of the `WHERE` and is not neutralized by `AND pw = ...`). None uses `=` or a
comment, so no rule fires, and each leaks the admin canary against the real sink:

1. `' OR 'x' LIKE 'x` — `LIKE` tautology instead of `=`
2. `' OR 'a'<>'b` — `<>` (not-equal) instead of `=`
3. `' OR 'x'>'` — `'x' > ''` (greater-than) tautology, no `=` at all

**False-positive cost (a real user blocked):** `select_committee_chair` and
`unionrep_delegate` are legitimate usernames, but the naive `union|select`
substring rule blocks both. Blocking `union`/`select` as substrings cannot tell
`UNION SELECT` from `unionrep_delegate`.

### B2 — Positive model (the real fix)

`do_login_safe()` uses a **parameterized query**
(`WHERE user = ? AND pw = ?`). Re-running **every Part-A payload plus all three B1
bypasses** against it:

**Result: 0/4 leak the canary** (see `b2_positive_fix.csv`).

**Guarantee (axis 2), as a conditional:** *for **any** `user`/`pw` input,
parameterization binds the input as data, so it cannot alter the query
**structure** → no SQL injection, by construction.* The WAF cannot make this
claim: it only blocks the attack shapes it enumerated, and B1.2 shows an
un-enumerated shape (the `LIKE`/`<>`/`>` tautologies) still gets through.

### The headline

The **blocklist raises cost** — 100 % coverage on known attacks, but bypassable
(3 working bypasses) and noisy (22 % of legitimate logins blocked). The
**positive model gives a guarantee** — 0 leaks for every payload, including the
bypasses. Both shown with numbers.

---

## Reproducing the numbers

```bash
# from the repo root (cmp-5006E-fall26/)
PYTHONPATH=. python homework/hw2/jarrin-miguel/attack_partA.py    # needs the target up (see above)
PYTHONPATH=. python homework/hw2/jarrin-miguel/defend_partB.py    # self-contained; regenerates the CSVs
```

---

## Part C — The duel: LLM vs. scanner

## Part D — Honesty
