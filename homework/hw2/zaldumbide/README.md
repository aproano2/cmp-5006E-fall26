# Homework 2 — Web Attack & Defend

**Names:** Luis Eduardo Zaldumbide, Miguel Jarrin, Josue Lopez
**Class:** Computer Security
**Date:** 6/11/2026

All work is local — see [`../../../resources/ethics-and-scope.md`](../../../resources/ethics-and-scope.md).

## Files

Each part has its own folder with its script, its inputs and its results.

| File | What it is |
|---|---|
| `attack/attack_partA.py` | Part A: confirms the 3 vulnerabilities with `seclab.attack` oracles |
| `defend/defend_partB.py` | Part B: the WAF (B1) and the parameterized fix (B2) |
| `defend/benign_traffic.json` | Part B: benign corpus used to measure WAF false positives |
| `defend/b1_coverage.csv` | Part B: WAF coverage over the SQLi attack battery (B1.1) |
| `defend/b1_bypass.csv` | Part B: the 3 confirmed WAF bypasses (B1.2) |
| `defend/b1_false_positives.csv` | Part B: benign traffic false positives (B1.3) |
| `defend/b2_positive_fix.csv` | Part B: every attack rerun against the parameterized login (B2) |
| `duel/duel_partC.py` | Part C: runs sqlmap and the LLM reviewer and scores them with `seclab.scan` |
| `duel/ground_truth.json` | Part C: hand built ground truth for the target |
| `duel/c_scores.csv` | Part C: precision, recall and F1 for sqlmap and each LLM run |
| `duel/c_findings.csv` | Part C: every reported finding with its verdict |
| `duel/raw/` | Part C: raw evidence (sqlmap logs, the prompt and both LLM answers) |
| `honesty.md` | Part D: where our attack, defense, or comparison might be unfair |
| `AI_LOG.md` | AI use log |

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

Everything for this part is in the `attack/` folder. It needs the target up (see above). From inside the `attack` folder:

```bash
PYTHONPATH=../../../.. python attack_partA.py
```

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

Everything for this part is in the `defend/` folder. It does not need the target up. From inside the `defend` folder (this regenerates the four CSVs):

```bash
PYTHONPATH=../../../.. python defend_partB.py
```

We defend **one** Part-A vulnerability — the **SQL injection in `do_login`** — two
ways. `defend_partB.py` imports the **real vulnerable `do_login`** in-process (no
Docker / no random port needed) and confirms every result with the same canary
oracle Part A used.

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

## Part C — The duel: LLM vs. scanner

Everything for this part is in the `duel/` folder. From inside the `duel` folder:

```bash
python duel_partC.py score
```

`score` only reads the saved output in `duel/raw/`, so it does not need sqlmap or Ollama. `scan` reruns sqlmap and `llm` reruns the LLM.

### Setup

| Tool | Configuration |
|---|---|
| Classical scanner: sqlmap 1.10.11 | run against the 4 endpoints of the app on 127.0.0.1, with level 3 and risk 3 |
| LLM reviewer: qwen2.5:1.5b on a local Ollama, through `seclab.LLM` | one plain prompt (`duel/raw/llm_prompt.txt`) with the source of `vulnweb_app.py`, run twice at temperature 0.8 with seeds 1 and 2 |

Both are scored with `seclab.scan.classify` against `duel/ground_truth.json`, which has 3 real findings (sqli in `do_login`, xss in `do_reflect`, cmdi in `do_ping`) and was built by reading the source, not by running a tool. A finding is matched by (rule, function). sqlmap reports routes, so each route is mapped to its handler function (POST /login to `do_login` and so on).

Two notes on the LLM run. The comments and docstrings are removed from the source before it goes in the prompt, because they name every bug ("VULN: SQL injection"). And `seclab.LLM` got a cap of 600 generated tokens, because without it this model repeats the same line forever and times out.

### C.1 Precision, recall and F1

| Tool | Reported | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| sqlmap | 1 | 1 | 0 | 2 | 1.00 | 0.33 | 0.50 |
| LLM run 1 | 4 | 1 | 3 | 2 | 0.25 | 0.33 | 0.29 |
| LLM run 2 | 1 | 1 | 0 | 2 | 1.00 | 0.33 | 0.50 |

The scores are in `duel/c_scores.csv` and every finding with its verdict is in `duel/c_findings.csv`.

Both tools found only the SQL injection in `do_login`. sqlmap reported nothing false. The LLM added three false findings in run 1.

### C.2 The LLM's best hallucination and the scanner's worst miss

LLM: in run 1 it reports SQL injection in `do_ping` and in `do_reflect`, two functions that have no SQL at all (one builds a ping command, the other an HTML string). The reason it gives is "Canary secret is hardcoded and exposed in SQL query", which has nothing to do with those functions. In the same run it reports XSS in `do_login` because "Password is passed through `do_reflect`", a data flow that does not exist in the code. Run 2 reports one SQL injection and then writes "No known vulnerabilities found in the provided code" four times, contradicting itself. Both answers are in `duel/raw/llm_run1.txt` and `duel/raw/llm_run2.txt`.

sqlmap: its worst miss is the command injection in `do_ping`. It tested the host parameter of POST /ping and reported it as not injectable, because sqlmap only looks for SQL injection. For the same reason it also missed the XSS in `do_reflect`. It also needed level 3 and risk 3 to find the SQL injection: on our first try with its default settings it reported nothing (`duel/raw/sqlmap_first_try_default_settings.log`).

### C.3 Nondeterminism

Same model, same prompt, same temperature, only the seed changes:

| Finding | In ground truth | Run 1 | Run 2 |
|---|---|---|---|
| sqli in do_login | yes | yes | yes |
| sqli in do_ping | no | yes | no |
| sqli in do_reflect | no | yes | no |
| xss in do_login | no | yes | no |

Only the SQL injection in `do_login` appears in both runs. The three false findings appear in run 1 and are gone in run 2, so precision goes from 0.25 to 1.00 and F1 from 0.29 to 0.50 just by changing the seed. A single LLM run is not reproducible evidence. sqlmap gave the same result every time we ran it.

### C.4 Did either tool find an access control issue?

No, and that is correct here. The app has no login session, no roles and no authorization check, so there is no access control decision to break (`duel/ground_truth.json` lists Broken Access Control as not present). sqlmap cannot express a rule like "this user should not see this data", so it could never find one. The LLM did not invent one this time, but the same run invented SQL injection in functions with no SQL, so this does not show that it understood authorization. The SQL injection in `do_login` lets an attacker log in as admin without the password, but that is an injection (A03), not a missing access check (A01).

## Part D — Honesty

See [`honesty.md`](honesty.md), titled "Where our attack, defense, or comparison might be unfair". It answers the four questions of the assignment: how independent the ground truth is, the tuning asymmetry, how realistic the benign corpus is, and which Part A finding we trust least.

---

## Reproducing the numbers

Each part runs from inside its own folder. `PYTHONPATH` points at the repo root so `seclab` can be imported.

```bash
cd attack && PYTHONPATH=../../../.. python attack_partA.py
```

```bash
cd defend && PYTHONPATH=../../../.. python defend_partB.py
```

```bash
cd duel && python duel_partC.py score
```

Part A needs the target up and `VULN_WEB_URL` set (see "Bring up the target"). Part B and the Part C `score` step need nothing else. Rerunning the Part C `scan` and `llm` steps needs sqlmap and a local Ollama with qwen2.5:1.5b.
