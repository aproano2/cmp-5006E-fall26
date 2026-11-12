**Group:** María Emilia Cueva (00328938), Santiago Reátegui (00331329), Jorge Gomez (00329264)
# Part A: Three Medium-filter bypasses confirmed by oracles

Run `python3 attack/run.py` (or  `python attack/run.py` on Windows) from the submission root. The script sends actual HTTP requests to the course target through the local Medium layer in `lab.py` and uses `seclab.attack.run_payloads` for three trials per finding.
The [OWASP Top 10:2021 A03 definition](https://top10.owasp.org/2021/A03_2021-Injection/) includes SQL, OS command, and cross-site scripting injection.

| Class and OWASP 2021 category | Payload and Medium bypass | Oracle result |
|---|---|---|
| SQL injection — A03:2021 Injection | `admin'/**/OR/**/'1'='1` replaces the spaces around `OR` with SQL comments; the Medium rule looks for whitespace around `OR`. | 3/3. JSON `rows` contains the `admin` row with the target's synthetic canary, despite password `x`. This is a data leak, not merely changed response text. |
| Reflected XSS — A03:2021 Injection | `<ScRiPt>alert(1)</ScRiPt>` changes the tag case; Medium checks only lowercase `<script`. | 3/3. `HTMLParser` recognizes a script element with `alert(1)` in its content. This proves unsafe HTML output, not browser execution. |
| Command injection — A03:2021 Injection | `127.0.0.1\|whoami` uses a pipe where Medium blocks only semicolons. | 3/3. JSON reports `injection_detected=true`, and the constructed `would_run` string contains the pipe. The app intentionally simulates shell execution. |

Each obvious spelling was separately blocked with HTTP 403: `admin' OR '1'='1`, `<script>alert(1)</script>`, and `127.0.0.1;whoami`. Controls with a wrong login, the original `/safe` endpoint, and a benign host triggered none of the three oracles.

**Broken Access Control (A01:2021):** the SQLi bypasses the password check and reveals the admin canary. The demonstrated root cause is a query structure injection in `do_login`. This small app has no session or role authorization system to assess independently, so we do not report a separate A01 finding.

See [results.csv](results.csv) for the three-trial counts. The canary is synthetic lab data, not a real credential.
