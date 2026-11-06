# B1 — Attempt to bypass our own WAF

## Selected vulnerability: reflected XSS

We selected `do_reflect` because the WAF checks the reflected-name field and
the positive fix can encode output at the HTML sink. The original WAF blocks
the literal `<script>` prefix, common `on...=` handlers, and the literal
`javascript:` scheme. It also applies broad SQLi patterns to this field.

## Three same-intent bypass candidates

These payloads use HTML character references to construct the `javascript:`
URL scheme after HTML parsing. The raw input does not contain the literal
substring `javascript:`, `<script`, an `on...=` attribute, or a single quote.

| ID | Payload | Why the blocklist lets it through | Expected browser action |
|---|---|---|---|
| B1-XSS-01 | `<a href=jav&#x61;script:alert(1)>click</a>` | `a` is represented as a hexadecimal character reference | Click the rendered link; the browser decodes the attribute and navigates to `javascript:alert(1)` |
| B1-XSS-02 | `<a href=j&#97;vascript:alert(1)>click</a>` | `a` is represented as a decimal character reference | Same |
| B1-XSS-03 | `<a href=java&#x73;cript:alert(1)>click</a>` | `s` is represented as a hexadecimal character reference | Same |

## Evidence status — do not overclaim

The included `measure_b1.py` verifies that all three raw strings are **allowed
by our WAF** and that the vulnerable endpoint reflects the markup without
escaping. It also verifies with Python's HTML parser that each attribute is
decoded to a `javascript:` URL. That proves a filter bypass and a dangerous
parsed link, but it is not itself proof that a real browser executed the URL.

`test_xss_bypasses_browser.py` performs the final browser-level check with
Playwright: it opens each reflected page, clicks the link, and records whether
the expected JavaScript dialog fires. Run it and commit its JSON output before
calling these browser-execution-confirmed bypasses. A Content Security Policy
or browser policy could affect execution; report the actual result.

## Measured WAF coverage

On the full 20-payload sample (the Part-A literal `<script>` payload, 16
additional XSS test inputs, and these three bypass candidates):

- blocked: **17/20 (85%)**
- allowed: **3/20 (15%)**
- selected Part-A payload blocked: **1/1 (100%)**
- B1 bypass candidates allowed: **3/3 (100%)**

The live WAF-proxy probe returned the expected 403/200 decisions for **20/20**
requests. These are WAF decision/reflection results, not proof of browser
execution. See `coverage.csv`, `coverage_report.json`, and
`bypass_results.csv`.
