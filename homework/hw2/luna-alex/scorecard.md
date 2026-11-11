# Control Scorecard — B1 WAF, B2 XSS output encoding, Part C LLM reviewer

## Scope

Threat model: an unauthenticated user able to send HTTP requests to the local
`vuln-web` service, running in the official course Docker container via
`seclab.targets`. The exercise path is loopback only; no external host or
production data is in scope. The WAF proxy is a separate local process on
port 8001 forwarding to the container's assigned port. All numbers below are
from runs against the actual official target/container, not a reconstruction.

| Axis | Before | After control | Evidence |
|---|---|---|---|
| 1 · Threat model | Unauthenticated local HTTP attacker; no credentials required | Same attacker, now expected to send traffic through port 8001 | `README.md`; proxy binds loopback. The target's own port stays directly reachable, so the attacker can bypass the proxy entirely if it isn't the only exposed route — a real limitation, not a hypothetical one (see axis 8). |
| 2 · Guarantee | Reflected input is inserted into HTML without encoding | WAF: blocks only listed regex patterns **if every request traverses the proxy**. B2: `html.escape` prevents user input from introducing HTML markup **provided the result is used as HTML text content and is not decoded/reparsed into an executable context**. | `defend/waf.py`, `defend/waf_proxy.py`, `defend/positive_fix.py` |
| 3 · Coverage | No WAF: 0/20 blocked | 20-payload XSS sample: 17/20 blocked (85%); the Part-A XSS payload: 1/1 blocked | `defend/coverage.csv`, `defend/coverage_report.json`. A finite 20-input sample, not universal XSS coverage. |
| 4 · Bypass | Not applicable before WAF | **Lexical bypass confirmed**: 3/3 same-intent candidates evade the regex proxy (HTTP 200, reflected unescaped). **Browser-execution NOT confirmed**: Playwright/Chromium loaded each reflected link and clicked it; `dialog_fired=False` for all three. The bypass defeats the WAF's pattern-matching but did not demonstrate actual JavaScript execution in a real browser in this test. | `defend/bypass.md`, `defend/bypass_results.csv`, `defend/browser_bypass_results.json`. We report both levels separately rather than calling the WAF "bypassed for real XSS" on the strength of the lexical result alone. |
| 5 · False-positive cost | No WAF: 0/26 blocked | 5/26 benign inputs blocked = **19.23%** | `defend/fp_report.json`, `defend/benign_traffic_results.csv`; synthetic instructor corpus only, see honesty.md §3. |
| 6 · Operational cost | Not measured | Not measured | No latency/CPU/RAM benchmark was run; we do not claim one. |
| 7 · Observability | No decision log in the target | Proxy logs allow/block, request path, field, and matched rule to stderr; raw payload is not logged | `defend/waf_proxy.py`; retain terminal output as evidence. |
| 8 · Failure mode | Vulnerable handler accepts the input | Upstream outage returns HTTP 502. **Fails open to bypass, not closed**: if the proxy process stops while the target's own port stays reachable, a client can connect directly to the backend and skip the control entirely. | `defend/waf_proxy.py`; architecture limitation, not yet mitigated. |
| 9 · Non-determinism | N/A for the deterministic regex WAF. **For the LLM reviewer**: 5 uncached runs, same source, temperature 0.7, seeds 0–4. | **4 distinct finding-sets across 5 runs** (only runs 1 and 5 matched each other exactly). Two runs (1, 5) were perfect: all 3 real bugs, no hallucination. Two runs (2, 3) found all 3 real bugs but also hallucinated a finding on the true-negative endpoint `do_reflect_safe`. One run (4) found all 3 real bugs *and* hallucinated the specific `broken-access-control` class the fixture marks as not-present. | `duel/llm_runs.jsonl`, `duel/metrics.csv`, `duel/duel_report.json`. Per the course's own axis-9 rule: even though every run found the real bugs, the *noise* changed every time — this model is reliable at recall, not at precision, and that inconsistency is itself the finding. |

## Part C comparison (precision / recall / F1)

⚠️ **Correction:** an earlier pass of this scorecard reported the LLM at
10% precision / 13.4% recall, from a `duel/score.py` run where 4 of 5 "runs"
showed 0 findings. That was a bug in `duel/llm_review.py`'s output
normalizer, not a real result — the model's `raw_text` for those "empty"
runs in fact contained 3–4 real findings each, in two JSON shapes the
normalizer didn't recognize (each finding double-wrapped in its own list;
findings given as positional `[rule, location, evidence, confidence]` lists
instead of objects) and silently dropped. The normalizer is fixed (see
`duel/llm_review.py`); the numbers below are recomputed from the same raw
model output already captured in `duel/llm_runs.jsonl`, with no new
inference calls.

| Tool | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| Semgrep | 2 | 0 | 1 | 100% | 67% | 0.80 |
| LLM run 1 | 3 | 0 | 0 | 100% | 100% | 1.00 |
| LLM run 2 | 2 | 2 | 1 | 50% | 67% | 0.57 |
| LLM run 3 | 2 | 2 | 1 | 50% | 67% | 0.57 |
| LLM run 4 | 3 | 1 | 0 | 75% | 100% | 0.86 |
| LLM run 5 | 3 | 0 | 0 | 100% | 100% | 1.00 |
| **LLM macro-average** | — | — | — | **75%** | **86.7%** | **0.800** |

**The LLM's recall is essentially perfect across all 5 runs** — it found all
three real bugs, every single time, including the SQLi that Semgrep's narrow
rule missed. Its F1 (0.800) ties Semgrep's (0.80) despite that disadvantage,
because its cost shows up entirely in precision, not recall. **The LLM's
worst hallucination** is run 4 inventing `broken-access-control` on
`do_login` — the exact OWASP category `ground_truth.json` marks as
*not present*, and the one `attack/broken_access_control_argument.md`
argues structurally cannot exist in this app (no session/role code at all).
Runs 2 and 3 each independently hallucinated a finding on `do_reflect_safe`,
the fixture's true-negative endpoint, under two different invented rule
names (`xss-reflected`, and a mislabeled `xss`). **Semgrep's one miss**
(`sqli`/`do_login`) is exactly what its own narrow, disclosed rule predicted
before this run — a single-line regex against a query built from two
adjacent f-strings.

## Interpretation

The WAF is a negative model: it blocks lexical patterns and has a measured,
non-trivial false-positive cost. It does not stop a semantically equivalent
payload it wasn't written against (the 3/3 lexical bypass), and even what it
does block is only pattern-matched text — it says nothing about whether a
browser would actually execute an unblocked payload (which, in our one test,
it didn't). Output encoding (B2) is a positive, structural control for the
HTML text context: when the fixed handler is the only rendering path and the
output is not reinterpreted elsewhere, user data is not parsed as markup —
and unlike the WAF, it isn't a finite list that a new payload can simply miss.

The LLM-vs-scanner duel does **not** favor one tool decisively — it trades
one property for another. Semgrep is precise and silent: when it speaks, it's
right, but its rule has a known, disclosed blind spot it will never find on
its own. The LLM is thorough and noisy: it never missed a real bug across 5
runs (even catching the one Semgrep structurally cannot), but roughly 2 of
5 runs produced a false alarm, and one of those false alarms was the exact
OWASP category the fixture set up as a trap. For a workflow where a human
reviews every finding before acting, the LLM's extra noise costs analyst
time but not blind spots; for a workflow that auto-blocks on any finding,
the LLM's hallucinations would be the more expensive failure mode. Which
tool is "better" depends on which of those two costs the deployment can
absorb — which is exactly the kind of conditional this course's axis 2
pushes us to state instead of picking a winner.

## Evidence provenance

All numbers in this scorecard were generated against the **official course
Docker container** (`seclab/vuln-web:local`, started via `python -m
seclab.targets --up vuln-web`) and the real `seclab.attack` / `seclab.scan` /
`seclab.llm` APIs — not a reconstruction. The one unresolved item is whether
the supplied `vuln-web` target includes a "Medium" filter layer the
assignment asks Part A to bypass; see `honesty.md` §5.
