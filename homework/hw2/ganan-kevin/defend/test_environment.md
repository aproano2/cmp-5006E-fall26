# Test environment and provenance

The result files currently included in this review package were generated in a
local temporary test setup on 2026-11-04. The vulnerable application process
was started from a temporary reconstruction of the exact `vulnweb_app.py`
source pasted in the conversation, not from the official course checkout or
its Docker container. The WAF proxy forwarded to that process. The patched
B2 test target was also loaded from the same temporary source copy.

This provenance matters: the results prove that the submitted scripts behave
as described against the supplied source excerpt, but they do not prove that
the official target, its Docker image, any external Medium filter, or the
course `seclab.attack` oracle was used.

## Commands and observed results

| Test | Observed result | Scope |
|---|---:|---|
| Instructor fixture verifier | `FIXTURES SOUND.` | Source copy supplied in conversation |
| Part-A baseline HTTP oracles | SQLi, XSS, and simulated CMDi confirmed | Direct local HTTP checks; not `seclab.attack`; no Medium filter |
| WAF benign corpus | 5/26 false positives = 19.23% | Instructor-provided synthetic corpus |
| WAF XSS sample | 17/20 blocked = 85%; selected Part-A payload 1/1 blocked | Regex decisions |
| B1 bypass candidates | 3/3 allowed by WAF; each reflected unescaped; parsed href becomes `javascript:` | Browser execution not verified |
| Live WAF proxy | 20/20 requests matched expected 403/200 behavior | Local proxy on loopback |
| B2 unit tests | 7/7 passed | Fixed helper functions |
| B2 HTTP regression tests | 7/7 passed | Patched local copy on loopback |

## Still not run

- Part-A tests through the actual Medium filter and with the official
  `seclab.attack` oracle.
- Semgrep CLI against the official source file.
- Five uncached Ollama LLM reviews and their metrics against
  `ground_truth.json`.
- Playwright Chromium execution of each reflected XSS link.
- Latency, CPU, RAM, and operational tuning measurements for the WAF.

Do not describe these pending items as completed. Once the official project is
available, re-run the README commands and replace or supplement this evidence
with the actual local course-environment outputs.


## Newly supplied course API integration (2026-11-04)

The group later supplied `seclab.zip`. Its `attack.py` and `scan.py` were read
and the homework scripts were updated to use their real APIs. The official
`seclab` unit-test suite was executed against that uploaded package: **16
passed**. The Part-A harness was additionally smoke-tested against a disposable
loopback HTTP mock that implements the same three endpoint response shapes; all
three `seclab.attack.run_payloads` oracles confirmed. The scorer was smoke-tested
with disposable synthetic records to verify that `seclab.scan.compare_scanners`
was called and its tuple-key output was handled. Those smoke-test records are
not part of the submission and are not graded findings.

Semgrep CLI and Ollama were not installed in this review environment, and the
actual `labs/vuln-web` directory was described/pasted rather than uploaded as a
separate archive. Therefore no real Semgrep or Ollama result is claimed. The
provided app/source/configuration still contains no Medium filter.
