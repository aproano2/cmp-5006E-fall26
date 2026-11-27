# Part C — LLM vs. Semgrep

Ground truth uses the instructor fixture, with source verification documented in ../ground_truth_review.md. Keys are (rule, function).

| Tool/run | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| semgrep | 2 | 0 | 1 | 100% | 67% | 0.80 |
| llm_run_1 | 0 | 3 | 3 | 0% | 0% | 0.00 |
| llm_run_2 | 1 | 2 | 2 | 33% | 33% | 0.33 |

## Findings

- **semgrep — sqli at `do_login`:** User-controlled values are interpolated into a SQL query.
- **semgrep — xss at `do_reflect`:** User input is returned in HTML without context-aware encoding.
- **llm_run_1 — sqli|xss|cmdi|broken-access-control|other at `do_login`:** SQL injection due to the use of string-formatted query without parameterization.
- **llm_run_1 — sqli|xss|cmdi|broken-access-control|other at `do_reflect`:** Reflected XSS due to the use of unencoded user input in the HTML.
- **llm_run_1 — sqli|xss|cmdi|broken-access-control|other at `do_reflect_safe`:** The code is intentionally safe as it uses html.escape() to encode the input.
- **llm_run_2 — sqli|xss|cmdi|broken-access-control|other at `do_login`:** do_login function is vulnerable to SQL injection and reflected XSS due to the use of unparameterized queries and input not being properly sanitized.
- **llm_run_2 — sqli|xss|cmdi|broken-access-control|other at `do_reflect`:** do_reflect function is vulnerable to reflected XSS due to the lack of input sanitization.
- **llm_run_2 — cmdi at `do_ping`:** do_ping function is vulnerable to command injection because the host input is concatenated into a command without proper sanitization.

## Non-determinism

Compare `llm_run_1` and `llm_run_2` in `metrics.csv` and `findings.csv`. The runner uses the same prompt for both calls. Recorded settings: run 1: temperature=0.7, seed=11, cached=False; run 2: temperature=0.7, seed=29, cached=False.

## Access control

The source contains no session, role, or authorization mechanism. A report of broken access control is unsupported by this target and must be treated as a false positive.

## Audit files

- `metrics.csv`: precision, recall, and F1.
- `findings.csv`: individual findings and model rationales.
- `llm_runs.json`: exact LLM responses and run settings.
- `semgrep_run.json`: scanner invocation and metadata.

## Scoring and interpretation

Labels are scored exactly as returned (case and whitespace normalized). Invalid labels count as unmatched findings / false positives; they are never inferred from the function name. All entries in findings are scored, including safe functions and access-control claims.

Evidence mode: replay of saved tool outputs; no new scanner or model calls.

- semgrep: false positives []; missed [('cmdi', 'do_ping')].
- llm_run_1: false positives [('sqli|xss|cmdi|broken-access-control|other', 'do_login'), ('sqli|xss|cmdi|broken-access-control|other', 'do_reflect'), ('sqli|xss|cmdi|broken-access-control|other', 'do_reflect_safe')]; missed [('cmdi', 'do_ping'), ('sqli', 'do_login'), ('xss', 'do_reflect')].
- llm_run_2: false positives [('sqli|xss|cmdi|broken-access-control|other', 'do_login'), ('sqli|xss|cmdi|broken-access-control|other', 'do_reflect')]; missed [('sqli', 'do_login'), ('xss', 'do_reflect')].

Run 2 added [('cmdi', 'do_ping')] and removed [('sqli|xss|cmdi|broken-access-control|other', 'do_reflect_safe')].

The scanner's worst miss is cmdi at do_ping: its two custom rules cover only SQLi and XSS.

Neither tool returned an exact broken-access-control label. This label check does not interpret claims in free-text rationales.

Manual review of these exact responses: run 2 incorrectly attributes reflected XSS to do_login. The HTML reflection is in do_reflect; this is a rationale hallucination. Most rule fields contain the entire example string sqli|xss|cmdi|broken-access-control|other rather than one class. Strict scores penalize these malformed labels and therefore measure output-contract compliance as well as detection. Run 1 also lists do_reflect_safe while explicitly describing it as safe; under the declared findings-list contract it is counted as an unmatched entry, not evidence that the model believed it vulnerable.

Neither reviewed response asserts a concrete access-control defect. The malformed example label contains that category but does not establish a supported finding.
