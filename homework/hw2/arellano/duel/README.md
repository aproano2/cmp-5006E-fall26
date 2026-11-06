# Part C — Same-target PHP duel

Both tools inspect the three real DVWA Medium PHP snippets and our fixed SQLi
negative control in dvwa_source/. The runner verifies originals against the live
container. Manual reasoning is in ../ground_truth_manual.json; reviewed_inputs.json
hashes it and the source before tool execution. Prior exposure to old vuln-web
outputs is disclosed; this new PHP reference is not derived from the new outputs.
Review was AI-assisted and requires group review.

| Tool | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| semgrep | 2 | 0 | 1 | 1.000 | 0.667 | 0.800 |
| ollama-run-1 | 1 | 2 | 2 | 0.333 | 0.333 | 0.333 |
| ollama-run-2 | 0 | 4 | 3 | 0.000 | 0.000 | 0.000 |

Classical scanner: actual Semgrep with custom PHP rules, offline read-only source
mount. semgrep_raw.json is the raw result. The deliberately narrow SQL rule can
miss construction via a query variable: [['sqli', 'sqli_medium.php']].
This is a limitation of our rules, not of Semgrep generally.

Model: local Ollama qwen2.5:0.5b, temperature 0.7, seeds 11 and 29,
cache reads disabled. Both raw responses and model metadata are in
part_c_results.json and the per-run raw JSON files; review_prompt.txt preserves
the exact identical prompt and source. Confidence labels are model claims,
not dynamic confirmation.

Observed false-positive keys:

- ollama-run-1: [['broken-access-control', 'sqli_fixed.php'], ['sqli', 'sqli_fixed.php']]
- ollama-run-2: [['broken-access-control', 'sqli_fixed.php'], ['cmdi', 'sqli_fixed.php'], ['sqli', 'exec_medium.php'], ['xss', 'exec_medium.php']]

These keys require source review to distinguish an unsupported finding from a
real reference omission; do not equate every differing label with hallucination
without reading the evidence. No example is invented when none occurs.

**Best observed hallucination:** run 2 labels `exec_medium.php` as SQLi and
claims that it retrieves user information with an SQL query. That file only
filters an IP/command string and calls `shell_exec`; it contains no database
query. The model invented the SQL operation. Run 1 also labels our prepared
SQLi patch vulnerable because `php_uname` is missing, which is unrelated to
SQL parameterization. The dynamic fixed-endpoint replay contradicts that SQLi
claim for the evaluated statement.

The run-1 XSS key matches ground truth, but its explanation about PHP opening
tags is not the actual flaw (the flaw is unencoded reflected input after a
case-sensitive filter). Key-based TP counts therefore overstate explanation
quality; a correct key alone is not sound security reasoning.

**Access control:** Semgrep reports none. Both LLM runs report
`broken-access-control/sqli_fixed.php`; their explanations confuse a Submit
check or supposed SQLi with an authorization violation. Neither supplies a
role/ownership policy or a demonstrated violation, so these claims are
unsupported in this scope.

**Format and scoring policy:** two initial unconstrained calls were retained
in format_attempt/ after run 2 produced invalid JSON. The scored results are
two new calls using Ollama's JSON schema feature (only data shape is constrained;
finding labels and filenames are free strings). The same schema and prompt are
used for both seeds. Location paths normalize to their lowercase basename,
so a harmless `dvwa_source/` prefix is not penalized. No finding is removed to
improve a score. This retry and the narrow three-intended-finding reference are
limitations of the experiment; the table is not an exhaustive DVWA audit.

Non-determinism: Jaccard 0.167; only run 1:
[['sqli', 'sqli_fixed.php'], ['xss', 'xss_medium.php']]; only run 2:
[['cmdi', 'sqli_fixed.php'], ['sqli', 'exec_medium.php'], ['xss', 'exec_medium.php']]. Identical sets in two samples do not
prove determinism. Wording can still differ.

Authentication and role/ownership policy are outside these snippets; absence of
a demonstrated separate A01 finding does not prove the full app is free of it.

Historical vuln-web duel results are in original/. They used qwen2.5:3b and
instructor fixtures; they are not current PHP evidence. Snapshots of original
DVWA code retain the upstream GPL license in dvwa_source/COPYING.txt.
