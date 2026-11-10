# Part C — Classical Scanner vs. Local LLM

> **Team:** Juan Diego Cadena · Omar Gordillo · Pablo Jarrín · Santiago Rodríguez

Both tools reviewed the same file: `labs/vuln-web/app/vulnweb_app.py`. We created
`ground_truth.json` by reading the source before scoring either tool.

| Tool | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Semgrep with committed local rules | 2 | 0 | 1 | 100% | 66.7% | 0.80 |
| Local LLM, run 1 | 3 | 0 | 0 | 100% | 100% | 1.00 |
| Local LLM, run 2 | 3 | 0 | 0 | 100% | 100% | 1.00 |

Semgrep's worst miss was SQL injection in `do_login`. The local SQLi rule looks
for a SELECT f-string on one source line, while this SQL construction spans two
lines. This shows that a real scanner is still limited by the rules it receives.

The LLM was `qwen3.5:4b` through local Ollama, temperature 0.8, with seeds 17 and
83. We did not observe a hallucinated finding in these two runs. This small sample
does not prove the model will never hallucinate. The raw responses are stored in
`llm_runs.json` so this statement can be checked.

The two LLM runs returned the same three normalized finding keys, giving 100%
Jaccard similarity. Their wording and severity formatting changed: run 1 included
explicit severity values, while run 2 did not follow that part of the requested
format. Therefore the security findings were stable, but the output was not
textually deterministic.

Neither tool reported Broken Access Control. That is the correct result because
the target does not implement sessions, user roles, or protected resources.

The individual findings and exact metrics are in `scanner_results.csv`,
`llm_results.csv`, `metrics.csv`, and `non_determinism.json`.
