# Part C — Scanner vs. LLM

Run from the repository root:

```bash
python3 homework/hw2/rodriguez_felipe/duel/run_duel.py --backend ollama --model qwen2.5:1.5b
```

Requirements:
- Semgrep installed (`brew install semgrep` on macOS).
- Ollama installed and serving (`ollama serve`) with the selected model available (`ollama pull qwen2.5:1.5b` if needed).

For a different installed Ollama model, pass its exact name with `--model`.
For the manual backend, use `--backend manual`; the script will ask you to paste
two separate model answers. Do not use `echo` as evidence because it is not a
real model.

The script scans the same `vulnweb_app.py` source with a small custom Semgrep
rule set and an LLM. It scores the outputs using the course
`../ground_truth.json`. The two LLM calls use different seeds, nonzero
temperature, and disabled caching.

Generated files:
- `metrics.csv` — TP, FP, FN, precision, recall, and F1.
- `findings.csv` — each reported finding.
- `llm_runs.json` — exact model responses and run settings.
- `semgrep_run.json` — Semgrep command metadata.
- `results.md` — readable summary.

The Semgrep rules are intentionally narrow and detect the SQLi and XSS patterns.
A missed command-injection finding is therefore a limitation of this rule set,
not a claim about every Semgrep rule pack. The recorded outputs and calculated
metrics are documented in [results.md](results.md).

## Reproduce the committed comparison without installed tools

```bash
python3 homework/hw2/rodriguez_felipe/duel/run_duel.py --replay
```

Replay uses the two original responses in llm_runs.json and the saved Semgrep
rows in findings.csv. It does not rerun either tool. Raw model responses and
scanner metadata remain the original evidence. Scoring preserves reported
labels, including invalid labels, safe-function reports and access-control
claims. No label is inferred from its function name. The saved prompt's enum-like
example confused the model; this output-format weakness is part of the result.

The report derives scanner misses, explicit access-control labels, and run-to-run
changes from the results. Manual interpretation of rationales is attached only
when the SHA-256 hashes of both responses match the reviewed evidence. Different
responses are marked as requiring manual review, including when replaying saved
outputs. Inspect those rationales before treating a new report as complete.
