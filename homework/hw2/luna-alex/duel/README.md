# Part C — LLM vs. classical scanner

This directory preserves the instructor's `ground_truth.json` and
`benign_traffic.json`. The ground truth is the reference set; neither scanner
output nor LLM output is used to construct it.

## Run Semgrep

From the course repository root:

```powershell
$HW = "homework/hw2/luna"
py -m pip install semgrep
semgrep --version
python "$HW/duel/run_semgrep.py" labs/vuln-web/app/vulnweb_app.py
```

Keep `semgrep_raw.json`, `scanner_findings.json`, and `scanner_metadata.json`. `semgrep_rules.yml` is a
small, disclosed ruleset for the lab, not a general-purpose default Semgrep
configuration. Its SQLi signature is single-line; the lab query is composed
from two adjacent f-strings on separate source lines, so the rule is expected
to miss that finding. The provided lab README describes this as the classroom
scanner's miss. Verify the actual Semgrep output rather than assuming the rule
fired as expected.

## Run the LLM five times

```powershell
ollama list
ollama pull qwen2.5:3b
python -m seclab.llm --list-backends
python "$HW/duel/llm_review.py" labs/vuln-web/app/vulnweb_app.py `
  --runs 5 --backend ollama --temperature 0.7 `
  --out "$HW/duel/llm_runs.jsonl"
```

The runner disables response caching and varies seeds (0 through 4), while
holding the source and prompt constant. It records backend, model, temperature,
seed, elapsed time, raw answer, and normalized findings. Failed or unparseable
runs are retained and must be discussed, not silently dropped.

## Score with the official course helper

```powershell
python "$HW/duel/score.py" `
  --ground-truth "$HW/duel/ground_truth.json" `
  --llm-runs "$HW/duel/llm_runs.jsonl" `
  --scanner-findings "$HW/duel/scanner_findings.json" `
  --out-dir "$HW/duel"
```

`score.py` calls `seclab.scan.compare_scanners` after converting each report to
`seclab.scan.ScanResult`. It writes the official TP/FP/FN, precision, recall,
and F1 to `metrics.csv` and a detailed `duel_report.json`. The CSV includes each run and the LLM macro-average (the arithmetic mean of per-run metrics; it is not the score of a union of findings). The report also
counts whether the LLM flags the fixture's `do_reflect_safe` true negative or
reports the not-present `broken-access-control` class.

After scoring, inspect `semgrep_raw.json` and every raw LLM answer. Write the
actual LLM hallucination and scanner miss in the main report. Do not fill those
fields with anticipated results before running the tools.
