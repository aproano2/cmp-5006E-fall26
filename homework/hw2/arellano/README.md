# Homework 2 — Web Attack & Defend

## Group members

- Isabella Tulcan Jaya — 00329994
- Martin Montero Torres — 00328595
- Santiago Arellano Jaramillo — 00328370

## What to run

The implementation and its explanatory Markdown are in
[`hw2_web_attack_defend.ipynb`](hw2_web_attack_defend.ipynb). It contains:

- Part A: local DVWA-at-Medium payloads and sound oracles for SQLi, reflected
  XSS, and command injection.
- Part B: WAF coverage, bypasses, benign-traffic false positives, and the
  structural-fix comparison against DVWA's Impossible level.
- Part C: a Semgrep-versus-local-Ollama (`qwen2.5:3b`) duel against the readable
  `vuln-web` source and its independent hand-built ground truth.

All targets must be local and authorized. The notebook refuses a DVWA URL other
than `127.0.0.1` or `localhost`.

## Prerequisites

- Python 3.10 or later (the notebook was prepared for Python 3.15).
- Jupyter Lab/Notebook or VS Code with a Python kernel.
- Docker Desktop running and an authorized local DVWA instance configured at
  **Medium**. The notebook defaults to `http://127.0.0.1:60281`; override it
  with `DVWA_BASE` if Docker assigns another local port.
- Ollama serving locally with the model used for Part C:

  ```zsh
  ollama serve
  ollama pull qwen2.5:3b
  ```

- Semgrep for the classical-scanner arm of Part C:

  ```zsh
  python3.15 -m pip install semgrep
  ```

The notebook imports `pandas` for result presentation. Install it in the same
kernel if it is not already available.

## Run the notebook

From this directory, set only local configuration. Do not commit passwords.

```zsh
cd /Users/santiagoarellano/Documents/Projects/cmp-5006E-fall26/homework/hw2/arellano
export DVWA_BASE='http://127.0.0.1:60281'
export DVWA_USERNAME='admin'
# Either set DVWA_PASSWORD in your local shell or let the notebook prompt for it.
jupyter lab hw2_web_attack_defend.ipynb
```

Select the Python 3.10+ kernel and run the cells in order. The notebook checks
that DVWA begins at Medium; its Impossible-level comparison blocks restore Medium
in `finally`, even if an assertion fails.

Part C makes two uncached local Ollama calls with different seeds. It writes the
raw model outputs, normalized findings, scores, and metrics to:

- `duel/part_c_results.json`
- `duel/part_c_metrics.csv`

Review those artifacts and the notebook's printed false positives, scanner miss,
and non-determinism section before writing the final report. They are evidence;
they should not be replaced by screenshots.

## Included source-of-truth files

- `ground_truth.json`: independently hand-verified findings for the `vuln-web`
  scan subject used in Part C.
- `benign_traffic.json`: legitimate inputs used to measure Part-B WAF false
  positives.
- `verify_fixtures.py`: instructor fixture check for the original `vuln-web`
  setup. Its path assumptions may differ from this homework-folder layout, so the
  notebook is the primary executable workflow here.
- `AI_LOG.md`: disclosure of AI assistance used while preparing this submission.
