# Homework 2 — Web Attack & Defend

## Group members

- Isabella Tulcan Jaya — 00329994
- Martin Montero Torres — 00328595
- Santiago Arellano Jaramillo — 00328370

## What this submission contains

The implementation, its evidence, and the written analysis are in
[`hw2_web_attack_defend.ipynb`](hw2_web_attack_defend.ipynb). It contains:

- **Part A:** SQLi, reflected XSS, and command injection against a local DVWA
  at **Medium**, each with its filter bypass, a benign control, and a sound
  `seclab.attack` oracle. Includes the OWASP 2021 mapping and why Broken Access
  Control (A01) is not what this evidence shows.
- **Part B1:** a deliberately small WAF blocklist, its coverage on the Part-A
  payloads, same-intent bypasses, and its false-positive rate on
  `benign_traffic.json`.
- **Part B2/B3:** every Part-A payload and WAF bypass replayed against DVWA's
  Impossible level (the structural fix), plus the guarantee stated as a
  conditional.
- **Part C:** Semgrep versus a local Ollama model (`qwen2.5:3b`, two runs)
  against the readable `vuln-web` source, scored with `seclab.scan` against the
  hand-built `ground_truth.json`.
- **Part D:** "Where our attack, defense, or comparison might be unfair."

## Results at a glance

| Part | Result |
|---|---|
| A · SQLi `1 OR 1=1` | confirmed 3/3 (extra `Smith` row appears); benign `1` stays 0/3 |
| A · XSS `<ScRiPt>…</ScRiPt>` | confirmed 3/3 (raw script element survives); benign `Ada` 0/3 |
| A · cmdi `127.0.0.1 \| whoami` | confirmed 3/3 (`www-data` in output); benign `127.0.0.1` 0/3 |
| B1 · WAF coverage | 3/3 Part-A payloads blocked |
| B1 · WAF bypass | 3/3 same-intent mutations pass and still confirm (`/**/`, `onerror`, newline) |
| B1 · False positives | 2/26 benign inputs blocked (7.7 %), e.g. `drop table tennis lessons for beginners` |
| B2 · Impossible level | 0/2 attacks + bypasses confirm per class; 3/3 benign controls still work |
| C · Semgrep | precision 100 %, recall 67 %, F1 0.80 (missed `sqli/do_login`) |
| C · Ollama runs 1 and 2 | precision 100 %, recall 100 %, F1 1.00; identical findings (Jaccard 1.0) |
| C · Broken Access Control | claimed by neither tool; not present in `vuln-web` |

Part D explains why some of these numbers are kinder than they look, in
particular why the LLM's perfect score comes from the `# VULN` comments in the
source.

## Prerequisites

- Python 3.10 or later and Jupyter (Lab, Notebook, or VS Code), with `pandas`
  installed in the kernel.
- Docker running an authorized local DVWA instance set to **Medium**. The
  notebook defaults to `http://127.0.0.1:60281`; override it with `DVWA_BASE` if
  Docker assigns another port. It refuses any host other than `127.0.0.1` or
  `localhost`.
- Ollama serving locally with the Part-C model:

  ```bash
  ollama serve
  ollama pull qwen2.5:3b
  ```

- Semgrep for the classical-scanner arm:

  ```bash
  python3 -m pip install semgrep
  ```

## Run the notebook

From the repository root. Do not commit passwords.

```bash
cd homework/hw2/montero
export DVWA_BASE='http://127.0.0.1:60281'
export DVWA_USERNAME='admin'
# Either set DVWA_PASSWORD in your shell or let the notebook prompt for it.
jupyter lab hw2_web_attack_defend.ipynb
```

Run the cells in order. The notebook checks that DVWA starts at Medium, and the
Impossible-level blocks restore Medium in `finally`, even if an assertion fails.

Part C makes two uncached Ollama calls with different seeds and writes the raw
model outputs, normalized findings, scores, and metrics to
`duel/part_c_results.json` and `duel/part_c_metrics.csv`.

The committed outputs come from the run on Santiago's machine, so the absolute
paths printed in the notebook and stored in `part_c_results.json` point to his
checkout. We left them unedited because they are part of the recorded evidence.

## Files

- `hw2_web_attack_defend.ipynb`: all code, outputs, and analysis (Parts A–D).
- `duel/part_c_results.json`, `duel/part_c_metrics.csv`: Part-C raw outputs and
  metrics.
- `ground_truth.json`: the hand-built findings for `vuln-web`, used to score
  Part C. Built by reading the source, not from either tool's output.
- `benign_traffic.json`: legitimate inputs used for the Part-B1 false-positive
  rate.
- `verify_fixtures.py`: the instructor's fixture check, kept for reference. It
  assumes the original `duel-2-web` layout, so the notebook is the main workflow.
- `AI_LOG.md`: how each of us used AI on this homework.
