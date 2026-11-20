# Homework 2 — Web Attack & Defend

**Target:** Course `vuln-web` application on localhost only

## Team

- Juan Diego Cadena
- Omar Gordillo
- Pablo Jarrín
- Santiago Rodríguez

This submission confirms SQL injection, reflected XSS, and command injection;
measures a SQLi blocklist; bypasses it; applies a parameterized-query fix; and
compares a classical scanner with two real runs of a local LLM.

## Main results

| Part | Result |
|---|---|
| A · Attacks | SQLi, XSS, and command injection confirmed 2/2 trials each |
| B1 · WAF coverage | 1/1 known SQLi payload blocked |
| B1 · WAF bypass | 3/3 variants passed and leaked the canary |
| B1 · False positives | 4/26 benign inputs blocked (15.4%) |
| B2 · Parameterization | 0/4 injection attempts succeeded |
| C · Semgrep | Precision 100%, recall 66.7%, F1 0.80 |
| C · Local LLM run 1 | Precision 100%, recall 100%, F1 1.00 |
| C · Local LLM run 2 | Precision 100%, recall 100%, F1 1.00 |

## Reproduce the work

From this folder:

```powershell
python attack\run_attacks.py
python defend\evaluate_defenses.py
python duel\run_duel.py
python test_hw2.py
```

`duel/run_duel.py` uses the two saved raw LLM responses. To perform two new
local Ollama reviews instead, run:

```powershell
python duel\run_duel.py --run-llm
```

The saved Semgrep JSON is also used by default. After installing Semgrep, a new
scan can be produced with:

```powershell
python duel\run_duel.py --run-semgrep
```

The default reproduction commands need only Python and the course repository.
New tool runs additionally require Semgrep and a local Ollama model named
`qwen3.5:4b`.

## Files

- `attack/`: attack harness, detailed report, and oracle evidence CSV.
- `defend/`: WAF, positive fix, report, and measurement CSV files.
- `duel/`: raw LLM runs, scanner/LLM findings, metrics, and comparison report.
- `ground_truth.json`: source-reviewed findings used to score both tools.
- `benign_traffic.json`: provided benign corpus used for false-positive testing.
- `control-scorecard.md`: evaluation across the eight scorecard axes.
- `honesty.md`: limitations and possible unfairness in the experiment.
- `AI_LOG.md`: record of AI assistance.

## Central conclusion

The blocklist looked successful on the payload it knew, but small changes bypassed
it and normal user text produced false positives. Parameterization was stronger
because it kept user input in the data channel instead of trying to recognize
every possible malicious string.
