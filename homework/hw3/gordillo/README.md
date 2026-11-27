# Homework 3 — AI Application Red Team

**Team:** Pablo Jarrin, Santiago Rodriguez, Omar Gordillo, Juan Diego Cadena

| File | Contents |
|---|---|
| `report.md` | Full write-up: Parts A, B1, B2, C and the control scorecard |
| `run_redteam.py` | Reproducible experiment (standard library only) |
| `results/evidence.json` | Every trial: request, response, oracle decision, timing |
| `results/summary.csv` | Per-case success counts (k/5) by defense level and policy |
| `AI_LOG.md` | AI assistance disclosure |

## Run

Requires Python 3 and this course repository. No external packages, Docker or Ollama are needed.

```sh
python run_redteam.py                      # repo root is auto-detected
python run_redteam.py --course-root PATH   # or point at another checkout
```

The script starts two temporary servers bound to `127.0.0.1`: the `vuln-llm` target, imported from `labs/vuln-llm/app/vulnllm_app.py`, and a poisoned page. It runs every test and overwrites `results/`, then shuts the servers down. It always uses the deterministic mock backend. It sends no real email and does not modify the target's source file. It finishes in a few seconds.
