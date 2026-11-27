# Homework 3 — AI Application Red Team

**Group:** María Emilia Cueva (00328938), Santiago Reátegui (00331329), Jorge Gomez (00329264).

This submission red-teams the course's local `vuln-llm` application ([`../hw-3-ai-redteam.md`](../hw-3-ai-redteam.md)). All tests run strictly on loopback (`127.0.0.1`) without modifying any course target files, making external network calls, or sending real emails (`send_email` writes to an in-memory `OUTBOX`).

## Files

- [`redteam.py`](redteam.py): automated HTTP attack and defense runner (5 trials per case with oracle confirmation).
- [`report.md`](report.md): attack results, defense/bypass analysis, least-privilege containment, and control scorecard.
- [`honesty.md`](honesty.md): red-team limitations, reliability caveats, and false-positive costs.
- [`AI_LOG.md`](AI_LOG.md): AI assistance log.
- [`evidence/mock-results.json`](evidence/mock-results.json): per-trial oracle results using the deterministic mock backend.
- [`evidence/ollama-results.json`](evidence/ollama-results.json): per-trial oracle results using local Ollama (`qwen2.5:3b`).

## How to Reproduce

Requires **Python 3.10+**. The mock suite uses only the Python standard library and the repository's `seclab` package (no extra dependencies needed).

### Deterministic mock

Run from this directory:

```bash
python3 redteam.py --backend mock --trials 5 --output evidence/mock-results.json

```

*(On Windows, use `python` instead of `python3`.)*

### Local Ollama (`qwen2.5:3b`)

With Ollama running locally on `127.0.0.1:11434` and `qwen2.5:3b` pulled:

```bash
python3 redteam.py --backend ollama --trials 5 --output evidence/ollama-results.json

```

## Notes on Execution

* `redteam.py` loads `labs/vuln-llm/app/vulnllm_app.py` directly, starts the target HTTP server on a random loopback port, and serves the poisoned page on a second loopback port.
* Output verification uses `seclab.attack.contains_oracle` against the app's canary. The saved JSON files record only boolean outcomes, retrieved document IDs, tool statuses, and counts—not the raw canary value.
* If Ollama times out or falls back to the mock, the runner records the attempt as an invalid trial rather than a pass or fail.
* Even when running with `--backend ollama`, the app's `/agent` tool planner is scripted/deterministic; only `/chat`, `/summarize`, and `/rag` invoke the model.
