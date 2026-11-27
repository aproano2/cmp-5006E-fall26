# AI Log — Homework 2

## How AI was used

AI assistance was used as a local development and documentation aid. Its role was
to trace the assignment contract to the course-provided sources of truth, connect
the notebook to the local lab applications, and help structure the reproducible
experiments and Markdown explanations.

Specifically, AI assisted with locating and relating:

- `hw2-web.md`, which defines the required attack, defense, scanner/LLM duel,
  non-determinism, and honesty evidence;
- `seclab.attack`, which supplies the `Payload`, `run_payloads`, and
  oracle-oriented workflow;
- `seclab.targets`, `seclab.llm`, and `seclab.scan`, which provide the local
  target lifecycle, Ollama client, and ground-truth scoring contract;
- DVWA running only on the local loopback interface for Parts A and B;
- `labs/vuln-web/app/vulnweb_app.py` and `ground_truth.json` as the shared scan
  subject and independently constructed truth set for Part C; and
- `benign_traffic.json` as the false-positive corpus for the WAF experiment.

AI also helped draft the notebook's request senders, oracles, WAF measurement,
Semgrep integration, Ollama prompt, result normalization, and reproducibility
notes. The group reviewed the code and must run it locally before submission.

## Boundaries and verification

- No external, public, or unauthorized host was targeted. The notebook enforces
  a localhost-only DVWA URL.
- AI-generated prose or code was not treated as evidence. Confirmed findings,
  false-positive rates, scanner metrics, model outputs, and non-determinism must
  come from the notebook's local execution artifacts.
- The hand-built `ground_truth.json` remains independent of Semgrep and Ollama;
  it is not derived from either tool's output.
- The group is responsible for checking each claim, preserving the raw local
  outputs in `duel/`, and correcting any model hallucinations before submission.
