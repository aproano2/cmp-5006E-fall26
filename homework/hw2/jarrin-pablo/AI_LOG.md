# AI Use Log

> **Team:** Juan Diego Cadena · Omar Andrés Gordillo · Pablo Jarrín · Santiago Rodríguez

## 2026-11-03 — Codex

The team used Codex to help organize and implement this homework. We asked it to help with the attack, defense, scanner-versus-LLM comparison, reports, and reproducibility checks in English.

The assistant helped with:

- reading the homework instructions and the local `vuln-web` source;
- writing the Python attack harness and security-effect oracles;
- measuring the WAF and parameterized query;
- running the real Semgrep engine with committed local rules;
- structuring the local Ollama comparison and calculating precision, recall, F1, and run-to-run similarity;
- drafting the reports, scorecard, and honesty limitations;
- running the scripts and correcting problems found during verification.

One important correction was needed during the LLM experiment. The first local calls returned an empty final-response field because the model used a separate thinking channel. The call was changed to disable that channel, and both LLM runs were repeated. Only the valid repeated runs are reported. No external target was tested. All attacks were limited to the course application on `127.0.0.1`.