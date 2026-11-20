# AI Use Log

> **Team:** Juan Diego Cadena · Omar Andrés Gordillo · Pablo Jarrín · Santiago Rodríguez

## 2026-11-03 — Codex

The team used Codex as a support tool to better understand the homework requirements, clarify technical concepts, and receive recommendations on how to approach the different tasks. The purpose was to obtain guidance and avoid common implementation mistakes, rather than having the AI complete the assignment.

The assistant provided guidance on:

- Understanding the homework instructions and identifying the main requirements.
- Reviewing the `vuln-web` application to understand its structure and potential vulnerabilities.
- Explaining how to approach the attack scenarios and what security effects should be verified.
- Recommending ways to evaluate the WAF and parameterized queries.
- Explaining how to use Semgrep with local rules and interpret its results.
- Clarifying how to compare Semgrep findings with a local Ollama model using precision, recall, F1, and run-to-run similarity.
- Suggesting how to organize the reports, document limitations, and ensure reproducibility.
- Providing recommendations for troubleshooting and verifying the experiments.

The team was responsible for implementing the solutions, running the experiments, analyzing the results, and preparing the final deliverables.

During the LLM experiment, an issue was identified where the model returned an empty final-response field because it was using a separate thinking channel. Based on the troubleshooting guidance, the team adjusted the configuration to disable that channel and repeated both runs. Only the valid repeated runs were included in the results.

All testing was performed locally using the course application on `127.0.0.1`. No external systems or targets were tested.
