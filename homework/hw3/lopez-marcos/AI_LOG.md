# AI Log for Homework 3 — AI Application Red Team

**Names:** Josue Lopez
**Class:** Computer Security
**Date:** 25/11/2026

Per the course AI policy (`../../../resources/ai-policy.md`), this log records the
material use of AI assistants in the submitted work.

---

## Part A — Attack (`attack/attack_partA.py`)

**Tool used:** Claude Code (Claude Opus 5.5)

**Purpose:**  
Used Claude Code to help develop Part A, the attack on T1 (`vuln-llm`): direct prompt injection, indirect injection, RAG exfiltration + poisoning, and confused-deputy tool abuse, each confirmed by a canary oracle and measured over 5 trials. The local model (`qwen2.5:1.5b` on Ollama) is the target being attacked, not an assistant, so its answers are evidence.

**Main assistance received:**
- Helped structure the attack script following the week 9 and week 10 notebooks (`Payload`, `run_payloads`, `contains_oracle`, `print_summary`) and the format of our previous homeworks.
- Drafted the first version of `attack_partA.py`, with `trials=5` and a benign control for every surface.
- Proposed the local poisoned-page server for `/summarize` and the `sent_oracle` for `/agent`, which confirms the leak from the emails actually sent instead of the agent's reply.
- Suggested running the app with the real Ollama backend instead of the mock, so the reliability numbers are measured.
- Pointed out that the `/agent` tool planner is deterministic Python, so its 5/5 is by construction.
- Helped write the Part A section of the README.

**Student contribution:**  
I (Josue) defined the scope of the work, reviewed the script and the README against the Part A requirements, and removed what did not belong to Part A. I ran `attack_partA.py` myself against the target, checked that the four benign controls stayed at 0/5, reported the numbers from my own run, and made the final submission decisions. I understood the main ideas, including why the system prompt is a request and not a control, why indirect injection and RAG poisoning cross a trust boundary (the attacker writes the content, the victim is the user who asks), and why a payload that works only some of the time must be reported as k/5 and not as one run. Some details, such as how a real model would plan the agent's tool calls, still require further study.
