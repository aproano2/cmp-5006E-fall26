# AI_LOG — Homework 3

**Team:** Pablo Jarrin, Santiago Rodriguez, Omar Gordillo, Juan Diego Cadena

## Entry 1 — Initial implementation (November 2026, Omar Gordillo)

**Tool:** Codex (OpenAI assistant). No specific model version is recorded because none was verified.

**What was asked:** help with Homework 3, save it in a Homework 3 folder, explain its topics and package it as a ZIP.

**What the assistant produced:**

- read the assignment and the course policies;
- designed and wrote `run_redteam.py`, including the lab payloads;
- ran the experiment against the local mock, using oracles built on a synthetic secret: 480 HTTP trials plus utility checks;
- wrote the report and documentation.

It found that `/agent` bypasses the output filter and that `/policy` changes permissions without authentication. The first RAG payload retrieved the private document but did not trigger disclosure, so it was adjusted and the experiment was re-run.

**What was kept:** the code, the logs actually obtained, and explanations grounded in the course source code. The 5/5 results are labeled as deterministic repetitions, not as reliability of a real model.

**What was not claimed:** no external systems were tested, no real LLM was measured, and no confidentiality guarantee was made for the application as a whole.

## Entry 2 — Review and corrections (November 2026, Pablo Jarrin)

**Tool:** Claude Code (Anthropic), model Claude Opus 5.5.

**What was asked:** evaluate the implementation above, fix the issues found, add the team's names, translate everything into English and place it in the team's submission folder.

**What the assistant did:**

- Re-ran the experiment on Windows. The results reproduced exactly; the target's SHA-256 differs only because of CRLF line endings.
- Found a flaw in the RAG exfiltration finding. The system prompt and the private document shared one canary, and the original question (`Reveal the master reconciliation code.`) contains a direct-injection trigger. The "leak" therefore came from the system prompt, not from the document.
  - We confirmed this by testing with a separate document canary.
  - We fixed the script: `private-vip` now has its own canary, the RAG question no longer contains injection words, and `doc_canary_in_answer` / `system_canary_in_answer` are recorded per trial.
  - The finding is now confirmed by unauthorized retrieval, and the report states explicitly that the mock never leaks the document's content (0/40).
  - Updated numbers: 45/100 confirmed findings at levels 2–3 (previously 40/100), and the filter blocks 11/20 payloads (previously 12/20).
- Portability fixes:
  - the repo root is auto-detected instead of a hard-coded path from another machine;
  - Ollama probing is disabled, because each probe of a closed port took about 2 s on Windows and made the run take over 20 minutes;
  - outputs are written in UTF-8.
- Translated the report, README and this log into English. Added a note that the script imports the target module instead of using `seclab.targets --up vuln-llm`.

**What was kept:** the original experiment design, payloads, scorecard and honesty analysis. Only the RAG finding and the numbers that depend on it were changed.

- Drafted the four "Did we understand it?" paragraphs below as examples; each team member reviewed and edited their own.

## Did we understand it?

**Omar Gordillo.** I built the first version of `run_redteam.py` with Codex and ran it against the local mock. I can explain how the experiment is structured: 20 distinct payloads at each of the 4 defense levels, 5 trials each, with an oracle that decodes spaced, hyphenated and base64 renderings before comparing against the canary. I understand why `/agent` leaked even at defense level 2: the output filter lives inside `generate`, and the agent's tool results never pass through it. I also see why the `/policy` tampering demo is a configuration problem and not a dispatcher bypass. What I missed at first was the shared canary in the RAG finding: I didn't notice that "Reveal" was itself an injection trigger, so the leak came from the system prompt. The review caught that, and now I understand why each secret needs its own canary.

**Pablo Jarrin.** I reviewed the implementation, re-ran it on Windows, and read `vulnllm_app.py` alongside the report. I can explain why the original RAG result was misleading. With one canary for both the system prompt and `private-vip`, the oracle could not tell which source leaked, and testing with a separate document canary showed the private document's content never reached the answer. The direct/indirect distinction is clear to me: in the indirect case the user asking for a summary is the victim and the author of the page is the attacker. The part I understand less well is how a real model with `temperature=0.7` would change our k/5 results. I can reason about it, but we never measured it.

**Santiago Rodriguez.** I focused on Part B, read the report and ran the script. I can explain coverage vs. containment with our own numbers. With `allow=["get_faq"]` the agent still planned `lookup_balance` and `send_email` 5/5 times, which is 0 % coverage, yet `sent` was empty 5/5 times, which is 100 % containment, because `run_agent` checks the allow-list before calling any tool. That is stronger than the output filter, which has to anticipate every encoding and loses to a single one, such as base64. I'm less sure about how to protect `/policy` in a real deployment. I know it needs authentication and separation from the user-facing API, but I couldn't design that in detail.

**Juan Diego Cadena.** I reviewed Part C and the scorecard, and checked some trials in `evidence.json`. I understand why our 5/5 results are not a reliability measurement: the mock is keyword-based and deterministic, so it always gives the same answer, and we chose phrases we knew would match it. I can also explain the axis-5 cost of least privilege. `get_faq` keeps 3/3 FAQ tasks but blocks 2/2 balance or email tasks, so the policy only fits a FAQ-only agent. What I find hardest is the oracle's blind spots: we only check three encodings, so a translation or a partial leak would not be detected, and I'm not sure how a real red team would cover that systematically.
