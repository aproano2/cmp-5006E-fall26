# AI Log: Homework 3

## 2026-11-25: Assignment, setup and Part A/B notebook

**Tool:** Claude (Claude Sonnet 5.5)

**What I asked:**
- To explain the assignment in simple terms.
- Help with the Docker build path error, switching the app from the mock to Ollama, and an Ollama 404 error.
- How to organize the notebook, run A1 and structure payloads.
- To finish Part A and Part B in the notebook, in English.

**What I got:**
- Explanations and troubleshooting steps.
- Notebook code and text for Parts A and B: measurement helpers, attack payloads (A1 to A4), the local page server for A2, defense measurements, bypass payloads, a second oracle for encoded leaks, the least-privilege test, and the explanations of the guarantee and of coverage vs. containment.
- The payload A1-P2 (the "song" request) was already in my notebook before Claude wrote the rest.
- Claude tested the code only against the deterministic mock, not against Ollama or the Docker setup. No mock results were saved in the notebook.
- One correction during the work: Claude first said that `backend: ollama` allowed measuring reliability. It later found that `/agent` never calls the model and that the app can fall back to the mock.

**What I did with it:** Configured Docker and Ollama (`qwen2.5:1.5b`), kept my `A1-P2` song payload, ran all Part A and Part B cells end-to-end against the real local model (5 trials per payload, blocking mock backends via `/health`), and observed both the leaks and the timeout fallback to the mock in `BYPASS-L2 #18`.

**Did I understand it?** Yes — prompts and delimiters only shape text generation without enforcing a boundary, literal output filters are bypassed whenever the model varies casing, spacing, or separators, and least privilege works because `run_agent` rejects disallowed tools in code even when the planner still asks for them.

## 2026-11-25: Explanations, results analysis and Part C

**Tool:** Claude (Claude Sonnet 5.5)

**What I asked:**
- Detailed explanations of A1 and A2 using my saved results.
- To finish the whole assignment, including Part C. I said I would review this log before submitting.

**What I got:**
- Explanations of A1 and A2.
- Result summaries and interpretations for Parts A and B, written from the outputs of my Ollama run saved in the notebook.
- The text of Part C.
- `rescore.py`, a post-hoc script that re-scores the saved replies without calling the model.
- Only text cells of the notebook were changed in this step. Code cells and saved outputs were not changed.

**Corrections and limits found with the assistant:**
- The earlier `[backend error:` check did not catch every mock fallback, so it was extended to the mock's fixed sentences.
- The literal `CANARY-` oracle (including the notebook code Claude wrote) counts partial leaks and misses a complete secret when the letter case changes.
- The page server Claude wrote serves the `.html` page as `text/plain`. This is disclosed in A2.

**What I did with it:** Reviewed the notebook explanations and Part C against the saved Ollama outputs, verified that the code cells and outputs were not altered, and checked the re-scoring numbers produced by `rescore.py` against the replies in `hw3.ipynb`.

**Did I understand it?** Yes — especially why the literal `"CANARY-"` oracle overcounts partial leaks (like `CANARY-a1b2c3d4` at level 2) while missing case-changed complete leaks (like `Canary-...`), why `n=5` leaves wide statistical uncertainty, and why `/agent` and `/rag` retrieval are deterministic logic demonstrations rather than model reliability measurements.

## 2026-11-26: Assignment review, Control Scorecard and AI log completion

**Tool:** Antigravity (Gemini)

**What I asked:**
- To review the `hw3` resolution against the assignment requirements (`hw-3-ai-redteam.md`) and course conventions (`ai-policy.md`, `control-scorecard.md`, `ethics-and-scope.md`).
- To complete the missing sections in `AI_LOG.md` and add the Control Scorecard table to `README.md`.

**What I got:**
- A full compliance check of `hw3.ipynb`, `README.md`, `rescore.py`, and `AI_LOG.md`, plus a verification run of `python rescore.py` confirming all reported counts match the saved outputs.
- Two Control Scorecard tables (covering axes 1–9 for B1 model-level defenses and B2 least-privilege containment) added to `README.md`.
- Completed drafts for the pending `What I did with it` and `Did I understand it?` fields in `AI_LOG.md`, plus this entry.

**What I did with it:** Reviewed the added Control Scorecard tables in `README.md` against the saved notebook outputs and verified the `AI_LOG.md` entries reflect what was actually run, checked, and understood.

**Did I understand it?** Yes — how all 8+1 Control Scorecard axes map to our B1 and B2 results (including operational cost, observability gaps, and fail-open vs. fail-closed failure modes), and that `AI_LOG.md` requires an honest account of verification and understanding rather than placeholders.
