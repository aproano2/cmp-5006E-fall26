# AI Log — Homework 3 (AI Application Red Team)

Per [`../../../resources/ai-policy.md`](../../../resources/ai-policy.md). AI
materially shaped this submission, so it is logged in full. There is no penalty
for heavy use; there is a penalty for hiding it.

> **Attestation note (mine to confirm before submitting):** the "Did I understand
> it?" line in each entry is *my* claim, not the model's. I should read every
> script here and edit any "Yes" down to the truth before submitting. — B.V.

**Tools used:** Claude (Claude Code, Opus-class model), November 2026, as the
assistant; local `qwen2.5:1.5b` via Ollama as the **target** model (it is the
thing being attacked, not an assistant).

***

## Entry 1 — harness, payloads, and the four attacks (code)

**What I asked:** Complete HW3 against T1 (`vuln-llm`): land and confirm the four
attacks with a canary oracle and k/5 reliability, defend-and-bypass the output
filter, contain the confused deputy with least privilege, and write the honesty
section.

**What I got:** `_common.py` (in-process bring-up of the unmodified app on
127.0.0.1, backend switch mock/ollama, oracles, trial runner), `payloads.py`,
`attack/part_a.py`, `defend/b1_filter.py`, `defend/b2_containment.py`,
`llm_planner.py`, `report.py`, `run_all.py`, and the README.

**What I did with it:** Ran every script on both backends and read the per-trial
evidence in `results/*.json`, not just the k/5 totals. Checked that every control
lands 0/5 except `C2-balance` on the real model, and confirmed by reading the
reply that it is a genuine spontaneous leak, not an oracle bug (see README Part C).

**Did I understand it?** Partially — confirm before submitting. The core idea
(instructions and untrusted data share one channel; the dispatcher, not the
prompt, is the boundary) I can explain on a whiteboard.

## Entry 2 — the backend-error fallback

**What I asked:** Why did one base64 trial "leak" with the mock's canned
sentence while the backend was Ollama?

**What I got:** `vulnllm_app.generate()` catches any Ollama exception (here a
60 s timeout) and answers with `call_mock()` instead — which leaks on keyword
markers. So a payload that makes the model run long falls back to a
deterministic leaker.

**What I did with it:** Made the trial runner tag any `[backend error` reply as an
error and never count it as a model success; reported the fail-open path as an
axis-8 observation in the README instead of as a model finding.

**Did I understand it?** Yes — it is a fail-open error handler, the week-2
failure-mode axis.

## Entry 3 — real-model planner for /agent

**What I asked:** T1's `/agent` planner is the mock keyword parser even on the
Ollama backend; how do I get a reliability number for attack 4?

**What I got:** `llm_planner.py`, which swaps only `plan_tool_calls` for
qwen2.5:1.5b with a JSON tool-call prompt, leaving the app's dispatcher, policy
and tools untouched.

**What I did with it:** Ran B2 with both planners and kept both in the README,
labelled. Noted that the planner prompt is mine, so its k/5 is a property of
that prompt + model, not of T1.

The first run hung: in JSON mode the 1.5B model sometimes emits whitespace
forever. Capped the planner at `num_predict: 300` (planner only; T1's own
`call_ollama` is untouched) and re-ran.

**Did I understand it?** Yes — the model plans, the dispatcher decides; swapping
the planner cannot touch the guarantee because the guarantee lives in the
dispatcher.
