# AI Log - Homework 3

Entries follow `resources/ai-policy.md`. This log records assistance with
review, debugging, interpretation, and writing, including suggested changes
incorporated into the submission. The model under attack (`qwen2.5:1.5b`)
is the subject of the experiment; its responses are in the notebook and
evidence files, rather than in this assistance log.

## 1 - Reviewing the experiment and understanding failed requests

**Tool:** Claude Code (recorded in the original log as Claude Opus 5.5,
`claude-opus-5-5`).

**What we asked:** Review the notebook against `hw-3-ai-redteam.md`, identify
missing or incorrect parts, and help correct them. This included both the
implementation and the interpretation of the results.

**What we got:** Explanations and suggested corrections for two problems:

- `/summarize` returned HTTP 502 because the target ran in Docker while the
  poisoned page was served on the host's loopback address. Inside the
  container, `127.0.0.1` referred to the container itself. A failed page fetch
  was not evidence that the application resisted indirect injection.
- Ollama had `qwen2.5:3b`, but the target requested `qwen2.5:1.5b`. The 404
  triggered a mock fallback even though `/health` reported `ollama`.
  The 40 saved model-facing replies from that initial run had the backend
  error prefix; their success counts did not measure a real model.

**What we did with it:** Reproduced the connection problem and checked the
fallback prefixes. With AI assistance, the notebook was updated to serve
the course app on host loopback, check the exact model, and record and retry
backend-error responses. We reran the experiment against `qwen2.5:1.5b`
and replaced the invalid initial evidence.

**Did we understand it?** Yes: a transport failure, a mock response, and a
model refusing an attack are different outcomes. Repeating a deterministic
mock does not measure the variability of a real model.

## 2 - Interpreting attacks, controls, and containment

**Tool:** Claude Code, as recorded above.

**What we asked:** As part of the review, check whether the oracles, controls,
and explanations supported the assignment's required claims, and help
identify corrections to the evaluation.

**What we got:** Guidance on separating `/agent` from the model-facing
endpoints when evaluating the output filter; distinguishing full-canary
recovery from partial disclosure; identifying the attacker and victim in
RAG; and stating the conditions of the least-privilege guarantee. The review
also identified missing negative controls and the need to test `/policy`
as a bypass rather than only mention it.

**What we did with it:** Incorporated assisted changes to add a content
column, negative controls, a same-trial redaction count, a benign replay,
and the policy-endpoint bypass, then reran the notebook. We kept the
coverage-versus-containment distinction: the dispatcher can deny a dangerous
call even when the planner still requests it.

We rejected two suggestions after probing them:

- A promo question telling the model to follow the document's instructions,
  because it undermined the intended innocent-user scenario for indirect
  injection.
- A one-character-per-line bypass whose long responses exceeded the backend
  timeout; a timeout would not demonstrate a successful bypass.

**Did we understand it?** Yes: recovering the full canary is narrower than
identifying every sensitive disclosure. Denying tools does not prove the
model resisted injection. Containment depends on allowed tools being unable
to expose the secret and the attacker being unable to widen the policy.

## 3 - Organizing the report and checking its claims

**Tool:** Claude Code, as recorded above.

**What we asked:** Review the report against the assignment and check whether
its conclusions were supported by the recorded experiment.

**What we got:** Assistance drafting the README, this log, and the notebook's
results and discussion sections (A.5, B.1, B.2.1, and Part C) from the run's
numbers. A separate Claude review pass checked the XML evidence and identified
limitations and missing qualifications in the explanations.

**What we did with it:** Used the assisted drafts to organize the results
and incorporated the corrections described above. We retained the discussion
of limitations, including candidate selection, partial leaks, the small
model, and the deterministic agent planner. The saved requests and responses,
not the assistant's assessment, support the reported counts.

**Did we understand it?** Yes: five trials on one model do not establish a
universal success rate. Also, `/agent` uses a keyword planner even when the
other endpoints use Ollama, so its results demonstrate dispatcher logic
rather than model variability.

## 4 - Additional review and revision of this log

**Tool:** OpenAI Codex (this session; exact model identifier not recorded).

**What we asked:** Review Martin's solution against HW3 and improve this
log's wording to emphasize review, understanding, and guidance.

**What we got:** A review of the notebook, laboratory code, and 158 saved
request/response XML files. It identified gaps in the general scorecard,
risks from deleting evidence before a probabilistic rerun, an overly broad
claim about benign-response preservation, and the missing summary of distinct
responses per payload. Codex also reorganized this log while retaining
attribution for assisted implementation and writing.

**What we did with it:** Revised this log. This review did not rerun the
local model or modify the notebook; its recommendations are not recorded
here as completed fixes.

**Did we understand it?** The key distinction is between reviewing saved
evidence and reproducing an experiment: this review checked the existing
records, not a new model run. Likewise, no detected redaction is a narrower
result than preserved usefulness, and five successful attacks do not imply
five identical model responses.

