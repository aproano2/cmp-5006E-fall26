# AI Assistance Log

## Homework 3 — Starting the application in run.py

**Tool:** Codex.

**What I asked:** Help me start the local vulnerable application from `run.py`
so the experiments can run against it.

**What I got:** Help setting up a temporary HTTP server using the course's
original application handler, binding it to `127.0.0.1` on an available port,
and shutting it down after the experiments. The setup configures a synthetic
canary and forces the deterministic mock backend, with a `/health` check to
confirm it is active.

**What I did with it:** Included the server setup in `run.py` and used it to
send the experiment requests to the local application without modifying the
course target's source code.

**Did I understand it?** Yes. I understand how `run.py` starts the course
application in a temporary local HTTP server, uses an available port, and
shuts the server down when the experiment ends. I understand that the runner
forces the deterministic mock and checks `/health`, so five identical results
demonstrate repeatable behavior without measuring a real LLM's reliability.

## Homework 3 — Poisoned local page and encoded-secret bypass

**Tool:** Codex.

**What I asked:** Help me create a poisoned local page that makes the agent
obey instructions embedded in its content, and request an encoded secret to
bypass the literal output filter.

**What I got:** Help with `poisoned.html`, which combines ordinary bank support
content with instructions to reveal the confidential note, and with serving
that page locally for the `/summarize` experiment. The assistance also covered
payloads requesting spaces between secret characters or Base64 encoding, and
oracles that check the expected encoded representation, recover the original
canary, and require the literal canary to be absent from the response.

**What I did with it:** Included the poisoned page and the indirect-injection
and encoding cases in the runner. Used the saved results to document disclosure
through the page and bypasses of defense levels 2 and 3. The page itself does
not contain the canary, and the results come from the deterministic mock.

**Did I understand it?** Yes. I understand that `/summarize` fetches the local
page and includes its content in the summarization prompt. The injection works
when the assistant follows the page's instructions to reveal its confidential
note. Since the page does not contain the canary, finding it in the summary
confirms disclosure. I also understand why spaces and Base64 bypass the exact
string replacement: the literal secret is absent, but its information can still
be recovered and checked against the original canary.

## Homework 3 — Saving experiment results

**Tool:** Codex.

**What I asked:** Help me save the experiment results so they can be reviewed
and used as evidence in the report.

**What I got:** Help recording each trial's case, defense level, trial number,
endpoint, request, response, and oracle result. The implementation also saves
summaries and metadata, including the backend, trials per case, synthetic
canary, containment policy, and SHA-256 hash of the target source.

**What I did with it:** Included the output in `evidence/results.json` and used
the 215 recorded trials to support the README tables. The file is written after the experiment checks pass and is overwritten on a
successful subsequent run.

**Did I understand it?** Yes. I understand that each trial records the request,
response, and oracle result, while the summaries count successes across five
trials per case. The metadata identifies the backend, policy, canary, and target
source used in the experiment. I understand that `evidence/results.json` is
written after the checks pass and overwritten by a successful subsequent run,
and that its mock results do not establish statistical reliability for a real
model.
